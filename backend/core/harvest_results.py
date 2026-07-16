"""0.12.7 — Centralised harvest result-file writer.

Responsibilities
----------------

* Compute the canonical results directory (``~/.mailaccess/results/``)
  and create it with mode ``0700`` on first use.
* Write the **default** ``{domain}_{timestamp}.json`` export on every
  harvest (unless ``--no-export``).
* Write the supplementary tool-chain files when their data exists:

    - ``{domain}_{timestamp}_subdomains.txt``    (Change 4 — File 1)
    - ``{domain}_{timestamp}_emails.txt``        (Change 4 — File 3)
    - ``{domain}_{timestamp}_nuclei_targets.txt`` (Change 4 — File 4)
    - ``{domain}_{timestamp}_report.md``         (Change 4 — File 5)
    - ``{domain}_{timestamp}_cidrs.txt``         (already shipped in 0.12.6,
      we just centralise the path so the file lives in the same
      results directory as the rest of the outputs — was a temp-path
      leak in the prior release)

* Run lazy cleanup: drop oldest per-domain files beyond
  ``harvest_results_max_per_domain`` and any files older than
  ``harvest_results_max_age_days``.

All file I/O is async-friendly: callers ``await`` :func:`write_harvest_results`
which dispatches the actual writes through ``asyncio.to_thread`` so a
slow disk never blocks the harvest pipeline.

This module deliberately keeps no state — every function is pure-ish
(input → files on disk) so it is straightforward to test in isolation.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import settings
from .domain_harvest_report import (
    _build_infrastructure,
    _build_subdomains,
    _export_summary_counts,
    _extract_discovered_names,
    _sanitised_export_emails,
    format_harvest_json_export,
    serialise_harvest_for_export,
)

_LOG = logging.getLogger(__name__)

# Allowed alphabet for the domain segment of a results filename.  A
# conservative superset of RFC-1035; we also accept underscores (which
# we generate) and dots (subdomain components when the harvest domain
# is itself a subdomain).
_SAFE_DOMAIN_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_domain_segment(domain: str) -> str:
    """Normalise a domain string for safe use in a filename."""
    cleaned = _SAFE_DOMAIN_RE.sub("_", (domain or "").strip())
    return cleaned.strip("._-") or "domain"


def results_dir() -> Path:
    """Return the configured harvest results directory, creating it if missing.

    Mode is ``0o700`` (owner-only) so the JSON / log files an analyst
    produces — which routinely contain personal email addresses — are
    never world-readable.  On Windows the chmod call is a best-effort
    no-op; the directory is still created.
    """
    base = Path(getattr(settings, "harvest_results_dir", Path.home() / ".mailaccess" / "results"))
    base.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        with contextlib.suppress(OSError):
            os.chmod(base, 0o700)
    return base


def timestamp_slug(now: datetime | None = None) -> str:
    """Return a ``YYYYMMDD_HHMMSS`` timestamp in local time."""
    moment = now or datetime.now()
    return moment.strftime("%Y%m%d_%H%M%S")


def results_paths(domain: str, timestamp: str) -> dict[str, Path]:
    """Return the canonical results paths for one harvest invocation.

    The returned dict includes the main JSON, the live log, the
    supplementary tool-chain files, and the CIDR file.  Nothing is
    created on disk by this function — it is a pure path builder.
    """
    seg = _safe_domain_segment(domain)
    base = results_dir()
    return {
        "base_dir": base,
        "json": base / f"{seg}_{timestamp}.json",
        "live_log": base / f"{seg}_{timestamp}_live.log",
        "subdomains": base / f"{seg}_{timestamp}_subdomains.txt",
        "emails": base / f"{seg}_{timestamp}_emails.txt",
        "nuclei_targets": base / f"{seg}_{timestamp}_nuclei_targets.txt",
        "report_md": base / f"{seg}_{timestamp}_report.md",
        "cidrs": base / f"{seg}_{timestamp}_cidrs.txt",
    }


# ---------------------------------------------------------------------------
# File writers — each takes the dataclass-shaped result and returns a Path.
# Sync; the public entry point runs them through asyncio.to_thread.
# ---------------------------------------------------------------------------
def _write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _write_subdomain_list(path: Path, result: Any) -> Path | None:
    entries = _build_subdomains(result)
    if not entries:
        return None
    lines = sorted(
        {
            str(item.get("subdomain", "")).strip()
            for item in entries
            if item.get("subdomain")
        }
    )
    if not lines:
        return None
    return _write_text(path, "".join(f"{line}\n" for line in lines))


def _collect_personal_emails(result: Any) -> list[Any]:
    """Return HIGH / MEDIUM confidence on-domain personal emails."""
    domain = (result.domain or "").strip().lower()
    out: list[Any] = []
    for entry in _sanitised_export_emails(result.unique_emails):
        if entry.is_role:
            continue
        if entry.confidence_label not in {"CONFIRMED", "LIKELY", "MEDIUM", "HIGH"}:
            continue
        if "@" not in entry.email:
            continue
        if not entry.on_domain:
            # On-domain filter — passwordspray tooling only wants org addresses.
            if email_domain(entry.email) != domain:
                continue
        out.append(entry)
    return out


def email_domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip() if "@" in addr else ""


def _write_emails_list(path: Path, result: Any) -> Path | None:
    personal = _collect_personal_emails(result)
    if not personal:
        return None
    sorted_emails = sorted({entry.email.strip().lower() for entry in personal})
    if not sorted_emails:
        return None
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    from ..config import APP_VERSION  # local import to avoid a cycle

    header = (
        f"# MailAccess v{APP_VERSION} — {result.domain} — {timestamp}\n"
        "# High/Medium confidence personal emails only\n"
    )
    body = "".join(f"{email}\n" for email in sorted_emails)
    return _write_text(path, header + body)


def _http_variants_for_subdomain(sub: str) -> list[str]:
    """Return the URL variants for a subdomain (HTTPS preferred)."""
    return [f"https://{sub}"]


def _http_fallback_for_subdomain(sub: str) -> str:
    return f"http://{sub}"


def _subdomains_with_port_80_open(result: Any) -> set[str]:
    """Return the set of subdomains for which Shodan InternetDB confirmed port 80."""
    open_set: set[str] = set()
    # Production subdomain enrichment stores InternetDB data on each
    # infrastructure IP row. Map those IPs back to their discovered hosts.
    infrastructure = _build_infrastructure(result)
    for ip_row in infrastructure.get("ips", []):
        if not isinstance(ip_row, dict):
            continue
        shodan_data = ip_row.get("shodan_data")
        if not isinstance(shodan_data, dict) or 80 not in (shodan_data.get("ports") or []):
            continue
        for host in ip_row.get("subdomains") or []:
            cleaned = str(host).strip().lower()
            if cleaned:
                open_set.add(cleaned)

    # Retain compatibility with callers that publish the older host-oriented
    # metadata shape directly.
    for module_result in result.module_results.values():
        metadata = module_result.metadata if module_result else {}
        if not isinstance(metadata, dict):
            continue
        shodan_meta = metadata.get("shodan_internetdb")
        if not isinstance(shodan_meta, dict):
            continue
        for host_entry in shodan_meta.get("hosts") or []:
            if not isinstance(host_entry, dict):
                continue
            ports = host_entry.get("ports") or []
            if 80 in ports:
                host = str(host_entry.get("host") or "").strip().lower()
                if host:
                    open_set.add(host)
    return open_set


def _write_nuclei_targets(path: Path, result: Any) -> Path | None:
    entries = _build_subdomains(result)
    if not entries:
        return None
    sub_domains = sorted(
        {
            str(item.get("subdomain", "")).strip().lower()
            for item in entries
            if item.get("subdomain")
        }
    )
    if not sub_domains:
        return None
    port_80_open = _subdomains_with_port_80_open(result)
    lines: list[str] = []
    for sub in sub_domains:
        lines.extend(_http_variants_for_subdomain(sub))
        if sub in port_80_open:
            lines.append(_http_fallback_for_subdomain(sub))
    if not lines:
        return None
    return _write_text(path, "".join(f"{line}\n" for line in lines))


def _write_cidr_file(path: Path, result: Any) -> Path | None:
    payload = format_harvest_json_export(result)
    infrastructure = payload.get("infrastructure") if isinstance(payload, dict) else None
    if not isinstance(infrastructure, dict):
        return None
    asns = infrastructure.get("asns") or []
    prefixes: set[str] = set()
    for row in asns:
        if not isinstance(row, dict):
            continue
        for prefix in row.get("prefixes") or row.get("cidrs") or []:
            if prefix:
                prefixes.add(str(prefix))
    if not prefixes:
        return None
    return _write_text(path, "".join(f"{prefix}\n" for prefix in sorted(prefixes)))


def _build_markdown_report(result: Any) -> str:
    """Render the human-readable summary report (File 5)."""
    counts = _export_summary_counts(_sanitised_export_emails(result.unique_emails))
    subdomains = _build_subdomains(result)
    infra = _build_infrastructure(result)
    names = _extract_discovered_names(result)
    seg_domain = (result.domain or "").strip().lower()
    confirmed = [
        e
        for e in _sanitised_export_emails(result.unique_emails)
        if e.confidence_label in {"CONFIRMED", "HIGH"} and not e.is_role
    ]
    likely = [
        e
        for e in _sanitised_export_emails(result.unique_emails)
        if e.confidence_label == "LIKELY" and not e.is_role
    ]
    medium = [
        e
        for e in _sanitised_export_emails(result.unique_emails)
        if e.confidence_label == "MEDIUM" and not e.is_role
    ]
    role_count = sum(1 for e in _sanitised_export_emails(result.unique_emails) if e.is_role)
    from ..config import APP_VERSION  # local import — avoid cycle

    started = str(getattr(result, "started_at", "") or "")
    completed = str(getattr(result, "completed_at", "") or "")
    duration = float(getattr(result, "duration_seconds", 0.0) or 0.0)

    def _fmt_ts(ts: str) -> str:
        if not ts:
            return "?"
        text = ts.strip()
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y%m%d%H%M%S"):
            try:
                return datetime.strptime(text[: len(fmt) + 2], fmt).strftime("%Y-%m-%d %H:%M")
            except (TypeError, ValueError):
                continue
        return text[:16]

    minutes, seconds = divmod(int(round(duration)), 60)
    duration_text = f"{minutes}m{seconds:02d}s"

    # Subdomain tier counts.
    tier_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFRA": 0, "SKIP": 0}
    for entry in subdomains:
        tier = str(entry.get("tier", "SKIP"))
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
    high_sub = [s for s in subdomains if str(s.get("tier", "SKIP")) == "HIGH"]

    # IP / ASN summary.
    ips = infra.get("ips", []) if isinstance(infra, dict) else []
    asns = infra.get("asns", []) if isinstance(infra, dict) else []
    ip_total = len(ips)
    asn_total = len(asns)

    lines: list[str] = []
    lines.append(f"# MailAccess Harvest — {seg_domain}")
    lines.append("")
    lines.append(f"**Date:** {_fmt_ts(started or completed)}  ")
    lines.append(f"**Duration:** {duration_text}  ")
    lines.append(f"**Version:** {APP_VERSION}")
    lines.append("")

    # Summary
    summary_emails = (
        f"- {counts['total_unique_emails']} emails found "
        f"({counts['high_confidence']} CONFIRMED · {counts['likely_confidence']} LIKELY · "
        f"{role_count} role)"
    )
    if medium:
        summary_emails += f" · {len(medium)} MEDIUM"
    summary_subs = (
        f"- {len(subdomains)} subdomains found "
        f"({tier_counts['HIGH']} HIGH · {tier_counts['MEDIUM']} MEDIUM)"
    )
    summary_infra = f"- {ip_total} IPs across {asn_total} ASNs"
    lines.append("## Summary")
    lines.append(summary_emails)
    lines.append(f"- {len(names)} employee names discovered")
    lines.append(summary_subs)
    lines.append(summary_infra)
    lines.append("")

    # High-confidence emails table
    lines.append("## High Confidence Emails")
    if confirmed or likely:
        lines.append("| Email | Source | Confidence |")
        lines.append("|-------|--------|------------|")
        for entry in confirmed + likely:
            source = entry.found_by_modules[0] if entry.found_by_modules else "—"
            lines.append(f"| {entry.email} | {source} | {entry.confidence_label} |")
    else:
        lines.append("_No HIGH-confidence personal emails found._")
    lines.append("")

    # Employee names table
    lines.append("## Employee Names")
    if names:
        lines.append("| Name | Title | Source |")
        lines.append("|------|-------|--------|")
        for entry in names[:50]:
            title = entry.get("title_or_role") or "—"
            source = ", ".join(entry.get("sources") or []) or "—"
            lines.append(f"| {entry['name']} | {title} | {source} |")
    else:
        lines.append("_No employee names discovered._")
    lines.append("")

    # Subdomains table
    lines.append("## Subdomains (HIGH tier)")
    if high_sub:
        lines.append("| Subdomain | Score | Finding |")
        lines.append("|-----------|-------|---------|")
        for entry in high_sub[:20]:
            score = float(entry.get("score") or 0.0)
            subdomain = str(entry.get("subdomain", ""))
            finding = ""
            metadata = entry.get("metadata") or {}
            if isinstance(metadata, dict):
                emails_meta = metadata.get("emails_extracted") or metadata.get("emails") or []
                if isinstance(emails_meta, list) and emails_meta:
                    finding = f"{len(emails_meta)} emails extracted"
            lines.append(f"| {subdomain} | {score:.2f} | {finding or '—'} |")
    else:
        lines.append("_No HIGH-tier subdomains._")
    lines.append("")

    # Infrastructure table
    lines.append("## Infrastructure")
    if asns:
        lines.append("| ASN | Org | IPs | CIDR Prefixes |")
        lines.append("|-----|-----|-----|---------------|")
        for record in asns:
            asn = record.get("asn")
            org = record.get("name") or "Unknown"
            ip_count = len(record.get("ips") or [])
            prefixes = record.get("prefixes") or record.get("cidrs") or []
            cidr_text = ", ".join(str(prefix) for prefix in prefixes) or "—"
            lines.append(f"| AS{asn} | {org} | {ip_count} | {cidr_text} |")
    else:
        lines.append("_No ASN data resolved._")
    lines.append("")

    # Suggested next steps
    lines.append("## Suggested Next Steps")
    next_steps: list[str] = []
    if likely:
        next_steps.append("- Run with SMTP verification enabled to confirm pattern candidates")
    high_sub_names = [str(s.get("subdomain", "")) for s in high_sub if s.get("subdomain")]
    if high_sub_names:
        next_steps.append(f"- Probe {high_sub_names[0]} for additional employee data")
    if asns:
        next_steps.append("- Use cidrs.txt as masscan input for port scanning")
    if not next_steps:
        next_steps.append("- Review the JSON export for full evidence")
    lines.extend(next_steps)
    lines.append("")
    return "\n".join(lines)


def _write_markdown_report_file(path: Path, result: Any) -> Path | None:
    text = _build_markdown_report(result)
    return _write_text(path, text)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class HarvestResultFiles:
    """Container for the paths produced by :func:`write_harvest_results`."""

    main_json: Path | None = None
    live_log: Path | None = None
    subdomains: Path | None = None
    emails: Path | None = None
    nuclei_targets: Path | None = None
    report_md: Path | None = None
    cidrs: Path | None = None

    def all_written(self) -> list[Path]:
        return [p for p in (self.main_json, self.live_log, self.subdomains,
                            self.emails, self.nuclei_targets, self.report_md,
                            self.cidrs) if p is not None]


async def write_harvest_results(
    result: Any,
    *,
    timestamp: str,
    no_export: bool = False,
    no_extras: bool = False,
    extra_export_path: Path | None = None,
) -> HarvestResultFiles:
    """Write the default JSON + supplementary files for one harvest.

    Parameters
    ----------
    result:
        A :class:`DomainHarvestResult` (or any duck-typed object with
        ``domain``, ``unique_emails``, ``module_results``).
    timestamp:
        ``YYYYMMDD_HHMMSS`` slug used in the filenames.
    no_export:
        If True, skip the default JSON AND all supplementary files.
        Equivalent to the ``--no-export`` CLI flag.
    no_extras:
        If True, write only the main JSON (plus the explicitly-requested
        ``extra_export_path`` if any).  Equivalent to ``--no-extras``.
    extra_export_path:
        When provided, an additional JSON copy is written to this path
        (the legacy ``--export <path>`` flow).  The default export is
        still written unless ``no_export=True``.
    """
    if no_export:
        return HarvestResultFiles()

    paths = results_paths(result.domain, timestamp)
    text, err = serialise_harvest_for_export(result, "default.json")
    if err is not None:
        _LOG.warning("harvest_results: default JSON serialisation failed: %s", err)
        return HarvestResultFiles()

    main_json = await asyncio.to_thread(_write_text, paths["json"], text)
    extras: dict[str, Path | None] = {"main_json": main_json}

    if extra_export_path is not None:
        # Write the explicit export too — same payload, different path.
        def _write_extra() -> Path:
            extra_export_path.parent.mkdir(parents=True, exist_ok=True)
            extra_export_path.write_text(text, encoding="utf-8")
            return extra_export_path

        await asyncio.to_thread(_write_extra)

    if not no_extras:
        # Run all supplementary writers concurrently; each one is
        # small enough that the thread pool's default size covers us.
        sub_task = asyncio.to_thread(_write_subdomain_list, paths["subdomains"], result)
        em_task = asyncio.to_thread(_write_emails_list, paths["emails"], result)
        nucl_task = asyncio.to_thread(_write_nuclei_targets, paths["nuclei_targets"], result)
        md_task = asyncio.to_thread(_write_markdown_report_file, paths["report_md"], result)
        cidr_task = asyncio.to_thread(_write_cidr_file, paths["cidrs"], result)
        sub, em, nucl, md, cidr = await asyncio.gather(
            sub_task, em_task, nucl_task, md_task, cidr_task
        )
        extras["subdomains"] = sub
        extras["emails"] = em
        extras["nuclei_targets"] = nucl
        extras["report_md"] = md
        extras["cidrs"] = cidr

    # Live log file is created (touched) by the LiveHarvestDisplay;
    # we do not write content here — the live display appends events
    # as they happen.  We DO ensure the file exists so analysts can
    # tail it from before the first event.
    live_log = paths["live_log"]
    await asyncio.to_thread(_ensure_file, live_log)
    extras["live_log"] = live_log

    # Lazy cleanup — drop oldest per-domain files and anything older
    # than ``harvest_results_max_age_days``.
    await asyncio.to_thread(
        _cleanup_results_dir,
        paths["base_dir"],
        str(getattr(result, "domain", "") or ""),
        int(getattr(settings, "harvest_results_max_per_domain", 50) or 50),
        int(getattr(settings, "harvest_results_max_age_days", 30) or 30),
    )

    return HarvestResultFiles(**extras)


def _ensure_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)


def _cleanup_results_dir(
    base: Path,
    domain: str,
    max_per_domain: int,
    max_age_days: int,
) -> None:
    """Lazy cleanup: drop oldest per-domain files and stale entries.

    Conservative — only removes files that match the canonical
    ``{domain}_{timestamp}{_suffix}.{ext}`` shape.  Never touches
    unrelated files in the same directory.
    """
    if not base.exists():
        return
    seg = _safe_domain_segment(domain)
    if not seg:
        return
    prefix = f"{seg}_"
    candidates: list[Path] = []
    for entry in base.iterdir():
        if not entry.is_file():
            continue
        if not entry.name.startswith(prefix):
            continue
        candidates.append(entry)
    if not candidates:
        return

    # 1. age-based cleanup
    if max_age_days > 0:
        cutoff = time.time() - (max_age_days * 86400)
        for path in candidates:
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
            except OSError:
                continue
        # Re-list after deletions
        candidates = [p for p in base.iterdir() if p.is_file() and p.name.startswith(prefix)]

    # 2. count-based cleanup — keep the most recent N
    if max_per_domain > 0 and len(candidates) > max_per_domain:
        candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        for stale in candidates[max_per_domain:]:
            with contextlib.suppress(OSError):
                stale.unlink()


def prune_stale_results(base: Path, max_age_days: int) -> int:
    """Public helper: delete any result file older than *max_age_days*.

    Returns the number of files removed.  Used by callers that want to
    trigger a cleanup without running a harvest (e.g. a scheduled job).
    """
    if not base.exists():
        return 0
    cutoff = time.time() - (max_age_days * 86400)
    removed = 0
    for path in base.iterdir():
        if not path.is_file():
            continue
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def list_results_for_domain(base: Path, domain: str) -> list[Path]:
    """Return the existing result files for *domain*, newest first."""
    seg = _safe_domain_segment(domain)
    if not base.exists():
        return []
    prefix = f"{seg}_"
    out: list[Path] = []
    for path in base.iterdir():
        if path.is_file() and path.name.startswith(prefix):
            out.append(path)
    out.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return out


# Re-export for callers that want a single import surface.
__all__ = [
    "HarvestResultFiles",
    "list_results_for_domain",
    "prune_stale_results",
    "results_dir",
    "results_paths",
    "timestamp_slug",
    "write_harvest_results",
]
