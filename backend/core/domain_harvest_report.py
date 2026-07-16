"""Domain Email Harvest report formatter — Phase C3.

Two output formats:

* :func:`format_harvest_cli_output` — Rich-formatted, human-readable
  summary for the CLI.  Domain-centric, NOT the normal email-
  investigation output format.
* :func:`format_harvest_json_export` — full machine-readable export
  preserving every evidence entry from every module.

The visual style follows the existing MailAccess CLI palette
(see ``cli/main.py``'s ``get_status_color`` / ``get_risk_color``) so
the harvest command feels native to the rest of the tool.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from .domain_harvest_orchestrator import (
    DomainHarvestResult,
    HarvestedEmail,
    _name_matches_email_local,
)
from .email_extraction import is_placeholder_domain, validate_email
from .enrichment.shadow_profiles import ShadowProfileDetector
from .harvest_quality import build_metrics

# --------------------------------------------------------------------------
# Color palette — mirrors cli/main.py's get_status_color /
# get_risk_color so the harvest command blends with the rest of the
# CLI's aesthetic.
# --------------------------------------------------------------------------
# P7: 4-tier color palette.  CONFIRMED and LIKELY are both
# "actionable" tiers so they share the green hue family;
# MEDIUM is the soft-yellow cautionary tier; LOW is the
# dim "speculative" tier.
_LABEL_COLORS = {
    "CONFIRMED": "green",
    "LIKELY": "bright_green",
    "MEDIUM": "yellow",
    "LOW": "dim",
}

_STATUS_COLORS = {
    "success": "green",
    "complete": "green",
    "failed": "red",
    "pending": "cyan",
    "running": "cyan",
    "partial": "yellow",
    "skipped": "dim",
}

_EXPORT_PLACEHOLDER_EMAIL_RE = re.compile(
    r"^(?:"
    r"[^@\s]+@(?:example|test)\.com"
    r"|[a-z0-9._%+\-]{1,8}@\.[a-z]{2,}"
    r"|email@[^@\s]+\.com"
    r")$",
    re.IGNORECASE,
)


def _is_placeholder_export_email(value: str | None) -> bool:
    if not isinstance(value, str):
        return False
    email = value.strip().lower()
    if not email:
        return False
    if _EXPORT_PLACEHOLDER_EMAIL_RE.fullmatch(email):
        return True
    if validate_email(email):
        _, _, domain = email.partition("@")
        return is_placeholder_domain(domain)
    return False


def _build_shadow_profiles(result: DomainHarvestResult) -> list[dict[str, Any]]:
    """Expose same-name/different-email identity pairs in harvest output."""
    findings: list[dict[str, Any]] = []
    for module_name, module_result in result.module_results.items():
        for finding in module_result.findings or []:
            if not isinstance(finding, dict):
                continue
            item = dict(finding)
            item["module_name"] = module_name
            findings.append(item)
    inferred = ShadowProfileDetector().find_shadow_pairs(findings)
    explicit = [
        dict(item)
        for item in getattr(result, "shadow_profiles", [])
        if isinstance(item, dict)
    ]
    return [*explicit, *inferred]


def _build_subdomains(result: DomainHarvestResult) -> list[dict[str, Any]]:
    values: dict[str, dict[str, Any]] = {}
    for module_result in result.module_results.values():
        for finding in module_result.findings or []:
            if not isinstance(finding, dict):
                continue
            subdomain = finding.get("subdomain")
            if not isinstance(subdomain, str):
                subdomain = (finding.get("metadata") or {}).get("subdomain")
            if isinstance(subdomain, str) and subdomain.strip():
                item = dict(finding)
                item["subdomain"] = subdomain.strip().lower()
                existing = values.get(item["subdomain"])
                if existing is None or item.get("tier") is not None:
                    values[item["subdomain"]] = item
    return [values[key] for key in sorted(values)]


def _format_subdomain_panel(result: DomainHarvestResult) -> Panel | Text:
    entries = _build_subdomains(result)
    module = result.module_results.get("subdomain_intel") or result.module_results.get(
        "subdomain_surface"
    )
    metadata = (module.metadata if module else {}) or {}
    if not entries and (not metadata or metadata.get("skip_reason")):
        return Text()
    counts = {
        tier: sum(str(item.get("tier", "SKIP")) == tier for item in entries)
        for tier in ("HIGH", "MEDIUM", "LOW", "SKIP", "INFRA")
    }
    tier_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFRA": 3, "SKIP": 4}
    top = sorted(
        entries,
        key=lambda item: (
            tier_order.get(str(item.get("tier", "SKIP")), 9),
            -float(item.get("score") or 0.0),
            str(item.get("subdomain", "")),
        ),
    )[:20]
    text = Text()
    text.append(
        f"  {len(entries)} discovered · "
        + " · ".join(
            f"{tier} {counts[tier]}" for tier in ("HIGH", "MEDIUM", "LOW", "INFRA", "SKIP")
        )
        + "\n"
    )
    text.append("  Top 20 by score:\n", style="bold")
    for item in top:
        tier = str(item.get("tier", "SKIP"))
        host = str(item.get("subdomain", ""))
        status = "scraped" if item.get("scraped") else "noted"
        if tier == "INFRA":
            status = "skipped"
        text.append(
            f"  {tier:<6} {host:<32} {float(item.get('score') or 0.0):.2f} [{status}]\n",
            style="dim" if tier in {"LOW", "SKIP"} else None,
        )
    if len(entries) > 20:
        text.append(f"  + {len(entries) - 20} more — full list in --export JSON\n", style="dim")
    source_counts = metadata.get("source_counts") or {}
    if source_counts:
        text.append(
            "  Sources: "
            + " · ".join(f"{key} ({value})" for key, value in sorted(source_counts.items()))
            + "\n",
            style="dim",
        )
    budget = metadata.get("budget") or {}
    if budget:
        text.append(
            f"  Budget: {budget.get('elapsed_seconds', 0)}s elapsed · hard cap {'hit' if budget.get('hard_exceeded') else 'not hit'}\n",
            style="dim",
        )
    return Panel(text, title="[bold cyan]SUBDOMAINS DISCOVERED[/bold cyan]", border_style="cyan")


def _build_infrastructure(result: DomainHarvestResult) -> dict[str, list[dict[str, Any]]]:
    """Return the normalized IP/ASN footprint emitted by subdomain discovery."""
    ip_rows: dict[str, dict[str, Any]] = {}
    asn_rows: dict[int, dict[str, Any]] = {}
    for module_result in result.module_results.values():
        metadata = module_result.metadata or {}
        infrastructure = metadata.get("infrastructure")
        if not isinstance(infrastructure, dict):
            continue
        ips = infrastructure.get("ips")
        asns = infrastructure.get("asns")
        if not isinstance(ips, list) or not isinstance(asns, list):
            continue
        for row in ips:
            if not isinstance(row, dict) or not row.get("ip"):
                continue
            key = str(row["ip"])
            existing = ip_rows.setdefault(key, {"ip": key})
            existing.update(row)
            for field in ("subdomains", "sources"):
                existing[field] = sorted(
                    {*existing.get(field, []), *row.get(field, [])}
                )
        for row in asns:
            if not isinstance(row, dict):
                continue
            try:
                key = int(row.get("asn"))
            except (TypeError, ValueError):
                continue
            existing = asn_rows.setdefault(key, {"asn": key})
            existing.update(row)
            for field in ("ips", "cidrs", "prefixes", "subdomains", "sources"):
                existing[field] = sorted(
                    {*existing.get(field, []), *row.get(field, [])}
                )
    return {
        "ips": [ip_rows[key] for key in sorted(ip_rows)],
        "asns": [asn_rows[key] for key in sorted(asn_rows)],
    }


def _format_infrastructure_panel(infrastructure: dict[str, list[dict[str, Any]]]) -> Panel:
    ips = infrastructure.get("ips", [])
    asns = infrastructure.get("asns", [])
    lines = Text()
    for record in asns:
        if not isinstance(record, dict):
            continue
        lines.append(
            f"  AS{record.get('asn')} {record.get('name') or 'Unknown'}"
            f"  · {len(record.get('ips') or [])} IPs"
            f" · {len(record.get('cidrs') or [])} CIDRs\n"
        )
        prefixes = record.get("prefixes") or record.get("cidrs") or []
        if prefixes:
            lines.append(f"    Prefixes: {', '.join(prefixes[:4])}\n", style="dim")
    for record in ips[:20]:
        shodan = record.get("shodan_data") if isinstance(record, dict) else None
        if not isinstance(shodan, dict):
            continue
        ports = ",".join(str(value) for value in shodan.get("ports", [])) or "none"
        vulns = ",".join(str(value) for value in shodan.get("vulns", [])[:3]) or "none"
        asn = f"AS{record.get('asn')}" if record.get("asn") else "ASN unknown"
        lines.append(
            f"  {record.get('ip')} · {asn} · Ports: {ports} · Vulns: {vulns}\n"
        )
    if not asns:
        lines.append("  No ASN data resolved.\n", style="dim")
    return Panel(
        lines,
        title=f"[bold cyan]INFRASTRUCTURE ({len(ips)} IPs · {len(asns)} ASNs)[/bold cyan]",
        border_style="cyan",
    )


def _sanitised_export_emails(emails: list[HarvestedEmail]) -> list[HarvestedEmail]:
    out: list[HarvestedEmail] = []
    for entry in emails:
        if _is_placeholder_export_email(entry.email):
            continue
        variants = [
            variant
            for variant in entry.subaddress_variants
            if not _is_placeholder_export_email(variant)
        ]
        if variants != entry.subaddress_variants:
            entry = replace(entry, subaddress_variants=variants)
        out.append(entry)
    return out


def _export_summary_counts(emails: list[HarvestedEmail]) -> dict[str, int]:
    personal = [entry for entry in emails if not entry.is_role]
    smtp_statuses: list[str] = []
    for entry in emails:
        for evidence in entry.evidence or []:
            metadata = evidence.get("metadata") if isinstance(evidence, dict) else None
            if isinstance(metadata, dict):
                status = metadata.get("smtp_verification_status")
                if isinstance(status, str) and status:
                    smtp_statuses.append(status)
                    break
    return {
        "total_unique_emails": len(emails),
        # P7: 4-tier count fields.  We keep the legacy
        # ``high_confidence`` / ``medium_confidence`` /
        # ``low_confidence`` keys for backward compatibility
        # (downstream tooling depends on them) and add the new
        # ``likely_confidence`` field.  ``high_confidence`` now
        # counts the CONFIRMED tier; ``medium_confidence``
        # counts BOTH LIKELY and MEDIUM (the historical
        # "anything above low" band); ``low_confidence``
        # counts the LOW tier.
        "high_confidence": sum(1 for entry in personal if entry.confidence_label == "CONFIRMED"),
        "likely_confidence": sum(1 for entry in personal if entry.confidence_label == "LIKELY"),
        "medium_confidence": sum(
            1 for entry in personal if entry.confidence_label in {"LIKELY", "MEDIUM"}
        ),
        "low_confidence": sum(1 for entry in personal if entry.confidence_label == "LOW"),
        "role_accounts": sum(1 for entry in emails if entry.is_role),
        "personal_emails": len(personal),
        "smtp_verified_emails": smtp_statuses.count("verified"),
        "smtp_not_found_emails": smtp_statuses.count("not_found"),
        "smtp_inconclusive_emails": sum(
            1
            for status in smtp_statuses
            if status in {"inconclusive", "temporary_failure", "blocked", "verification_timeout"}
        ),
        "smtp_not_attempted_emails": smtp_statuses.count("not_attempted"),
    }


def _email_validation_summary(entry: HarvestedEmail) -> dict[str, Any]:
    """Flatten native and SMTP evidence for tabular/streaming exports."""
    native: dict[str, Any] = {}
    smtp: dict[str, Any] = {}
    m365: dict[str, Any] = {}
    for evidence in entry.evidence or []:
        metadata = evidence.get("metadata") if isinstance(evidence, dict) else None
        if not isinstance(metadata, dict):
            continue
        if not native and isinstance(metadata.get("native_email_validation"), dict):
            native = metadata["native_email_validation"]
        if not smtp and isinstance(metadata.get("smtp_validation"), dict):
            smtp = metadata["smtp_validation"]
        if not smtp and metadata.get("smtp_verification_status"):
            smtp = {"status": metadata["smtp_verification_status"]}
        if not m365 and isinstance(metadata.get("m365_verification"), dict):
            m365 = metadata["m365_verification"]
        if not m365 and isinstance(metadata.get("yahoo_verification"), dict):
            m365 = metadata["yahoo_verification"]
    return {
        "native_validation_status": native.get("status", ""),
        "native_mx_valid": native.get("mx_valid", ""),
        "smtp_verification_status": smtp.get("status", ""),
        "smtp_exists": smtp.get("exists", ""),
        "smtp_mx_host": smtp.get("mx_host", ""),
        "smtp_transport_error": smtp.get("transport_error", ""),
        "smtp_catchall": smtp.get("is_catchall", ""),
        "provider_verification_status": m365.get("status", ""),
        "provider_verification_provider": m365.get("provider", ""),
        "m365_if_exists_result": m365.get("if_exists_result", ""),
    }


def _format_timestamp(value: str | None) -> str:
    if not value:
        return "unknown"
    text = str(value).strip()
    if not text:
        return "unknown"
    try:
        if len(text) == 14 and text.isdigit():
            return datetime.strptime(text, "%Y%m%d%H%M%S").strftime("%Y-%m-%d")
        if len(text) == 8 and text.isdigit():
            return datetime.strptime(text, "%Y%m%d").strftime("%Y-%m-%d")
        if "T" in text or "-" in text:
            return text[:10]
    except (TypeError, ValueError):
        return text[:10] if text else "unknown"
    return text[:10] if len(text) >= 10 else text


def _module_display_name(name: str) -> str:
    """Map module-name slugs to user-friendly labels."""
    mapping = {
        "commoncrawl_email": "Common Crawl",
        "code_and_cert_email": "Code & Cert",
        "email_search_dork": "Search Dork",
        "employee_name_discovery": "Employee Names",
        "npm_email": "npm Registry",
        "pypi_email": "PyPI Registry",
        "pgp_domain_email": "PGP Keyservers",
        "pattern_and_verify": "Pattern+Verify",
        "person_email_pivot": "Person Email Pivot",
        "email_identity_enrichment": "Identity Enrichment",
        "gravatar_lookup": "Gravatar",
        "github_commits": "GitHub Commits",
    }
    return mapping.get(name, name.replace("_", " ").title())


def _rationale_chip(entry: HarvestedEmail) -> str:
    """Build a compact ``(...why this confidence label)`` string.

    MUST-FIX S4: analysts saw ``HIGH`` / ``MEDIUM`` / ``LOW`` with no
    explanation. This builds a one-line rationale from the per-email
    ``confidence_breakdown`` that's already on the entry — short enough
    to fit in a table row, rich enough to convey the major factors.

    Forms (always parenthesised):
        ``(smtp+cc+recent)``
        ``(3 sources, multi-source verified)``
        ``(ca+cc)``
        ``(cc only)``
        ``(1 source, recent)``
    """
    breakdown = entry.confidence_breakdown or {}
    source_types: list[str] = sorted(
        breakdown.get("source_types") or sorted({m for m in entry.found_by_modules if m})
    )
    # Map source_types to compact display labels.
    compact_map = {
        "common_crawl_single": "cc",
        "common_crawl_medium": "cc",
        "common_crawl_high_density": "cc*",
        "ca_attested": "ca",
        "smtp_verified": "smtp",
        "permutation_verified": "smtp",
        "permutation_catchall": "catchall",
        "permutation_mx_valid": "mx",
        "permutation_verified_m365": "m365",
        "permutation_verified_yahoo": "yahoo",
        "permutation_gravatar_hit": "gravatar",
        "permutation_breach_hit": "breach",
        "permutation_unverified": "perm",
        "permutation_unverified_{first}_{last}": "perm:first.last",
        "permutation_unverified_{first}": "perm:first",
        "permutation_unverified_{f}{last}": "perm:flast",
        "permutation_unverified_{first}{last}": "perm:firstlast",
        "permutation_unverified_{last}": "perm:last",
        "permutation_unverified_{last}_{first}": "perm:last.first",
        "permutation_unverified_other": "perm:other",
        "github_commit_author": "gh",
        "github_code_match": "gh-code",
        "github_profile_email": "gh-profile",
        "security_txt_contact": "security.txt",
        "structured_page": "page",
        "json_ld": "json-ld",
        "microdata": "microdata",
        "rdfa": "rdfa",
        "hcard": "hcard",
        "mailto": "mailto",
        "press_release": "press",
        "search_snippet_ddg": "ddg",
        "search_snippet_bing": "bing",
        # W5: the three new structured-source modules.
        "npm_package_author": "npm",
        "pypi_package_author": "pypi",
        "pgp_uid": "pgp",
    }
    chips: list[str] = []
    for st in source_types:
        label = compact_map.get(st)
        if label and label not in chips:
            chips.append(label)
    smtp_status: str | None = None
    catchall_limited = False
    for evidence in entry.evidence or []:
        metadata = evidence.get("metadata") if isinstance(evidence, dict) else None
        if not isinstance(metadata, dict):
            continue
        candidate_status = metadata.get("smtp_verification_status")
        if isinstance(candidate_status, str):
            smtp_status = candidate_status
        validation = metadata.get("smtp_validation")
        if isinstance(validation, dict) and validation.get("is_catchall") is True:
            catchall_limited = True
    if smtp_status == "verified" and "smtp" not in chips:
        chips.insert(0, "smtp")
    elif catchall_limited and smtp_status == "not_attempted" and "catchall" not in chips:
        chips.insert(0, "catchall")
    multiplier_label = breakdown.get("multiplier_label") or ""
    # Tighten "smtp_verified" → "smtp", collapse synonyms
    if "smtp" in chips and multiplier_label in ("smtp_verified", "pgp_or_ca"):
        # already covered by smtp chip
        pass
    freshness = breakdown.get("freshness")
    fresh_chip = ""
    if isinstance(freshness, int | float) and freshness >= 0.95:
        fresh_chip = "recent"
    elif isinstance(freshness, int | float) and freshness <= 0.5:
        fresh_chip = "stale"

    parts: list[str] = []
    if chips:
        parts.append("+".join(chips))
    elif entry.found_by_modules:
        parts.append("+".join(sorted(entry.found_by_modules)))
    else:
        parts.append("1 source")
    if multiplier_label and multiplier_label not in ("single_source",):
        parts.append(multiplier_label.replace("_", "-"))
    if fresh_chip:
        parts.append(fresh_chip)
    if not parts:
        return "(unknown)"
    return "(" + " ".join(parts) + ")"


def _is_unverified_permutation(entry: HarvestedEmail) -> bool:
    """Return True for emails generated as patterns but never SMTP-verified.

    Phase 1 of 4: after Change 1 (``permutation_unverified`` weight
    drops to 0.0) these candidates always score 0.0 and therefore
    always land in LOW.  They are qualitatively different from a real
    email that happened to score LOW (e.g. stale CC data): they were
    synthesised from a name pattern and the SMTP probe didn't confirm
    them.  The CLI hides them by default and shows a dedicated
    suppressed-count line.

    Detection rule (per spec): any evidence entry from the
    ``pattern_and_verify`` module carrying
    ``verification_status="unverified"``.
    """
    for ev in entry.evidence or []:
        if not isinstance(ev, dict):
            continue
        if ev.get("module") != "pattern_and_verify":
            continue
        meta = ev.get("metadata") or {}
        if not isinstance(meta, dict):
            continue
        if meta.get("verification_status") == "unverified":
            return True
    return False


def _subaddress_annotations(entry: HarvestedEmail) -> list[str]:
    """Explain alternate address forms collapsed by subaddress_key()."""
    if not entry.subaddress_variants:
        return []
    has_plus = "+" in entry.email.split("@", 1)[0] or any(
        "+" in variant.split("@", 1)[0] for variant in entry.subaddress_variants
    )
    source_types: set[str] = set(entry.found_by_modules)
    for evidence in entry.evidence or []:
        module = evidence.get("module") if isinstance(evidence, dict) else ""
        if module == "pgp_domain_email":
            source_types.add("pgp_uid")
        meta = evidence.get("metadata") if isinstance(evidence, dict) else {}
        if isinstance(meta, dict):
            value = meta.get("source_type")
            if isinstance(value, str):
                source_types.add(value)
            values = meta.get("source_types")
            if isinstance(values, list):
                source_types.update(str(item) for item in values)
    if has_plus and ({"pgp_uid", "pgp_domain_email"} & source_types):
        return ["PGP key alias"]
    if has_plus:
        return ["plus-address alias"]
    return ["subaddress variant"]


def _extract_discovered_names(result: DomainHarvestResult) -> list[dict[str, Any]]:
    """Pull discovered employee names from the ``employee_name_discovery``
    module's findings.

    MUST-FIX S13: the orchestrator already aggregates these names into
    pattern_and_verify's input, but the analyst never sees them in the
    CLI output. Each ``EmployeeNameResult`` carries the ``name``,
    ``sources`` (which sub-sources attested it), and ``confidence``.
    """
    module_result = (result.module_results or {}).get("employee_name_discovery")
    if module_result is None:
        return []
    pattern_result = (result.module_results or {}).get("pattern_and_verify")
    pattern_by_name: dict[str, dict[str, Any]] = {}
    pattern_medium_threshold = 0.50
    if pattern_result is not None:
        pattern_meta = pattern_result.metadata or {}
        if isinstance(pattern_meta, dict):
            pattern_medium_threshold = float(
                pattern_meta.get("pattern_medium_confidence_threshold") or 0.50
            )
            for item in pattern_meta.get("pattern_generation_by_name") or []:
                if not isinstance(item, dict):
                    continue
                name_key = str(item.get("name") or "").strip().lower()
                if name_key:
                    pattern_by_name[name_key] = item
    findings = module_result.findings or []
    out: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        meta = finding.get("metadata") or {}
        if not isinstance(meta, dict):
            continue
        name = meta.get("name")
        if not name:
            continue
        if len(str(name).split()) < 2:
            continue
        row = {
            "name": str(name),
            "sources": list(meta.get("sources") or []),
            "source_count": int(meta.get("source_count") or 0),
            "title_or_role": meta.get("title_or_role"),
            "confidence_score": float(meta.get("confidence_score") or 0.0),
            "source_urls": list(meta.get("source_urls") or []),
        }
        pattern_row = pattern_by_name.get(str(name).strip().lower())
        if pattern_row:
            row["pattern_tier"] = pattern_row.get("tier")
            row["patterns_generated"] = int(pattern_row.get("patterns_generated") or 0)
            row["pattern_skipped"] = bool(pattern_row.get("skipped"))
            row["pattern_skip_reason"] = pattern_row.get("skip_reason")
            row["pattern_medium_confidence_threshold"] = pattern_medium_threshold
            row["downgraded_for_budget"] = bool(pattern_row.get("downgraded_for_budget"))
        out.append(row)
    # Highest-confidence first, multi-source wins ties.
    out.sort(
        key=lambda r: (
            -r["confidence_score"],
            -r["source_count"],
            r["name"].lower(),
        )
    )
    return out


def _build_people(
    result: DomainHarvestResult,
    *,
    include_low: bool = True,
    include_patterns: bool = True,
) -> list[dict[str, Any]]:
    """Build person-centric rows by joining names to email evidence.

    A direct ``metadata.name`` match wins.  When a source only provides an
    email, the same conservative local-part matcher used by the aggregator
    provides a secondary link.  The original email list remains authoritative;
    this is an analyst-facing view over that evidence, not a new confidence
    scorer.
    """
    people: dict[str, dict[str, Any]] = {}

    def ensure(
        name: str,
        source: str,
        *,
        title: str | None = None,
        confidence: float = 0.0,
        urls: list[str] | None = None,
    ) -> dict[str, Any] | None:
        clean = " ".join(str(name or "").split())
        if not clean:
            return None
        key = clean.casefold()
        row = people.setdefault(
            key,
            {
                "name": clean,
                "title_or_role": title,
                "sources": [],
                "source_urls": [],
                "confidence_score": 0.0,
                "emails": {},
            },
        )
        if source and source not in row["sources"]:
            row["sources"].append(source)
        if title and not row.get("title_or_role"):
            row["title_or_role"] = title
        row["confidence_score"] = max(row["confidence_score"], float(confidence or 0.0))
        for url in urls or []:
            if isinstance(url, str) and url and url not in row["source_urls"]:
                row["source_urls"].append(url)
        return row

    def attach(row: dict[str, Any], entry: HarvestedEmail, reason: str) -> None:
        email = entry.email
        detail = row["emails"].setdefault(
            email,
            {
                "email": email,
                "confidence_score": entry.confidence_score,
                "confidence_label": entry.confidence_label,
                "identity_graph_score": entry.identity_graph_score,
                "identity_graph_label": entry.identity_graph_label,
                "identity_graph_flags": entry.identity_graph_flags,
                "pattern_only": _is_unverified_permutation(entry),
                "sources": list(entry.found_by_modules),
                "evidence_urls": list(entry.aggregated_source_urls),
                "match_reasons": [],
                "is_role": entry.is_role,
                "subaddress_variants": list(entry.subaddress_variants),
                "subaddress_annotations": _subaddress_annotations(entry),
            },
        )
        if reason not in detail["match_reasons"]:
            detail["match_reasons"].append(reason)
        for url in entry.aggregated_source_urls:
            if url not in detail["evidence_urls"]:
                detail["evidence_urls"].append(url)

    discovered = _extract_discovered_names(result)
    for name_row in discovered:
        ensure(
            name_row["name"],
            "employee_name_discovery",
            title=name_row.get("title_or_role"),
            confidence=name_row.get("confidence_score", 0.0),
            urls=name_row.get("source_urls") or [],
        )

    entries = _sanitised_export_emails(result.unique_emails)
    for entry in entries:
        if entry.is_role:
            continue
        if entry.confidence_label == "LOW" and not include_low:
            continue
        if _is_unverified_permutation(entry) and not include_patterns:
            continue
        direct_names: list[tuple[str, str]] = []
        for evidence in entry.evidence or []:
            meta = evidence.get("metadata") if isinstance(evidence, dict) else {}
            if not isinstance(meta, dict):
                continue
            for key in ("name", "person_name", "source_name", "display_name", "author_name"):
                value = meta.get(key)
                if isinstance(value, str) and value.strip():
                    direct_names.append((value, str(evidence.get("module") or "evidence")))
                    break
        linked = False
        for name, source in direct_names:
            row = ensure(name, source, confidence=entry.confidence_score)
            if row is not None:
                attach(row, entry, "direct_source_name")
                linked = True
        for row in people.values():
            if _name_matches_email_local(row["name"], entry.email.rsplit("@", 1)[0]):
                attach(row, entry, "email_local_part_match")
                linked = True
        if not linked:
            from ..modules.person_email_pivot import derive_name_from_email

            derived = derive_name_from_email(entry.email)
            if derived:
                row = ensure(derived, "email_local_part", confidence=entry.confidence_score)
                if row is not None:
                    attach(row, entry, "derived_from_email")

    out: list[dict[str, Any]] = []
    for row in people.values():
        emails = sorted(
            row["emails"].values(), key=lambda item: (-item["confidence_score"], item["email"])
        )
        row["emails"] = emails
        row["email_count"] = len(emails)
        row["status"] = (
            "name_only"
            if not emails
            else "pattern_only"
            if all(item.get("pattern_only") for item in emails)
            else "email_found"
        )
        row["confidence_label"] = label_for_score(row["confidence_score"])
        row["sources"].sort()
        out.append(row)
    out.sort(
        key=lambda item: (-item["email_count"], -item["confidence_score"], item["name"].casefold())
    )
    return out


def _format_people_panel(people: list[dict[str, Any]], *, max_lines: int = 50) -> Panel | Text:
    text = Text()
    if not people:
        text.append("  No person-to-email links discovered.", style="dim")
    else:
        for person in people[:max_lines]:
            text.append("  * ", style="dim")
            text.append(
                person["name"], style=_LABEL_COLORS.get(person["confidence_label"], "white")
            )
            # P7: short label for the people row.  The 3-letter
            # codes keep the row compact (legacy "MED" stays
            # "MED"; "HIGH" is now "CONF" or "LKLY" depending
            # on the actual tier).
            short_label = {
                "CONFIRMED": "CONF",
                "LIKELY": "LKLY",
                "MEDIUM": "MED",
                "LOW": "LOW",
            }.get(person["confidence_label"], person["confidence_label"])
            text.append(f"  [{person['status']} {short_label} {person['confidence_score']:.2f}]")
            if person["emails"]:
                text.append("  ")
                text.append(", ".join(item["email"] for item in person["emails"][:4]), style="cyan")
            if person["sources"]:
                text.append(f"  via {','.join(person['sources'][:4])}", style="dim")
            evidence_urls = sorted(
                {
                    url
                    for email in person["emails"][:4]
                    for url in email.get("evidence_urls", [])[:2]
                    if url
                }
            )
            if evidence_urls:
                text.append("  evidence: " + " | ".join(evidence_urls[:2]), style="blue")
            text.append("\n")
        if len(people) > max_lines:
            text.append(f"  …and {len(people) - max_lines} more\n", style="dim")
    return Panel(text, title=f"[bold]People → emails ({len(people)})[/bold]", border_style="blue")


def _format_discovered_names_panel(
    names: list[dict[str, Any]],
    *,
    max_lines: int = 50,
) -> Panel | Text:
    """Render the ``Discovered names`` Panel for S13.

    Returns a ``Panel`` when names exist, otherwise a one-line ``Text``
    reading "no names discovered". Tested explicitly in
    ``tests/test_domain_harvest_report.py``.
    """
    text = Text()
    if not names:
        text.append("  No employee names discovered.", style="dim")
    else:
        for entry in names[:max_lines]:
            label = str(entry.get("pattern_tier") or "").upper()
            if not label:
                label = label_for_score(entry["confidence_score"])
            # P7: short display labels for the name panel.  The
            # ``pattern_tier`` field is internal (always lowercase:
            # ``high``/``medium``/``low``); the 4-tier label
            # system uses the new ``CONFIRMED``/``LIKELY``/
            # ``MEDIUM``/``LOW`` strings.  We map both into the
            # compact 3-letter codes so the analyst sees the
            # same visual length regardless of which label
            # vocabulary the underlying code uses.
            short_label = {
                "HIGH": "HIGH",
                "CONFIRMED": "HIGH",
                "LIKELY": "HIGH",
                "MEDIUM": "MED",
                "MED": "MED",
                "LOW": "LOW",
            }.get(label, label)
            color = _LABEL_COLORS.get(label, "white")
            text.append("  * ", style="dim")
            text.append(entry["name"], style=color)
            if entry.get("title_or_role"):
                text.append(f"  ({entry['title_or_role']})", style="dim")
            text.append(
                f"  via {','.join(entry['sources'])}",
                style="cyan",
            )
            if entry.get("pattern_tier"):
                text.append("  ")
                text.append(short_label, style=color)
                text.append(" -> ", style="dim")
                if entry.get("pattern_skipped"):
                    text.append("skipped", style="dim")
                else:
                    text.append(
                        f"{entry.get('patterns_generated', 0)} patterns",
                        style="dim",
                    )
                if entry.get("downgraded_for_budget"):
                    text.append(" (budget)", style="dim")
            if len(names) > max_lines:
                # full count shown in title; max_lines enforces panel height.
                pass
            text.append("\n")
        if len(names) > max_lines:
            text.append(
                f"  …and {len(names) - max_lines} more\n",
                style="dim",
            )
        tiered = [n for n in names if n.get("pattern_tier")]
        if tiered:
            medium_threshold = float(tiered[0].get("pattern_medium_confidence_threshold") or 0.50)
            high_count = sum(1 for n in tiered if n.get("pattern_tier") == "high")
            med_count = sum(1 for n in tiered if n.get("pattern_tier") == "medium")
            low_count = sum(1 for n in tiered if n.get("pattern_tier") == "low")
            high_patterns = sum(
                int(n.get("patterns_generated") or 0)
                for n in tiered
                if n.get("pattern_tier") == "high"
            )
            med_patterns = sum(
                int(n.get("patterns_generated") or 0)
                for n in tiered
                if n.get("pattern_tier") == "medium"
            )
            # P7: keep the in-panel "Pattern generation:" footer
            # using the legacy 3-tier vocabulary — ``high`` /
            # ``medium`` / ``low`` are the *pattern-generation*
            # tier names, NOT the email confidence tiers.  They
            # were always lowercase and never collided with
            # ``HIGH`` / ``MEDIUM`` / ``LOW`` confidence labels.
            text.append(
                f"  Pattern generation: {high_count} high-tier names -> "
                f"{high_patterns} patterns · {med_count} medium-tier names -> "
                f"{med_patterns} patterns · {low_count} low-tier names skipped "
                f"(confidence < {medium_threshold:.2f})\n",
                style="dim",
            )
    return Panel(
        text,
        title=f"[bold]Discovered employee names ({len(names)})[/bold]",
        border_style="magenta",
    )


# Late import to avoid a cycle (email_confidence stays at module scope
# of its own file).
from .email_confidence import label_for_score  # noqa: E402


def _format_emails_block(
    emails: list[HarvestedEmail],
    *,
    max_lines: int = 200,
) -> Text:
    """Render a list of emails as a Rich Text block.

    MUST-FIX S4: each row now shows a compact rationale chip so the
    analyst sees WHY an email landed in HIGH / MEDIUM / LOW — not just
    the label. Example: ``jane.doe@example.com  via 2 source(s)  (smtp+cc)``.
    """
    text = Text()
    if not emails:
        text.append("  (none)", style="dim")
        return text
    for entry in emails[:max_lines]:
        line_style = _LABEL_COLORS.get(entry.confidence_label, "white")
        text.append("  * ", style="dim")
        text.append(entry.email, style=line_style)
        text.append("  ")
        text.append(
            f"via {len(entry.found_by_modules)} source(s)",
            style="dim",
        )
        text.append("  ")
        # MUST-FIX S4: rationale chip — kept short, fits in a table row.
        text.append(_rationale_chip(entry), style="cyan")
        if entry.found_by_modules:
            text.append("  ", style="dim")
            text.append(
                "pivots: " + ", ".join(entry.found_by_modules),
                style="dim",
            )
        if entry.aggregated_source_urls:
            urls = entry.aggregated_source_urls[:2]
            text.append("  ", style="dim")
            text.append("source: " + " | ".join(urls), style="blue")
        aliases = _subaddress_annotations(entry)
        if aliases:
            text.append("  ", style="dim")
            text.append(f"[{'; '.join(aliases)}]", style="magenta")
            text.append("  aliases: " + ", ".join(entry.subaddress_variants[:2]), style="dim")
        if entry.identity_graph_label or entry.identity_graph_score is not None:
            text.append("  ", style="dim")
            text.append(
                f"identity: {entry.identity_graph_label or 'unresolved'} "
                f"({entry.identity_graph_score or 0.0:.2f})",
                style="magenta",
            )
        if entry.is_role:
            text.append("  ")
            text.append("[ROLE]", style="yellow")
        if entry.first_seen_timestamp or entry.last_seen_timestamp:
            text.append("  ")
            first = _format_timestamp(entry.first_seen_timestamp)
            last = _format_timestamp(entry.last_seen_timestamp or entry.first_seen_timestamp)
            if first and first == last:
                text.append(f"seen {first}", style="dim")
            else:
                text.append(f"first: {first or '?'} · last: {last or '?'}", style="dim")
        text.append("\n")
    if len(emails) > max_lines:
        text.append(
            f"  …and {len(emails) - max_lines} more\n",
            style="dim",
        )
    return text


def _is_proxy_fail(status: str, errors: list[str]) -> bool:
    """Return True if status is PARTIAL and any error mentions proxy failure."""
    return status == "partial" and any(
        "proxy" in e.lower() or "ProxyConnectionError" in e for e in errors
    )


def _build_sources_table(result: DomainHarvestResult) -> Table:
    """Per-module status table — the 'Sources run' section."""
    table = Table(title="Sources run", box=None, header_style="bold cyan")
    table.add_column("Module", style="cyan")
    table.add_column("Status", justify="right")
    table.add_column("Emails", justify="right", style="dim")
    table.add_column("Notes", style="dim")

    for name, mod_result in result.module_results.items():
        status = (
            mod_result.status.value
            if hasattr(mod_result.status, "value")
            else str(mod_result.status)
        )
        errors = list(mod_result.errors or [])
        # M2: render PARTIAL proxy failures as distinct PROXY FAIL
        if _is_proxy_fail(status, errors):
            display = "[red]PROXY FAIL[/red]"
        else:
            color = _STATUS_COLORS.get(status.lower(), "white")
            display = f"[{color}]{status.upper()}[/]"
        n_emails = sum(
            1
            for f in (mod_result.findings or [])
            if isinstance(f, dict)
            and (
                (f.get("metadata") or {}).get("email")
                or (f.get("metadata") or {}).get("discovered_email")
            )
        )
        notes = ""
        meta = mod_result.metadata or {}
        if name == "employee_name_discovery":
            notes = f"{meta.get('total_unique_names', 0)} names"
        elif name == "pattern_and_verify":
            verified = meta.get("verified_count", 0)
            notes = f"{verified} verified"
            if meta.get("is_catchall"):
                notes += " · catch-all"
        elif name == "commoncrawl_email":
            notes = f"{meta.get('total_emails_found', 0)} found"
        elif name == "code_and_cert_email":
            notes = f"{meta.get('total_emails_found', 0)} found"
        elif name == "email_search_dork":
            notes = f"{meta.get('total_emails_found', 0)} found"
        elif name in ("npm_email", "pypi_email", "pgp_domain_email"):
            # W5: the three new structured-source modules report the
            # unique-email count under ``total_unique_emails``.
            notes = f"{meta.get('total_unique_emails', 0)} found"

        table.add_row(
            _module_display_name(name),
            display,
            str(n_emails),
            notes,
        )
    return table


def _build_suggested_next_steps(
    result: DomainHarvestResult,
    *,
    show_low: bool = False,
    show_unverified_patterns: bool = False,
    show_role: bool = False,
    suppressed_low_count: int = 0,
    unverified_permutation_count: int = 0,
    role_count: int = 0,
) -> list[str]:
    """Conditional hints based on what happened during the harvest.

    Phase 1 of 4: extended to surface the new display-filter flags so
    the analyst knows what was hidden by default and which flag
    re-reveals each category.
    """
    hints: list[str] = []
    if result.total_unique_emails == 0:
        hints.append(
            "No emails discovered.  Check: (1) domain spelling, "
            "(2) does the org actually publish email addresses online, "
            "(3) try a different domain (e.g. parent company)."
        )
        return hints

    # Phase 1: hint about suppressed unverified permutations when SMTP
    # was not used.  This is the highest-leverage hint — re-running with
    # Default-on SMTP is the most common path from "lots of LOW junk" to
    # "a handful of SMTP-confirmed candidates".
    if unverified_permutation_count > 0 and not result.smtp_verification_used:
        hints.append(
            f"-> {unverified_permutation_count} pattern candidates "
            "generated from discovered names. Rerun without --no-verify "
            "to confirm which addresses actually exist."
        )

    if role_count > 0 and not show_role:
        hints.append(f"-> {role_count} role accounts hidden — use --show-role to reveal.")

    # Legacy hints preserved verbatim.
    if result.employee_names_processed > 0 and not result.smtp_verification_used:
        hints.append(
            f"{result.employee_names_processed} employee name(s) discovered — "
            "run without --no-verify to expand into SMTP-verified "
            "pattern candidates."
        )

    if result.catchall_detected is True:
        hints.append(
            "Catch-all MX detected — SMTP verification provides limited "
            "additional confidence for this domain."
        )

    if result.total_unique_emails > 0 and result.high_confidence_count == 0:
        hints.append(
            "No CONFIRMED-tier hits. Consider rerunning without --no-verify, "
            "checking related domains, or pivoting through discovered names."
        )

    # Phase 1: always-present "reveal everything" hint — the user can
    # opt into the legacy "show everything" surface with a single flag.
    hints.append("-> --full reveals everything.")

    if not hints:
        hints.append(
            "All set — review CONFIRMED-tier candidates above and "
            "pivot on confirmed names if you need broader coverage."
        )
    return hints


def format_harvest_cli_output(
    result: DomainHarvestResult,
    *,
    show_low: bool = False,
    hide_low: bool = False,
    show_unverified_patterns: bool = False,
    show_role: bool = False,
    full: bool = False,
    with_subdomains: bool = False,
    show_personal: bool = False,
) -> str:
    """Build the Rich-formatted CLI output.

    Returns a plain ``str`` — callers should pass it to a Rich
    ``Console.print()`` so glyphs render correctly.

    Phase 1 of 4 — display-filter surface:

    * ``show_low`` (default False) — LOW-confidence emails are hidden.
      When False and there are LOW personal emails, a suppressed-
      count line is rendered below the panels.
    * ``show_unverified_patterns`` (default False) — pattern
      candidates generated by ``pattern_and_verify`` but never
      SMTP-verified are hidden (independent of ``show_low``).  When
      False and there are any, a dedicated suppressed-count line is
      rendered with the default SMTP-verification hint.
    * ``show_role`` (default False) — role accounts render as a
      collapsed name-only list.  When True they expand with full
      metadata same as personal emails.
    * ``full`` (default False) — convenience alias that sets all
      three flags to True.  Restores the pre-Phase-1 surface exactly.

    Role accounts (``is_role=True``) are excluded from the HIGH /
    MEDIUM / LOW tier panels regardless of confidence label — they
    live in their own section so the analyst's tier counts reflect
    personal emails only.
    """
    # ``full`` is the convenience restore-legacy alias.
    if full:
        show_low = True
        hide_low = False
        show_unverified_patterns = True
        show_role = True

    # Record the rich render without writing the intermediate Rule to the
    # real terminal. The caller prints the exported text once, which keeps
    # the visible header but avoids the duplicate console render.
    header_console = Console(record=True, width=120, file=io.StringIO())
    header_console.print(
        Rule(
            title=f"[bold]DOMAIN EMAIL HARVEST — {result.domain}[/bold]",
            style="cyan",
        )
    )
    header = header_console.export_text()

    console = Console(record=True, width=120, file=io.StringIO())

    # Per-source status table (unchanged).
    console.print(_build_sources_table(result))
    infrastructure = _build_infrastructure(result)
    console.print(_format_infrastructure_panel(infrastructure))

    # ------------------------------------------------------------------
    # Phase 1: split personal vs role emails, and unverified permutations
    # out of the personal LOW bucket.  All three bucketings are derived
    # from ``result.unique_emails`` directly — the report layer is
    # self-contained and does not depend on the orchestrator's count
    # fields, which means downstream tests can construct mock results
    # with arbitrary count fields and the display stays correct.
    # ------------------------------------------------------------------
    export_emails = _sanitised_export_emails(result.unique_emails)
    persona_candidates = [
        entry
        for entry in export_emails
        if any(
            isinstance(ev, dict)
            and isinstance(ev.get("metadata"), dict)
            and (ev.get("metadata") or {}).get("source_type") == "persona_pivot_personal"
            for ev in entry.evidence or []
        )
    ]
    persona_addresses = {entry.email for entry in persona_candidates}
    personal_emails = [
        e for e in export_emails if not e.is_role and e.email not in persona_addresses
    ]
    role_emails = [e for e in export_emails if e.is_role]

    unverified_perms = [e for e in personal_emails if _is_unverified_permutation(e)]
    non_perm_personal = [e for e in personal_emails if not _is_unverified_permutation(e)]

    # P7: 4-tier personal bucket split.  CONFIRMED and LIKELY
    # are the new "actionable" tiers (analyst should pivot
    # on these).  MEDIUM is the soft "weak corroboration"
    # tier (visible by default, single-source CC, dork
    # snippet, etc.).  LOW stays hidden by default.
    confirmed = [e for e in non_perm_personal if e.confidence_label == "CONFIRMED"]
    likely = [e for e in non_perm_personal if e.confidence_label == "LIKELY"]
    medium = [e for e in non_perm_personal if e.confidence_label == "MEDIUM"]
    low = [e for e in non_perm_personal if e.confidence_label == "LOW"]
    # Backward-compat alias for the rest of the function —
    # ``high`` was the 3-tier HIGH bucket, now it means
    # "anything in the actionable tiers (CONFIRMED + LIKELY)".
    high = confirmed + likely
    # ------------------------------------------------------------------
    # Phase 1: new summary bar.  Replaces the legacy "Total: N candidates"
    # with an "Actionable: ..." line that names each visible bucket and
    # the suppressed count.
    # ------------------------------------------------------------------
    summary_parts: list[str] = [
        f"[bold green]{len(confirmed)} CONFIRMED[/bold green]",
        f"[bold bright_green]{len(likely)} LIKELY[/bold bright_green]",
        f"[bold yellow]{len(medium)} MEDIUM[/bold yellow] personal emails",
    ]
    if role_emails:
        summary_parts.append(f"{len(role_emails)} role accounts")
    console.print("\n[bold]Actionable:[/bold] " + " · ".join(summary_parts))
    if low or unverified_perms:
        console.print(
            f"[bold]Suppressed:[/bold] {len(low)} LOW emails · "
            f"{len(unverified_perms)} unverified patterns"
        )
        console.print("  → Use --show-low to review LOW emails")
        console.print("  → Use --show-unverified-patterns to review patterns")
        console.print("  → Use --full to show everything")
    validation_summary = (result.metadata or {}).get("low_email_validation")
    if isinstance(validation_summary, dict):
        promotion = validation_summary.get("promotion") or {}
        method = validation_summary.get("method") or "unknown"
        provider = validation_summary.get("provider")
        if validation_summary.get("status") == "disabled":
            console.print("[dim]Low-email validation: disabled.[/dim]")
        elif validation_summary.get("status") == "provider_verification_unavailable":
            console.print(
                f"[dim]Low-email validation skipped: {provider or method} has no "
                "provider-specific verification path.[/dim]"
            )
        elif validation_summary.get("status") not in {
            "no_candidates",
            "skipped_injected_modules",
        }:
            checked = int(validation_summary.get("checked") or 0)
            confirmed_promoted = int(promotion.get("promoted") or 0)
            eliminated = int(promotion.get("not_found") or 0)
            inconclusive = int(promotion.get("inconclusive") or 0)
            route = f"{provider}/{method}" if provider else str(method)
            console.print(
                f"[dim]Low-email validation: validated {checked} LOW emails; "
                f"{confirmed_promoted} confirmed, {eliminated} eliminated, "
                f"{inconclusive} inconclusive ({route}).[/dim]"
            )
    console.print("[dim]Run with --full to show everything.[/dim]\n")

    # ------------------------------------------------------------------
    # P7: CONFIRMED / LIKELY / MEDIUM panels.  LOW panel is
    # hidden by default and surfaced by ``--show-low``.  We
    # render CONFIRMED and LIKELY in a single green panel to
    # keep the CLI output compact — both are "actionable" in
    # the spec — and split them inside the panel for analyst
    # clarity.
    # ------------------------------------------------------------------
    actionable_block = _format_emails_block(confirmed + likely)
    console.print(
        Panel(
            actionable_block,
            title=(
                f"[bold green]CONFIRMED + LIKELY ({len(confirmed)} + {len(likely)})[/bold green]"
            ),
            border_style="green",
        )
    )
    console.print(
        Panel(
            _format_emails_block(medium),
            title=f"[bold yellow]MEDIUM CONFIDENCE ({len(medium)})[/bold yellow]",
            border_style="yellow",
        )
    )

    # LOW content is opt-in. Counts and review commands are always shown
    # above, even when the analyst keeps the content hidden.
    if show_low and not hide_low:
        console.print(
            Panel(
                _format_emails_block(low),
                title=(f"[dim]LOW CONFIDENCE ({len(low)})[/dim]"),
                border_style="dim",
            )
        )

    # Unverified permutations are independently opt-in.
    if show_unverified_patterns:
        console.print(
            Panel(
                _format_emails_block(unverified_perms),
                title="[bold yellow]PATTERN CANDIDATES (unverified)[/bold yellow]",
                border_style="yellow",
                subtitle=(
                    "Generated from discovered names; run with "
                    "default SMTP verification normally confirms these."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Role accounts section.  Phase 1: collapsed by default — a comma-
    # separated name-only list with a hint at the bottom.  When
    # ``show_role`` is True, expand to full metadata same as personal
    # emails (via ``_format_emails_block`` which already tags rows with
    # ``[ROLE]``).
    # ------------------------------------------------------------------
    if role_emails:
        role_text = Text()
        if show_role:
            # Expanded: full per-email rendering identical to personal.
            for entry in role_emails:
                # Inline copy of _format_emails_block rendering so we
                # can capture the [ROLE] tag in this section without
                # inheriting the "via N source(s)" / rationale chip
                # layout that personal emails get.  Keep it focused on
                # the metadata the analyst needs when expanding roles.
                line_style = _LABEL_COLORS.get(entry.confidence_label, "white")
                role_text.append("  * ", style="dim")
                role_text.append(entry.email, style=line_style)
                role_text.append("  ")
                role_text.append(
                    f"({entry.confidence_label})",
                    style="dim",
                )
                role_text.append("  ")
                role_text.append("[ROLE]", style="yellow")
                role_text.append("\n")
            console.print(
                Panel(
                    role_text,
                    title=(f"[bold yellow]ROLE ACCOUNTS ({len(role_emails)})[/bold yellow]"),
                    border_style="yellow",
                )
            )
        else:
            # Collapsed: comma-separated list with hint.
            emails_csv = ", ".join(e.email for e in role_emails)
            role_text.append(f"  {emails_csv}\n")
            role_text.append(
                "  Run with --show-role for full list.\n",
                style="dim",
            )
            console.print(
                Panel(
                    role_text,
                    title=(f"[bold yellow]ROLE ACCOUNTS ({len(role_emails)})[/bold yellow]"),
                    border_style="yellow",
                )
            )

    # MUST-FIX S13: Discovered employee names — these are the names
    # pattern_and_verify already used to generate permutations. Showing
    # them lets the analyst see "why" a candidate email pattern was
    # tried, and pivot directly on a name when no email matched. The
    # panel is positioned between Role accounts and Suggested next
    # steps, per the audit spec.
    discovered = _extract_discovered_names(result)
    console.print(_format_discovered_names_panel(discovered))
    console.print(
        _format_people_panel(
            _build_people(
                result,
                include_low=show_low and not hide_low,
                include_patterns=show_unverified_patterns,
            )
        )
    )
    if with_subdomains:
        console.print(_format_subdomain_panel(result))

    if persona_candidates:
        personal_text = Text()
        personal_text.append(
            f"  These addresses may belong to employees discovered on {result.domain}\n"
            f"  but are not @{result.domain} addresses. Treat as unverified leads.\n\n",
            style="dim",
        )
        if show_personal:
            for entry in persona_candidates:
                source_name = "Unknown"
                for evidence in entry.evidence or []:
                    metadata = evidence.get("metadata") if isinstance(evidence, dict) else None
                    if isinstance(metadata, dict) and metadata.get("source_name"):
                        source_name = str(metadata["source_name"])
                        break
                personal_text.append(
                    f"  {source_name:<22} → {entry.email:<32} [persona_pivot · unverified]\n"
                )
        else:
            personal_text.append(
                f"  Run with --show-personal to reveal all {len(persona_candidates)} candidates.\n",
                style="dim",
            )
        console.print(
            Panel(
                personal_text,
                title="[bold magenta]PERSONAL EMAIL CANDIDATES[/bold magenta]",
                border_style="magenta",
            )
        )

    # Suggested next steps — now display-aware.
    hints = _build_suggested_next_steps(
        result,
        show_low=show_low,
        show_unverified_patterns=show_unverified_patterns,
        show_role=show_role,
        suppressed_low_count=len(low),
        unverified_permutation_count=len(unverified_perms),
        role_count=len(role_emails),
    )
    hint_text = Text()
    for hint in hints:
        hint_text.append("  • ", style="cyan")
        hint_text.append(hint + "\n")
    console.print(
        Panel(
            hint_text,
            title="[bold cyan]Suggested next steps[/bold cyan]",
            border_style="cyan",
        )
    )

    if result.errors:
        err_text = Text()
        for err in result.errors[:20]:
            err_text.append("  ⚠ ", style="yellow")
            err_text.append(err + "\n", style="dim")
        if len(result.errors) > 20:
            err_text.append(
                f"  …and {len(result.errors) - 20} more\n",
                style="dim",
            )
        console.print(
            Panel(
                err_text,
                title="[bold yellow]Non-fatal errors[/bold yellow]",
                border_style="yellow",
            )
        )

    return header + console.export_text()


def format_harvest_json_export(result: DomainHarvestResult) -> dict[str, Any]:
    """Build the full machine-readable JSON export.

    This is the format for downstream tooling — every evidence
    entry from every module is preserved.

    MUST-FIX M4: ``found_by_modules`` is already deduplicated by the
    aggregator; we keep ``sorted()`` as a defensive belt. The new
    fields ``total_finding_count``, ``occurrence_count_per_module``,
    and ``aggregated_source_urls`` carry the "seen N times" signal
    without bloating the ``evidence`` list.
    """
    emails_out: list[dict[str, Any]] = []
    export_emails = _sanitised_export_emails(result.unique_emails)
    for entry in export_emails:
        # MUST-FIX S4: every email in the JSON export MUST carry a
        # non-null confidence_breakdown — downstream tooling relies on
        # the field being present and structured. If the aggregator
        # didn't populate one (e.g. caller constructed the
        # HarvestedEmail directly), look for a module-provided one in
        # the evidence list before falling back to a synthesised stub.
        if entry.confidence_breakdown is None:
            module_breakdown: dict[str, Any] | None = None
            for ev in entry.evidence or []:
                if not isinstance(ev, dict):
                    continue
                md = ev.get("metadata") or {}
                if not isinstance(md, dict):
                    continue
                cb = md.get("confidence_breakdown")
                if isinstance(cb, dict):
                    module_breakdown = cb
                    break
            if module_breakdown is not None:
                entry.confidence_breakdown = module_breakdown
            else:
                entry.confidence_breakdown = {
                    "source_types": sorted({m for m in entry.found_by_modules if m}),
                    "multiplier_label": (
                        "smtp_verified"
                        if entry.is_smtp_verified
                        else (
                            "pgp_or_ca"
                            if entry.is_pgp_or_ca
                            else ("multi_source" if entry.source_count >= 2 else "single_source")
                        )
                    ),
                    "synthesised": True,
                }
        emails_out.append(
            {
                "email": entry.email,
                "on_domain": entry.on_domain,
                "is_role": entry.is_role,
                "pattern_only": _is_unverified_permutation(entry),
                "role_match_type": entry.role_match_type,
                "confidence_score": entry.confidence_score,
                "confidence_label": entry.confidence_label,
                "identity_graph_score": entry.identity_graph_score,
                "identity_graph_label": entry.identity_graph_label,
                "identity_graph_flags": entry.identity_graph_flags,
                "found_by_modules": entry.found_by_modules,
                "source_count": entry.source_count,
                "first_seen_timestamp": entry.first_seen_timestamp,
                "last_seen_timestamp": entry.last_seen_timestamp,
                "is_smtp_verified": entry.is_smtp_verified,
                "is_provider_verified": entry.is_provider_verified,
                **_email_validation_summary(entry),
                "is_ca_attested": entry.is_ca_attested,
                "evidence": entry.evidence,
                "total_finding_count": entry.total_finding_count,
                "occurrence_count_per_module": dict(entry.occurrence_count_per_module),
                "aggregated_source_urls": entry.aggregated_source_urls,
                "subaddress_variants": entry.subaddress_variants,
                "subaddress_annotations": _subaddress_annotations(entry),
                # MUST-FIX S4: full per-email confidence breakdown.
                # Either the module-provided breakdown (rich — captures
                # freshness + multiplier math + source_types) or a
                # synthesised minimal one. Downstream tooling can build
                # its own per-email explanations from this.
                "confidence_breakdown": entry.confidence_breakdown,
                # MUST-FIX S4: compact rationale chip rendered in CLI.
                "rationale_chip": _rationale_chip(entry),
            }
        )

    # Strip non-JSON-serialisable fields from each module's metadata —
    # we just need raw dicts, no Enum / dataclass leakage.
    module_metadata: dict[str, Any] = {}
    for name, mod_result in result.module_results.items():
        meta = mod_result.metadata or {}
        if not isinstance(meta, dict):
            meta = {"_raw": str(meta)}
        # Cast status to its string value
        status_value = (
            mod_result.status.value
            if hasattr(mod_result.status, "value")
            else str(mod_result.status)
        )
        module_metadata[name] = {
            "status": status_value,
            "findings_count": len(mod_result.findings or []),
            "errors": list(mod_result.errors or []),
            "metadata": meta,
        }

    summary_counts = _export_summary_counts(export_emails)
    suppressed_low = [
        entry
        for entry in export_emails
        if not entry.is_role
        and entry.confidence_label == "LOW"
        and not _is_unverified_permutation(entry)
    ]
    suppressed_patterns = [entry for entry in export_emails if _is_unverified_permutation(entry)]
    suppressed_count = len(suppressed_low) + len(suppressed_patterns)
    people = _build_people(result)
    quality_metrics = build_metrics(result, emails_out)
    shadow_profiles = _build_shadow_profiles(result)
    subdomains = _build_subdomains(result)
    infrastructure = _build_infrastructure(result)
    module_timings = {
        name: float((mod.metadata or {}).get("duration_seconds"))
        for name, mod in result.module_results.items()
        if isinstance((mod.metadata or {}).get("duration_seconds"), (int, float))
    }
    module_skip_reasons = {
        name: str((mod.metadata or {}).get("skip_reason"))
        for name, mod in result.module_results.items()
        if (mod.metadata or {}).get("skip_reason")
    }
    return {
        "domain": result.domain,
        "harvested_at": result.completed_at,
        "duration_seconds": result.duration_seconds,
        "summary": {
            **summary_counts,
            "smtp_verification_used": result.smtp_verification_used,
            "catchall_detected": result.catchall_detected,
            "native_email_validation": (result.metadata or {}).get("native_email_validation", {}),
            "smtp_email_verification": (result.metadata or {}).get("smtp_email_verification", {}),
            "m365_email_verification": (result.metadata or {}).get("m365_email_verification", {}),
            "yahoo_email_verification": (result.metadata or {}).get("yahoo_email_verification", {}),
            "low_email_validation": (result.metadata or {}).get("low_email_validation", {}),
            "confirmed_pattern": result.confirmed_pattern,
            "employee_names_processed": result.employee_names_processed,
            "people_count": len(people),
            "people_with_emails": sum(1 for person in people if person.get("emails")),
            # Phase 1 of 4: signal to downstream tooling that the CLI
            # hid a class of emails by default.  The JSON/CSV/NDJSON
            # exports always carry the FULL email list (hiding is a
            # CLI display decision only); ``display_filter`` is
            # documentation, NOT a filter applied to ``emails``.
            # Values:
            #     "all"               — no filter applied (legacy)
            #     "medium_and_above"  — LOW + unverified patterns hidden
            "display_filter": "medium_and_above",
            "suppressed_count": suppressed_count,
            "suppressed_low_count": len(suppressed_low),
            "suppressed_pattern_count": len(suppressed_patterns),
            "p0_p1_metrics": quality_metrics,
            "shadow_profile_count": len(shadow_profiles),
            "module_timings": module_timings,
            "module_skip_reasons": module_skip_reasons,
        },
        "emails": emails_out,
        "personal_email_candidates": [
            item
            for item in emails_out
            if any(
                isinstance(ev, dict)
                and isinstance(ev.get("metadata"), dict)
                and (ev.get("metadata") or {}).get("source_type") == "persona_pivot_personal"
                for ev in item.get("evidence", [])
            )
        ]
        + [
            item
            for item in shadow_profiles
            if item.get("type") == "personal_email_candidate"
        ],
        "module_metadata": module_metadata,
        "errors": list(result.errors),
        # MUST-FIX S13: full discovered names list (NOT just a count) —
        # analysts and downstream tooling can pivot directly on a name
        # when no email attestation matched.
        "discovered_names": _extract_discovered_names(result),
        "people": people,
        "shadow_profiles": shadow_profiles,
        "subdomains": subdomains,
        "infrastructure": infrastructure,
        # MUST-FIX S12: schema version for forward-compatibility. Bump this
        # when the export structure changes in a backward-incompatible
        # way (renaming a top-level key, removing a field, changing a
        # type). Downstream tooling should ``assert schema_version <= X``
        # before consuming.
        "schema_version": 1,
    }


# --------------------------------------------------------------------------
# MUST-FIX S11: CSV and NDJSON exporters.
# --------------------------------------------------------------------------

# Stable CSV column order. Each row matches the columns an analyst pivots
# on most often (email, score, who found it, when). JSON-only fields are
# omitted to keep CSV readable in spreadsheets.
_CSV_COLUMNS = [
    "email",
    "confidence_label",
    "confidence_score",
    "is_role",
    "on_domain",
    "is_smtp_verified",
    "is_provider_verified",
    "native_validation_status",
    "native_mx_valid",
    "smtp_verification_status",
    "smtp_exists",
    "smtp_mx_host",
    "smtp_transport_error",
    "smtp_catchall",
    "provider_verification_status",
    "provider_verification_provider",
    "m365_if_exists_result",
    "is_ca_attested",
    "found_by_modules",
    "source_count",
    "first_seen_timestamp",
    "last_seen_timestamp",
    "subaddress_variants",
    "rationale_chip",
]


def format_harvest_csv_export(result: DomainHarvestResult) -> str:
    """Render *result* as a CSV string.

    MUST-FIX S11: flat, spreadsheet-friendly export. ``found_by_modules``
    and ``subaddress_variants`` are comma-joined for direct paste into
    GSheets / Excel. ``None`` becomes empty string.
    """
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for entry in _sanitised_export_emails(result.unique_emails):
        validation = _email_validation_summary(entry)
        row: dict[str, Any] = {
            "email": entry.email,
            "confidence_label": entry.confidence_label,
            "confidence_score": entry.confidence_score,
            "is_role": entry.is_role,
            "on_domain": entry.on_domain,
            "is_smtp_verified": entry.is_smtp_verified,
            "is_provider_verified": entry.is_provider_verified,
            **validation,
            "is_ca_attested": entry.is_ca_attested,
            "found_by_modules": ",".join(entry.found_by_modules or []),
            "source_count": entry.source_count,
            "first_seen_timestamp": entry.first_seen_timestamp or "",
            "last_seen_timestamp": entry.last_seen_timestamp or "",
            "subaddress_variants": ",".join(entry.subaddress_variants or []),
            "rationale_chip": _rationale_chip(entry),
        }
        writer.writerow(row)
    return buf.getvalue()


def format_harvest_ndjson_export(result: DomainHarvestResult) -> str:
    """Render *result* as newline-delimited JSON.

    MUST-FIX S11: one JSON object per line, each a single email. Same
    per-email structure as the JSON export's ``emails`` array entries
    (minus the list wrapper). Includes a synthetic ``domain`` field on
    each line so callers don't lose context when streaming the file
    through ``jq -c`` line by line.
    """
    out_lines: list[str] = []
    for entry in _sanitised_export_emails(result.unique_emails):
        validation = _email_validation_summary(entry)
        # MUST-FIX S4: ensure breakdown is non-null for the stream.
        if entry.confidence_breakdown is None:
            entry.confidence_breakdown = {
                "source_types": sorted({m for m in entry.found_by_modules if m}),
                "multiplier_label": (
                    "smtp_verified"
                    if entry.is_smtp_verified
                    else (
                        "pgp_or_ca"
                        if entry.is_pgp_or_ca
                        else ("multi_source" if entry.source_count >= 2 else "single_source")
                    )
                ),
                "synthesised": True,
            }
        payload = {
            "domain": result.domain,
            "email": entry.email,
            "on_domain": entry.on_domain,
            "is_role": entry.is_role,
            "role_match_type": entry.role_match_type,
            "confidence_score": entry.confidence_score,
            "confidence_label": entry.confidence_label,
            "found_by_modules": entry.found_by_modules,
            "source_count": entry.source_count,
            "first_seen_timestamp": entry.first_seen_timestamp,
            "last_seen_timestamp": entry.last_seen_timestamp,
            "is_smtp_verified": entry.is_smtp_verified,
            "is_provider_verified": entry.is_provider_verified,
            **validation,
            "is_ca_attested": entry.is_ca_attested,
            "total_finding_count": entry.total_finding_count,
            "occurrence_count_per_module": dict(entry.occurrence_count_per_module),
            "aggregated_source_urls": entry.aggregated_source_urls,
            "subaddress_variants": entry.subaddress_variants,
            "confidence_breakdown": entry.confidence_breakdown,
            "rationale_chip": _rationale_chip(entry),
            # MUST-FIX S12: schema version applies to NDJSON rows too.
            "schema_version": 1,
        }
        out_lines.append(json.dumps(payload, default=str))
    if not out_lines:
        # Empty harvest still produces a valid (empty) NDJSON file.
        return ""
    return "\n".join(out_lines) + "\n"


# MUST-FIX S11: format dispatcher — picks the right serialiser from the
# export filename extension. Returns (text, error). ``error`` is None on
# success; non-None describes the unknown-extension condition.
def serialise_harvest_for_export(
    result: DomainHarvestResult,
    export_path: str | Path,
    *,
    comparison: dict[str, Any] | None = None,
) -> tuple[str, str | None]:
    """Pick CSV / NDJSON / JSON based on filename extension.

    MUST-FIX S11: this is the single decision point the CLI uses. If the
    extension is unknown (anything other than ``.json`` / ``.csv`` /
    ``.ndjson``), return ``error="unknown extension"`` so the CLI can
    surface a clear message rather than silently defaulting to JSON.
    """
    p = str(export_path).lower()
    if p.endswith(".csv"):
        return format_harvest_csv_export(result), None
    if p.endswith(".ndjson"):
        return format_harvest_ndjson_export(result), None
    if p.endswith(".json"):
        # MUST-FIX S12: include ``schema_version``.
        payload = format_harvest_json_export(result)
        if comparison is not None:
            payload["comparison"] = comparison
        return (
            json.dumps(payload, indent=2, default=str),
            None,
        )
    return (
        "",
        f"unknown export extension for {export_path!r}; supported: .json, .csv, .ndjson",
    )
