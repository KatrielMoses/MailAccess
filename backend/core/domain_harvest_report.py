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
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from .domain_harvest_orchestrator import DomainHarvestResult, HarvestedEmail

# --------------------------------------------------------------------------
# Color palette — mirrors cli/main.py's get_status_color /
# get_risk_color so the harvest command blends with the rest of the
# CLI's aesthetic.
# --------------------------------------------------------------------------
_LABEL_COLORS = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "dim"}

_STATUS_COLORS = {
    "success": "green",
    "complete": "green",
    "failed": "red",
    "pending": "cyan",
    "running": "cyan",
    "partial": "yellow",
    "skipped": "dim",
}


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
        breakdown.get("source_types")
        or sorted({m for m in entry.found_by_modules if m})
    )
    # Map source_types to compact display labels.
    compact_map = {
        "common_crawl_single": "cc",
        "common_crawl_high_density": "cc*",
        "ca_attested": "ca",
        "smtp_verified": "smtp",
        "permutation_verified": "smtp",
        "permutation_catchall": "catchall",
        "permutation_unverified": "perm",
        "github_commit_author": "gh",
        "github_code_match": "gh-code",
        "press_release": "press",
        "search_snippet": "search",
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
    multiplier_label = breakdown.get("multiplier_label") or ""
    # Tighten "smtp_verified" → "smtp", collapse synonyms
    if "smtp" in chips and multiplier_label in ("smtp_verified", "ca_attested"):
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


def _extract_discovered_names(result: DomainHarvestResult) -> list[dict[str, Any]]:
    """Pull discovered employee names from the ``employee_name_discovery``
    module's findings.

    MUST-FIX S13: the orchestrator already aggregates these names into
    pattern_and_verify's input, but the analyst never sees them in the
    CLI output. Each ``EmployeeNameResult`` carries the ``name``,
    ``sources`` (which sub-sources attested it), and ``confidence``.
    """
    module_result = (result.module_results or {}).get(
        "employee_name_discovery"
    )
    if module_result is None:
        return []
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
        out.append(
            {
                "name": str(name),
                "sources": list(meta.get("sources") or []),
                "source_count": int(meta.get("source_count") or 0),
                "title_or_role": meta.get("title_or_role"),
                "confidence_score": float(
                    meta.get("confidence_score") or 0.0
                ),
                "source_urls": list(meta.get("source_urls") or []),
            }
        )
    # Highest-confidence first, multi-source wins ties.
    out.sort(
        key=lambda r: (
            -r["confidence_score"],
            -r["source_count"],
            r["name"].lower(),
        )
    )
    return out


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
            label = label_for_score(entry["confidence_score"])
            color = _LABEL_COLORS.get(label, "white")
            text.append("  * ", style="dim")
            text.append(entry["name"], style=color)
            if entry.get("title_or_role"):
                text.append(f"  ({entry['title_or_role']})", style="dim")
            text.append(
                f"  via {','.join(entry['sources'])}",
                style="cyan",
            )
            if len(names) > max_lines:
                # full count shown in title; max_lines enforces panel height.
                pass
            text.append("\n")
        if len(names) > max_lines:
            text.append(
                f"  …and {len(names) - max_lines} more\n",
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
        if entry.is_role:
            text.append("  ")
            text.append("[ROLE]", style="yellow")
        if entry.first_seen_timestamp:
            text.append("  ")
            text.append(f"first seen {entry.first_seen_timestamp[:10]}", style="dim")
        text.append("\n")
    if len(emails) > max_lines:
        text.append(
            f"  …and {len(emails) - max_lines} more\n",
            style="dim",
        )
    return text


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
        color = _STATUS_COLORS.get(status.lower(), "white")
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
            f"[{color}]{status.upper()}[/]",
            str(n_emails),
            notes,
        )
    return table


def _build_suggested_next_steps(result: DomainHarvestResult) -> list[str]:
    """Conditional hints based on what happened during the harvest."""
    hints: list[str] = []
    if result.total_unique_emails == 0:
        hints.append(
            "No emails discovered.  Check: (1) domain spelling, "
            "(2) does the org actually publish email addresses online, "
            "(3) try a different domain (e.g. parent company)."
        )
        return hints

    if (
        result.employee_names_processed > 0
        and not result.smtp_verification_used
    ):
        hints.append(
            f"{result.employee_names_processed} employee name(s) discovered — "
            "run with --verify-smtp to expand into SMTP-verified "
            "pattern candidates (opt-in, see docs)."
        )

    if result.catchall_detected is True:
        hints.append(
            "Catch-all MX detected — SMTP verification provides limited "
            "additional confidence for this domain."
        )

    if result.total_unique_emails > 0 and result.high_confidence_count == 0:
        hints.append(
            "No HIGH-confidence hits.  Consider: enabling --verify-smtp, "
            "checking related domains, or pivoting through discovered names."
        )

    if not hints:
        hints.append(
            "All set — review HIGH-confidence candidates above and "
            "pivot on confirmed names if you need broader coverage."
        )
    return hints


def format_harvest_cli_output(result: DomainHarvestResult) -> str:
    """Build the Rich-formatted CLI output.

    Returns a plain ``str`` — callers should pass it to a Rich
    ``Console.print()`` so glyphs render correctly.
    """
    console = Console(record=True, width=120)
    console.print(
        Rule(
            title=f"[bold]DOMAIN EMAIL HARVEST — {result.domain}[/bold]",
            style="cyan",
        )
    )

    # Per-source status table
    console.print(_build_sources_table(result))

    verified_count = sum(1 for e in result.unique_emails if e.is_smtp_verified)
    console.print(
        f"\n[bold]Total:[/bold] {result.total_unique_emails} candidate emails, "
        f"{verified_count} verified "
        f"[dim](took {result.duration_seconds:.1f}s)[/dim]\n"
    )

    # HIGH / MEDIUM / LOW sections
    high = [e for e in result.unique_emails if e.confidence_label == "HIGH"]
    medium = [e for e in result.unique_emails if e.confidence_label == "MEDIUM"]
    low = [e for e in result.unique_emails if e.confidence_label == "LOW"]

    console.print(
        Panel(
            _format_emails_block(high),
            title=f"[bold green]HIGH CONFIDENCE ({len(high)})[/bold green]",
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
    console.print(
        Panel(
            _format_emails_block(low),
            title=f"[dim]LOW CONFIDENCE ({len(low)})[/dim]",
            border_style="dim",
        )
    )

    # Role accounts section
    role_accts = [e for e in result.unique_emails if e.is_role]
    role_text = Text()
    if role_accts:
        for entry in role_accts:
            role_text.append(f"  * {entry.email}", style="yellow")
            role_text.append(
                f"  ({entry.confidence_label})\n",
                style="dim",
            )
    else:
        role_text.append("  (none)", style="dim")
    console.print(
        Panel(
            role_text,
            title=f"[bold yellow]Role accounts ({len(role_accts)})[/bold yellow]",
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

    # Suggested next steps
    hints = _build_suggested_next_steps(result)
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

    return console.export_text()


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
    for entry in result.unique_emails:
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
                    "source_types": sorted(
                        {m for m in entry.found_by_modules if m}
                    ),
                    "multiplier_label": (
                        "smtp_verified"
                        if entry.is_smtp_verified
                        else (
                            "ca_attested"
                            if entry.is_ca_attested
                            else (
                                "multi_source"
                                if entry.source_count >= 2
                                else "single_source"
                            )
                        )
                    ),
                    "synthesised": True,
                }
        emails_out.append(
            {
                "email": entry.email,
                "on_domain": entry.on_domain,
                "is_role": entry.is_role,
                "role_match_type": entry.role_match_type,
                "confidence_score": entry.confidence_score,
                "confidence_label": entry.confidence_label,
                "found_by_modules": entry.found_by_modules,
                "source_count": entry.source_count,
                "first_seen_timestamp": entry.first_seen_timestamp,
                "is_smtp_verified": entry.is_smtp_verified,
                "is_ca_attested": entry.is_ca_attested,
                "evidence": entry.evidence,
                "total_finding_count": entry.total_finding_count,
                "occurrence_count_per_module": dict(
                    entry.occurrence_count_per_module
                ),
                "aggregated_source_urls": entry.aggregated_source_urls,
                "subaddress_variants": entry.subaddress_variants,
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

    return {
        "domain": result.domain,
        "harvested_at": result.completed_at,
        "duration_seconds": result.duration_seconds,
        "summary": {
            "total_unique_emails": result.total_unique_emails,
            "high_confidence": result.high_confidence_count,
            "medium_confidence": result.medium_confidence_count,
            "low_confidence": result.low_confidence_count,
            "role_accounts": result.role_account_count,
            "personal_emails": result.personal_email_count,
            "smtp_verification_used": result.smtp_verification_used,
            "catchall_detected": result.catchall_detected,
            "confirmed_pattern": result.confirmed_pattern,
            "employee_names_processed": result.employee_names_processed,
        },
        "emails": emails_out,
        "module_metadata": module_metadata,
        "errors": list(result.errors),
        # MUST-FIX S13: full discovered names list (NOT just a count) —
        # analysts and downstream tooling can pivot directly on a name
        # when no email attestation matched.
        "discovered_names": _extract_discovered_names(result),
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
    "is_ca_attested",
    "found_by_modules",
    "source_count",
    "first_seen_timestamp",
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
    for entry in result.unique_emails:
        row: dict[str, Any] = {
            "email": entry.email,
            "confidence_label": entry.confidence_label,
            "confidence_score": entry.confidence_score,
            "is_role": entry.is_role,
            "on_domain": entry.on_domain,
            "is_smtp_verified": entry.is_smtp_verified,
            "is_ca_attested": entry.is_ca_attested,
            "found_by_modules": ",".join(entry.found_by_modules or []),
            "source_count": entry.source_count,
            "first_seen_timestamp": entry.first_seen_timestamp or "",
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
    for entry in result.unique_emails:
        # MUST-FIX S4: ensure breakdown is non-null for the stream.
        if entry.confidence_breakdown is None:
            entry.confidence_breakdown = {
                "source_types": sorted(
                    {m for m in entry.found_by_modules if m}
                ),
                "multiplier_label": (
                    "smtp_verified"
                    if entry.is_smtp_verified
                    else (
                        "ca_attested"
                        if entry.is_ca_attested
                        else (
                            "multi_source"
                            if entry.source_count >= 2
                            else "single_source"
                        )
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
            "is_smtp_verified": entry.is_smtp_verified,
            "is_ca_attested": entry.is_ca_attested,
            "total_finding_count": entry.total_finding_count,
            "occurrence_count_per_module": dict(
                entry.occurrence_count_per_module
            ),
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
    result: DomainHarvestResult, export_path: str | Path
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
        return (
            json.dumps(
                format_harvest_json_export(result), indent=2, default=str
            ),
            None,
        )
    return (
        "",
        f"unknown export extension for {export_path!r}; "
        "supported: .json, .csv, .ndjson",
    )