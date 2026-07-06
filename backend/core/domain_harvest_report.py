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
        "common_crawl_medium": "cc",
        "common_crawl_high_density": "cc*",
        "ca_attested": "ca",
        "smtp_verified": "smtp",
        "permutation_verified": "smtp",
        "permutation_catchall": "catchall",
        "permutation_unverified": "perm",
        "github_commit_author": "gh",
        "github_code_match": "gh-code",
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
        row = {
            "name": str(name),
            "sources": list(meta.get("sources") or []),
            "source_count": int(meta.get("source_count") or 0),
            "title_or_role": meta.get("title_or_role"),
            "confidence_score": float(
                meta.get("confidence_score") or 0.0
            ),
            "source_urls": list(meta.get("source_urls") or []),
        }
        pattern_row = pattern_by_name.get(str(name).strip().lower())
        if pattern_row:
            row["pattern_tier"] = pattern_row.get("tier")
            row["patterns_generated"] = int(
                pattern_row.get("patterns_generated") or 0
            )
            row["pattern_skipped"] = bool(pattern_row.get("skipped"))
            row["pattern_skip_reason"] = pattern_row.get("skip_reason")
            row["pattern_medium_confidence_threshold"] = pattern_medium_threshold
            row["downgraded_for_budget"] = bool(
                pattern_row.get("downgraded_for_budget")
            )
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
            display_label = "MED" if label == "MEDIUM" else label
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
                text.append(display_label, style=color)
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
            medium_threshold = float(
                tiered[0].get("pattern_medium_confidence_threshold") or 0.50
            )
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
            text.append(
                f"  Pattern generation: {high_count} HIGH names -> "
                f"{high_patterns} patterns · {med_count} MED names -> "
                f"{med_patterns} patterns · {low_count} LOW names skipped "
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
        if entry.is_role:
            text.append("  ")
            text.append("[ROLE]", style="yellow")
        if entry.first_seen_timestamp or entry.last_seen_timestamp:
            text.append("  ")
            first = (entry.first_seen_timestamp or "")[:7]
            last = (entry.last_seen_timestamp or entry.first_seen_timestamp or "")[:7]
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
    return (
        status == "partial"
        and any(
            "proxy" in e.lower() or "ProxyConnectionError" in e
            for e in errors
        )
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
    # --verify-smtp is the most common path from "lots of LOW junk" to
    # "a handful of SMTP-confirmed candidates".
    if unverified_permutation_count > 0 and not result.smtp_verification_used:
        hints.append(
            f"-> {unverified_permutation_count} pattern candidates "
            "suppressed — re-run with --verify-smtp to expand into "
            "SMTP-verified findings."
        )

    if suppressed_low_count > 0 and not show_low:
        hints.append(
            f"-> {suppressed_low_count} LOW confidence emails hidden — "
            "use --show-low to reveal."
        )

    if role_count > 0 and not show_role:
        hints.append(
            f"-> {role_count} role accounts hidden — "
            "use --show-role to reveal."
        )

    # Legacy hints preserved verbatim.
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

    # Phase 1: always-present "reveal everything" hint — the user can
    # opt into the legacy "show everything" surface with a single flag.
    hints.append("-> --full reveals everything.")

    if not hints:
        hints.append(
            "All set — review HIGH-confidence candidates above and "
            "pivot on confirmed names if you need broader coverage."
        )
    return hints


def format_harvest_cli_output(
    result: DomainHarvestResult,
    *,
    show_low: bool = False,
    show_unverified_patterns: bool = False,
    show_role: bool = False,
    full: bool = False,
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
      rendered with the ``--verify-smtp`` hint.
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
        show_unverified_patterns = True
        show_role = True

    console = Console(record=True, width=120)
    console.print(
        Rule(
            title=f"[bold]DOMAIN EMAIL HARVEST — {result.domain}[/bold]",
            style="cyan",
        )
    )

    # Per-source status table (unchanged).
    console.print(_build_sources_table(result))

    # ------------------------------------------------------------------
    # Phase 1: split personal vs role emails, and unverified permutations
    # out of the personal LOW bucket.  All three bucketings are derived
    # from ``result.unique_emails`` directly — the report layer is
    # self-contained and does not depend on the orchestrator's count
    # fields, which means downstream tests can construct mock results
    # with arbitrary count fields and the display stays correct.
    # ------------------------------------------------------------------
    personal_emails = [e for e in result.unique_emails if not e.is_role]
    role_emails = [e for e in result.unique_emails if e.is_role]

    unverified_perms = [
        e for e in personal_emails if _is_unverified_permutation(e)
    ]
    non_perm_personal = [
        e for e in personal_emails if not _is_unverified_permutation(e)
    ]

    # HIGH / MEDIUM / LOW — personal, excluding unverified permutations.
    high = [e for e in non_perm_personal if e.confidence_label == "HIGH"]
    medium = [
        e for e in non_perm_personal if e.confidence_label == "MEDIUM"
    ]
    low = [e for e in non_perm_personal if e.confidence_label == "LOW"]

    # ------------------------------------------------------------------
    # Phase 1: new summary bar.  Replaces the legacy "Total: N candidates"
    # with an "Actionable: ..." line that names each visible bucket and
    # the suppressed count.
    # ------------------------------------------------------------------
    suppressed_total = len(low) + len(unverified_perms)
    summary_parts: list[str] = [
        f"[bold green]{len(high)} HIGH[/bold green]",
        f"[bold yellow]{len(medium)} MEDIUM[/bold yellow] personal emails",
    ]
    if role_emails:
        summary_parts.append(f"{len(role_emails)} role accounts")
    if suppressed_total > 0:
        summary_parts.append(
            f"{suppressed_total:,} suppressed (LOW + unverified patterns)"
        )
    console.print("\n[bold]Actionable:[/bold] " + " · ".join(summary_parts))
    console.print(
        "[dim]Run with --full to show everything.[/dim]\n"
    )

    # ------------------------------------------------------------------
    # HIGH / MEDIUM / LOW panels.
    # ------------------------------------------------------------------
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

    # LOW: hidden by default.  When shown, unverified permutations are
    # included only if ``show_unverified_patterns`` is also True (the
    # two flags are independent).
    if show_low:
        low_panel_emails = list(low)
        if show_unverified_patterns:
            low_panel_emails.extend(unverified_perms)
        console.print(
            Panel(
                _format_emails_block(low_panel_emails),
                title=(
                    f"[dim]LOW CONFIDENCE ({len(low_panel_emails)})"
                    "[/dim]"
                ),
                border_style="dim",
            )
        )
    elif low:
        # LOW panel suppressed — print the dedicated suppressed-count line.
        console.print(
            f"[dim]LOW confidence: {len(low)} emails hidden. "
            "Run with --show-low to reveal.[/dim]"
        )

    # Unverified permutations: always suppressed unless the explicit
    # flag is passed.  Independent of ``show_low`` — even when LOW is
    # shown, unverified patterns stay hidden behind their own flag.
    if unverified_perms and not show_unverified_patterns:
        console.print(
            f"[dim]Unverified pattern candidates: {len(unverified_perms)} "
            "hidden (score 0.0 — no SMTP verification). "
            "Run with --verify-smtp to verify, or "
            "--show-unverified-patterns to view raw.[/dim]"
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
                    title=(
                        f"[bold yellow]ROLE ACCOUNTS ({len(role_emails)})"
                        "[/bold yellow]"
                    ),
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
                    title=(
                        f"[bold yellow]ROLE ACCOUNTS ({len(role_emails)})"
                        "[/bold yellow]"
                    ),
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
                            "pgp_or_ca"
                            if entry.is_pgp_or_ca
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
                "last_seen_timestamp": entry.last_seen_timestamp,
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
            # Phase 1 of 4: signal to downstream tooling that the CLI
            # hid a class of emails by default.  The JSON/CSV/NDJSON
            # exports always carry the FULL email list (hiding is a
            # CLI display decision only); ``display_filter`` is
            # documentation, NOT a filter applied to ``emails``.
            # Values:
            #     "all"               — no filter applied (legacy)
            #     "medium_and_above"  — LOW + unverified patterns hidden
            "display_filter": "medium_and_above",
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
                            "pgp_or_ca"
                            if entry.is_pgp_or_ca
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
            "last_seen_timestamp": entry.last_seen_timestamp,
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
