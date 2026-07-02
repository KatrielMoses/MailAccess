"""Platform audit — visibility layer for Phase 6D auto-demotion.

Reads ``~/.mailaccess/platform_health.db`` and surfaces which platforms are
noisy, reliable, or dead. Analysts use this BEFORE Phase 6D's automation kicks
in, so they can see and trust what will be automated.

This module is intentionally read-only — it does not modify the health DB.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from backend.config import APP_VERSION
from backend.core.demotion_log import (
    demotion_log_path,
    env_var_key_for,
    read_recent_events,
)
from backend.core.platform_health import get_health_db

# ── status logic (per spec) ───────────────────────────────────────────────────
#
#   SKIP:   inconclusive_rate > 0.70 AND total_probes > 50
#   DEMOTE: inconclusive_rate > 0.40 AND total_probes > 30
#   WATCH:  total_probes < 20 OR (0.20 <= inconclusive_rate <= 0.40)
#   KEEP:   inconclusive_rate < 0.20 AND total_probes > 20
#
# Priority is checked in this order so the highest-severity tag wins.
# Anything that falls through SKIP / DEMOTE / WATCH / KEEP defaults to WATCH
# (the "borderline" bucket) — defensible for unclear cases.


def _classify_status(total_probes: int, inconclusive_rate: float) -> str:
    if inconclusive_rate > 0.70 and total_probes > 50:
        return "SKIP"
    if inconclusive_rate > 0.40 and total_probes > 30:
        return "DEMOTE"
    if inconclusive_rate < 0.20 and total_probes > 20:
        return "KEEP"
    return "WATCH"


# ── sort key helpers ──────────────────────────────────────────────────────────


_VALID_SORTS = ("noise", "hit-rate", "latency", "total-probes", "name")


def _sort_key(stats: dict[str, Any], sort: str):
    total = int(stats.get("total_probes") or 0)
    inconclusive = int(stats.get("inconclusive") or 0)
    inconclusive_rate = (inconclusive / total) if total else 0.0
    hit_rate = float(stats.get("hit_rate") or 0.0)
    avg_latency = int(stats.get("avg_latency_ms") or 0)
    name = str(stats.get("platform") or "")

    if sort == "noise":
        # Descending by noise rate (noisiest first).
        return (-inconclusive_rate, name)
    if sort == "hit-rate":
        # Ascending by hit rate (worst first).
        return (hit_rate, name)
    if sort == "latency":
        return (-avg_latency, name)
    if sort == "total-probes":
        return (-total, name)
    if sort == "name":
        return (name.lower(),)
    return (-inconclusive_rate, name)


# ── render ────────────────────────────────────────────────────────────────────


_STATUS_STYLE: dict[str, tuple[str, str]] = {
    "SKIP":   ("⚠", "red"),
    "DEMOTE": ("⚠", "yellow"),
    "KEEP":   ("✓", "green"),
    "WATCH":  ("~", "dim"),
}


def _db_path_str() -> str:
    home = Path.home()
    return str(home / ".mailaccess" / "platform_health.db")


def _recent_auto_demotions(within_hours: int = 24) -> dict[str, dict[str, Any]]:
    """Map ``platform -> most_recent_event_within_window``.

    Used to overlay the ``[AUTO-DEMOTED]`` label on platforms that the most
    recent investigation auto-skipped or auto-demoted. Returns a dict keyed
    by platform name; the value is the most recent matching event.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=within_hours)
    events = read_recent_events(since=cutoff)
    latest: dict[str, dict[str, Any]] = {}
    for event in events:
        action = str(event.get("action") or "")
        if action not in {"skip", "demote", "upgrade"}:
            continue
        platform = str(event.get("platform") or "")
        if not platform:
            continue
        ts = str(event.get("timestamp") or "")
        prev = latest.get(platform)
        if prev is None or ts > str(prev.get("timestamp") or ""):
            latest[platform] = event
    return latest


def _render(
    stats: list[dict[str, Any]],
    *,
    total_tracked: int,
    min_probes: int,
    sort: str,
    top: int,
    console: Console,
    auto_demotions: dict[str, dict[str, Any]] | None = None,
    show_override_hints: bool = False,
) -> None:
    sort_label = {
        "noise": "noise rate",
        "hit-rate": "hit rate",
        "latency": "avg latency",
        "total-probes": "total probes",
        "name": "name",
    }.get(sort, sort)

    plural = "s" if total_tracked != 1 else ""
    header_lines = [
        f"[bold cyan]PLATFORM AUDIT v{APP_VERSION}[/] — {total_tracked} platform{plural} tracked",
        "[dim](2500+ checked per investigation — tracked count grows as more investigations run)[/]",
        f"[dim]Data from:[/] {_db_path_str()}",
        f"[dim]Showing:[/] top {min(top, len(stats))} by {sort_label} (min {min_probes} probes)",
    ]
    console.rule(characters="━")
    for line in header_lines:
        console.print(f"  {line}")
    console.rule(characters="━")
    console.print()

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("", width=2)
    table.add_column("Platform", style="cyan", no_wrap=True)
    table.add_column("Probes", justify="right")
    table.add_column("Hit%", justify="right")
    table.add_column("Miss%", justify="right")
    table.add_column("Inconcl%", justify="right")
    table.add_column("Avg ms", justify="right")
    table.add_column("Status", justify="right")

    for row in stats:
        total = int(row.get("total_probes") or 0)
        misses = int(row.get("misses") or 0)
        inconclusive = int(row.get("inconclusive") or 0)
        hit_rate = float(row.get("hit_rate") or 0.0)
        avg_latency = int(row.get("avg_latency_ms") or 0)
        status = _classify_status(total, (inconclusive / total) if total else 0.0)
        symbol, style = _STATUS_STYLE[status]
        platform_name = str(row.get("platform") or "")
        auto_event = (auto_demotions or {}).get(platform_name)
        if auto_event is not None:
            status_text = (
                f"[{style}]{status}[/{style}]\n[magenta][AUTO-DEMOTED][/magenta]"
            )
        else:
            status_text = f"[{style}]{status}[/{style}]"

        table.add_row(
            f"[{style}]{symbol}[/{style}]",
            platform_name[:30],
            str(total),
            f"{hit_rate * 100:.0f}%" if total else "—",
            f"{(misses / total) * 100:.0f}%" if total else "—",
            f"{(inconclusive / total) * 100:.0f}%" if total else "—",
            str(avg_latency),
            status_text,
        )

    console.print(table)
    console.print()

    counts = {"SKIP": 0, "DEMOTE": 0, "KEEP": 0, "WATCH": 0}
    for row in stats:
        total = int(row.get("total_probes") or 0)
        inconclusive = int(row.get("inconclusive") or 0)
        inconcl_rate = (inconclusive / total) if total else 0.0
        counts[_classify_status(total, inconcl_rate)] += 1

    # Auto-demotion summary line — Phase 6D.
    auto_summary: dict[str, int] = {"skip": 0, "demote": 0, "upgrade": 0}
    if auto_demotions:
        for event in auto_demotions.values():
            action = str(event.get("action") or "")
            if action in auto_summary:
                auto_summary[action] += 1
    auto_summary_text = (
        f"Auto-demotions: {auto_summary['skip']} skipped · "
        f"{auto_summary['demote']} demoted to Wave 2 · "
        f"{auto_summary['upgrade']} upgraded to Wave 1 in last investigation"
    )

    console.rule(characters="─")
    plural = "s" if total_tracked != 1 else ""
    console.print(
        f"  [bold]Summary:[/] {total_tracked} platform{plural} tracked · "
        f"{counts['SKIP']} SKIP · {counts['DEMOTE']} DEMOTE · "
        f"{counts['KEEP']} KEEP · {counts['WATCH']} WATCH"
    )
    console.print(f"  [bold]{auto_summary_text}[/bold]")
    console.print("  [dim]Run with --recommend-skip for skip candidates.[/dim]")
    console.print("  [dim]Run with --export audit.json to save full report.[/dim]")
    console.print("  [dim]Run with --show-demotions to inspect auto-demoted platforms.[/dim]")
    console.rule(characters="─")

    if show_override_hints:
        skip_candidates = [
            row
            for row in stats
            if _classify_status(
                int(row.get("total_probes") or 0),
                (
                    int(row.get("inconclusive") or 0)
                    / max(int(row.get("total_probes") or 1), 1)
                ),
            )
            == "SKIP"
        ]
        if skip_candidates:
            console.print()
            console.rule(characters="─")
            console.print("  [bold]Override instructions for SKIP candidates:[/bold]")
            for row in skip_candidates:
                platform_name = str(row.get("platform") or "")
                if not platform_name:
                    continue
                env_key = env_var_key_for(platform_name)
                console.print(
                    f"  [cyan]{platform_name}[/cyan]  →  "
                    f"set [bold]{env_key}=true[/bold]"
                )
            console.rule(characters="─")


def _render_show_demotions(
    events: list[dict[str, Any]],
    console: Console,
) -> None:
    """Render the --show-demotions view: only platforms that were auto-demoted."""
    console.rule(characters="━")
    console.print("  [bold cyan]AUTO-DEMOTED PLATFORMS[/bold cyan]")
    console.print(f"  [dim]Log:[/] {demotion_log_path()}")
    console.rule(characters="━")
    console.print()

    if not events:
        console.print("  [dim]No auto-demotions recorded yet.[/dim]")
        return

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Platform", style="cyan", no_wrap=True)
    table.add_column("Action", justify="right")
    table.add_column("Inconcl%", justify="right")
    table.add_column("Hit%", justify="right")
    table.add_column("Probes", justify="right")
    table.add_column("When")
    table.add_column("Override")

    action_style = {"skip": "red", "demote": "yellow", "upgrade": "green"}

    for event in events:
        platform = str(event.get("platform") or "")
        action = str(event.get("action") or "")
        stats = event.get("stats") if isinstance(event.get("stats"), dict) else {}
        inconclusive_rate = float(stats.get("inconclusive_rate") or 0.0)
        hit_rate = float(stats.get("hit_rate") or 0.0)
        total_probes = int(stats.get("total_probes") or 0)
        ts = str(event.get("timestamp") or "")[:19]
        env_key = str(event.get("reversible_via") or env_var_key_for(platform))
        style = action_style.get(action, "white")
        override = f"set {env_key}=true"

        table.add_row(
            platform[:30],
            f"[{style}]{action.upper()}[/{style}]",
            f"{inconclusive_rate * 100:.0f}%",
            f"{hit_rate * 100:.0f}%",
            str(total_probes),
            ts,
            f"[dim]{override}[/dim]",
        )

    console.print(table)
    console.print()
    console.print(
        "  [dim]To permanently disable auto-actions for a platform, set the "
        "MAIGRET_FORCE_<PLATFORM>=true env var (any truthy value).[/dim]"
    )
    console.print()


# ── export ────────────────────────────────────────────────────────────────────


def _build_export_payload(
    all_filtered: list[dict[str, Any]],
    *,
    min_probes: int,
    recommend_skip: bool,
    sort: str,
    top: int,
    auto_demotions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    counts = {"SKIP": 0, "DEMOTE": 0, "KEEP": 0, "WATCH": 0}
    platforms_payload: list[dict[str, Any]] = []
    sorted_rows = sorted(all_filtered, key=lambda s: _sort_key(s, sort))
    displayed = sorted_rows[:top]
    if recommend_skip:
        displayed = [r for r in displayed if _classify_status(
            int(r.get("total_probes") or 0),
            (int(r.get("inconclusive") or 0) / int(r.get("total_probes") or 1))
            if int(r.get("total_probes") or 0) else 0.0,
        ) == "SKIP"]

    for row in all_filtered:
        total = int(row.get("total_probes") or 0)
        hits = int(row.get("hits") or 0)
        misses = int(row.get("misses") or 0)
        inconclusive = int(row.get("inconclusive") or 0)
        hit_rate = (hits / total) if total else 0.0
        miss_rate = (misses / total) if total else 0.0
        inconclusive_rate = (inconclusive / total) if total else 0.0
        status = _classify_status(total, inconclusive_rate)
        counts[status] += 1

    auto_demotions = auto_demotions or {}
    for row in displayed:
        total = int(row.get("total_probes") or 0)
        hits = int(row.get("hits") or 0)
        misses = int(row.get("misses") or 0)
        inconclusive = int(row.get("inconclusive") or 0)
        hit_rate = (hits / total) if total else 0.0
        miss_rate = (misses / total) if total else 0.0
        inconclusive_rate = (inconclusive / total) if total else 0.0
        consecutive_misses = int(row.get("consecutive_misses") or 0)
        platform_name = str(row.get("platform") or "")
        auto_event = auto_demotions.get(platform_name)
        platforms_payload.append({
            "name": platform_name or None,
            "total_probes": total,
            "hit_rate": round(hit_rate, 3),
            "miss_rate": round(miss_rate, 3),
            "inconclusive_rate": round(inconclusive_rate, 3),
            "avg_latency_ms": int(row.get("avg_latency_ms") or 0),
            "status": _classify_status(total, inconclusive_rate),
            "last_probed": row.get("last_seen"),
            "quarantined": consecutive_misses >= 10,
            # The platform_health schema does not track probe source; we leave
            # this None rather than fabricate a value.
            "source": None,
            "auto_demoted": (
                {
                    "action": auto_event.get("action"),
                    "timestamp": auto_event.get("timestamp"),
                    "reversible_via": auto_event.get("reversible_via"),
                }
                if auto_event
                else None
            ),
        })

    auto_summary = {"skip": 0, "demote": 0, "upgrade": 0}
    for event in auto_demotions.values():
        action = str(event.get("action") or "")
        if action in auto_summary:
            auto_summary[action] += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "database": _db_path_str(),
        "total_platforms_tracked": len(all_filtered),
        "filters_applied": {
            "min_probes": min_probes,
            "recommend_skip": recommend_skip,
            "sort": sort,
            "top": top,
        },
        "summary": {
            "skip_count": counts["SKIP"],
            "demote_count": counts["DEMOTE"],
            "keep_count": counts["KEEP"],
            "watch_count": counts["WATCH"],
            "auto_skipped": auto_summary["skip"],
            "auto_demoted": auto_summary["demote"],
            "auto_upgraded": auto_summary["upgrade"],
        },
        "platforms": platforms_payload,
    }


# ── public entry point ───────────────────────────────────────────────────────


def run_platform_audit(
    min_probes: int = 20,
    recommend_skip: bool = False,
    export: str | None = None,
    top: int = 50,
    sort: str = "noise",
    window: int = 30,
    console: Console | None = None,
    show_demotions: bool = False,
) -> None:
    """Surface the per-platform health DB for analyst review.

    Args:
        min_probes: filter platforms with fewer than this many probes.
        recommend_skip: only display SKIP candidates (inconclusive > 70% AND probes > 50).
        export: optional path to write the full JSON report to. Bare filenames route
            to ``./results/`` (the project's existing convention).
        top: maximum rows to display / export.
        sort: one of ``noise`` | ``hit-rate`` | ``latency`` | ``total-probes`` | ``name``.
        window: rolling window in days (default 30).
        console: Rich console (defaults to stdout).
        show_demotions: only display platforms that were auto-demoted in the
            last 24 hours, with stats and override instructions. Mutually
            exclusive with the normal table view.
    """
    if sort not in _VALID_SORTS:
        raise ValueError(
            f"Invalid sort: {sort!r}. Choose from: {', '.join(_VALID_SORTS)}"
        )
    if min_probes < 1:
        raise ValueError("min_probes must be >= 1")
    if top < 1:
        raise ValueError("top must be >= 1")

    if console is None:
        console = Console()

    db = get_health_db()
    all_stats = db.get_all_platforms_stats(min_probes=min_probes, window_days=window)
    auto_demotions = _recent_auto_demotions(within_hours=24)

    if show_demotions:
        events = sorted(
            auto_demotions.values(),
            key=lambda e: str(e.get("timestamp") or ""),
        )
        _render_show_demotions(events, console)
        if export:
            payload = {
                "generated_at": datetime.now(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "log": str(demotion_log_path()),
                "events": events,
            }
            export_path = _resolve_export_path(export)
            export_path.parent.mkdir(parents=True, exist_ok=True)
            export_path.write_text(
                json.dumps(payload, indent=2), encoding="utf-8"
            )
            console.print(
                f"[green]Demotion log exported to:[/] {export_path}"
            )
        return

    if not all_stats:
        # Release criterion: version must be visible even when the DB
        # is empty so operators know which MailAccess build produced
        # this output. The version header here matches the style used
        # in the populated view (PLATFORM AUDIT v{APP_VERSION}).
        console.print(f"[bold cyan]mailaccess platform-audit v{APP_VERSION}[/]")
        console.print("[yellow]No platform health data found.[/yellow]")
        console.print(
            "[dim]Run an investigation first to populate "
            "(results from maigret / sherlock / nexfil / blackbird feed this DB).[/dim]"
        )
        if export:
            # Still write an empty report so downstream tooling has a stable shape.
            payload = _build_export_payload(
                [],
                min_probes=min_probes,
                recommend_skip=recommend_skip,
                sort=sort,
                top=top,
                auto_demotions=auto_demotions,
            )
            export_path = _resolve_export_path(export)
            export_path.parent.mkdir(parents=True, exist_ok=True)
            export_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            console.print(f"[green]Empty report saved to:[/] {export_path}")
        return

    total_tracked = len(all_stats)
    display_rows = sorted(all_stats, key=lambda s: _sort_key(s, sort))[:top]
    if recommend_skip:
        display_rows = [
            r for r in display_rows
            if _classify_status(
                int(r.get("total_probes") or 0),
                (int(r.get("inconclusive") or 0) / int(r.get("total_probes") or 1))
                if int(r.get("total_probes") or 0) else 0.0,
            ) == "SKIP"
        ]

    _render(
        display_rows,
        total_tracked=total_tracked,
        min_probes=min_probes,
        sort=sort,
        top=top,
        console=console,
        auto_demotions=auto_demotions,
        show_override_hints=recommend_skip,
    )

    if export:
        payload = _build_export_payload(
            all_stats,
            min_probes=min_probes,
            recommend_skip=recommend_skip,
            sort=sort,
            top=top,
            auto_demotions=auto_demotions,
        )
        export_path = _resolve_export_path(export)
        export_path.parent.mkdir(parents=True, exist_ok=True)
        export_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print()
        console.print(f"[green]✓ Full report saved to:[/] {export_path}")


def _resolve_export_path(export: str) -> Path:
    """Route bare filenames into ./results/ to match existing project convention."""
    p = Path(export)
    if p.parent == Path("."):
        results_dir = Path(__file__).resolve().parent.parent / "results"
        results_dir.mkdir(exist_ok=True)
        return results_dir / p.name
    return p
