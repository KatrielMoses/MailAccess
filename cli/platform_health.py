from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from backend.core.platform_health import get_health_db

platform_health_app = typer.Typer(
    name="platform-health",
    help="Inspect per-platform probe health. Shows the noisiest platforms by default.",
    invoke_without_command=True,
)


def _fragility_color(fragility: float) -> str:
    if fragility >= 0.7:
        return "red"
    if fragility >= 0.4:
        return "yellow"
    return "green"


def _render_table(rows: list[dict], console: Console) -> None:
    table = Table(title="Platform Health")
    table.add_column("Platform", style="cyan")
    table.add_column("Probes", justify="right")
    table.add_column("Hits", justify="right", style="green")
    table.add_column("Misses", justify="right")
    table.add_column("Inconclusive", justify="right")
    table.add_column("Hit Rate", justify="right")
    table.add_column("Fragility", justify="right")
    table.add_column("Consec Misses", justify="right")
    table.add_column("Last Probed")

    for row in rows:
        frag = float(row.get("fragility") or 0.0)
        color = _fragility_color(frag)
        last_seen = str(row.get("last_seen") or "—")[:19]
        frag_text = Text(f"{frag:.3f}", style=color)
        table.add_row(
            str(row.get("platform") or ""),
            str(row.get("total_probes") or 0),
            str(row.get("hits") or 0),
            str(row.get("misses") or 0),
            str(row.get("inconclusive") or 0),
            f"{float(row.get('hit_rate') or 0.0):.3f}",
            frag_text,
            str(row.get("consecutive_misses") or 0),
            last_seen,
        )

    console.print(table)


def _build_share_payload(
    rows: list[dict[str, Any]],
    *,
    window: int,
    min_probes: int,
) -> dict[str, Any]:
    """Anonymized platform stats for the public Gist (6D.3).

    Critical: NO user data, NO email addresses, NO investigation targets.
    Only platform-level metadata — names + counts + rates + latency. Names
    are public platform names (e.g. "GitHub") which anyone scraping the web
    already knows; nothing here reveals what was investigated or against whom.
    """
    platforms: list[dict[str, Any]] = []
    for row in rows:
        total = int(row.get("total_probes") or 0)
        hits = int(row.get("hits") or 0)
        misses = int(row.get("misses") or 0)
        inconclusive = int(row.get("inconclusive") or 0)
        avg_latency_ms = int(row.get("avg_latency_ms") or 0)
        platforms.append(
            {
                "name": row.get("platform"),
                "hit_rate": round((hits / total) if total else 0.0, 3),
                "miss_rate": round((misses / total) if total else 0.0, 3),
                "inconclusive_rate": (
                    round((inconclusive / total) if total else 0.0, 3)
                ),
                "avg_latency_ms": avg_latency_ms,
                "total_probes": total,
                "last_probed": row.get("last_seen"),
            }
        )
    return {
        "generator": "mailaccess",
        "version": "0.9.0",
        "shared_at": datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "window_days": window,
        "min_probes": min_probes,
        "platform_count": len(platforms),
        "platforms": platforms,
    }


def _share_health(
    console: Console,
    *,
    window: int,
    min_probes: int,
    timeout: float,
) -> None:
    """Post anonymized platform stats to a public GitHub Gist.

    Strictly opt-in. The user must explicitly pass ``--share``; nothing in
    this code path runs from background jobs, scheduled tasks, or
    investigation completion hooks. The Gist is public (no auth required)
    and contains platform-level metadata only — no user data, no emails,
    no investigation targets.
    """
    db = get_health_db()
    rows = db.get_all_platforms_stats(min_probes=min_probes, window_days=window)
    payload = _build_share_payload(rows, window=window, min_probes=min_probes)

    # We import httpx lazily so the rest of the module remains importable in
    # offline / constrained environments.
    import httpx

    gist_body = {
        "description": "MailAccess platform health",
        "public": True,
        "files": {
            "platform_health.json": {
                "content": json.dumps(payload, indent=2, ensure_ascii=False),
            }
        },
    }
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "mailaccess",
    }

    try:
        resp = httpx.post(
            "https://api.github.com/gists",
            headers=headers,
            json=gist_body,
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        console.print(f"[red]Failed to reach GitHub Gist API:[/] {exc}")
        return

    if resp.status_code >= 400:
        console.print(
            f"[red]GitHub Gist API error:[/] HTTP {resp.status_code} "
            f"— {resp.text[:200]}"
        )
        return

    try:
        gist_url = str(resp.json().get("html_url") or "").strip()
    except (ValueError, KeyError, TypeError) as exc:
        console.print(f"[red]Unexpected response from GitHub:[/] {exc}")
        return

    if not gist_url:
        console.print("[red]GitHub returned no Gist URL.[/red]")
        return

    console.print(
        f"[green]Platform health shared. Gist URL:[/] {gist_url}\n"
        "[green]Thank you for improving MailAccess for everyone.[/green]"
    )


@platform_health_app.callback(invoke_without_command=True)
def platform_health_cmd(
    platform: str | None = typer.Option(
        None, "--platform", "-p", help="Show stats for a single platform."
    ),
    export: str | None = typer.Option(
        None, "--export", "-e", help="Export all platform stats to a JSON file."
    ),
    clear: str | None = typer.Option(
        None, "--clear", help="Delete all health records for a platform."
    ),
    window: int = typer.Option(
        30, "--window", "-w", help="Rolling window in days (default: 30)."
    ),
    share: bool = typer.Option(
        False,
        "--share",
        help="[OPT-IN] Post anonymized platform health stats to a public GitHub "
        "Gist. Strictly opt-in — never runs automatically. Use this only when "
        "you want to contribute health stats back to the community.",
    ),
    share_min_probes: int = typer.Option(
        20,
        "--share-min-probes",
        help="Minimum probes for a platform to be included in a --share payload.",
    ),
    share_timeout: float = typer.Option(
        15.0,
        "--share-timeout",
        help="HTTP timeout in seconds for the Gist upload.",
    ),
) -> None:
    """Show noisy/fragile platforms or manage the probe health database."""
    console = Console()
    db = get_health_db()

    if share:
        if export or clear or platform:
            console.print(
                "[yellow]--share is exclusive: it ignores --export, --clear, "
                "and --platform.[/yellow]"
            )
        _share_health(
            console,
            window=window,
            min_probes=share_min_probes,
            timeout=share_timeout,
        )
        return

    if clear is not None:
        db.clear(clear)
        console.print(f"[green]Cleared health records for:[/] {clear}")
        return

    if export is not None:
        names = db.all_platform_names()
        all_rows = [db.get_stats(name, window) for name in names]
        Path(export).write_text(json.dumps(all_rows, indent=2), encoding="utf-8")
        console.print(f"[green]Exported {len(all_rows)} platform records to:[/] {export}")
        return

    if platform is not None:
        rows = [db.get_stats(platform, window)]
    else:
        rows = db.get_noisiest_platforms(limit=20, window_days=window)

    if not rows:
        console.print("[dim]No health data recorded yet.[/dim]")
        return

    _render_table(rows, console)