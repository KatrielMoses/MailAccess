from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Force UTF-8 on stdout/stderr so Rich glyphs (✓, box-drawing, etc.) don't
# crash on legacy Windows code pages (cp1252).
if sys.platform == "win32":
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]

import logging
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("mailaccess").setLevel(logging.WARNING)

import httpx
import websockets
import typer
from dotenv import load_dotenv, set_key, unset_key
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# Auto-load ~/.mailaccess/.env before reading system env
_ENV_FILE = Path.home() / ".mailaccess" / ".env"
if _ENV_FILE.exists():
    load_dotenv(_ENV_FILE, override=False)

from importlib.metadata import version as pkg_version
try:
    _VERSION = pkg_version("mailaccess")
except Exception:
    _VERSION = "dev"

BANNER = f"""\
[bold red]
███╗   ███╗ █████╗ ██╗██╗      █████╗  ██████╗ ██████╗███████╗███████╗███████╗
████╗ ████║██╔══██╗██║██║     ██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝
██╔████╔██║███████║██║██║     ███████║██║     ██║     █████╗  ███████╗███████╗
██║╚██╔╝██║██╔══██║██║██║     ██╔══██║██║     ██║     ██╔══╝  ╚════██║╚════██║
██║ ╚═╝ ██║██║  ██║██║███████╗██║  ██║╚██████╗╚██████╗███████╗███████║███████║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚══════╝╚══════╝╚══════╝
[/bold red]
[dim]Open-source OSINT email intelligence tool[/dim]
[dim]v{_VERSION} · pypi.org/project/mailaccess[/dim]"""

app = typer.Typer(name="mailaccess", help="MailAccess OSINT email intelligence CLI.")
console = Console()
err_console = Console(stderr=True)

CONFIG_FILE = Path.home() / ".mailaccess" / "config.json"
ENV_FILE = Path.home() / ".mailaccess" / ".env"

_API_KEYS: list[tuple[str, str, str]] = [
    ("HIBP_API_KEY",        "hibp",          "haveibeenpwned.com/API"),
    ("SERPAPI_KEY",         "google_dork,email_discovery", "serpapi.com"),
    ("GITHUB_TOKEN",        "github_commits", "github.com API (optional)"),
    ("SHODAN_API_KEY",      "domain_intel",  "shodan.io"),
    ("EMAILREP_API_KEY",    "emailrep",      "emailrep.io"),
    ("HUNTER_IO_API_KEY",   "hunter_io",     "hunter.io"),
    ("COMPANIES_HOUSE_API_KEY", "companies_house", "developer.company-information.service.gov.uk"),
    ("SLACK_WEBHOOK_URL",   "notifications", "Slack app webhooks"),
    ("DISCORD_WEBHOOK_URL", "notifications", "Discord server webhooks"),
]

_EXPORT_FORMATS = {".json", ".csv", ".md", ".pdf", ".stix", ".mtgx"}

_HARDCODED_MODULES = [
    ("haveibeenpwned", "HIBP",      "HIBP_API_KEY",      "No", "Check email against known breach databases"),
    (
        "breach_deep",
        "HIBP top 100",
        "—",
        "Yes",
        "Probe accounts on high-severity breached domains",
    ),
    ("hunter_io",      "Hunter.io", "HUNTER_IO_API_KEY", "No", "Find associated domain email patterns"),
    ("emailrep",       "EmailRep",  "EMAILREP_API_KEY",  "No", "Email reputation and metadata lookup"),
    ("gravatar",       "Gravatar",  "—",                 "No", "Retrieve profile photo via Gravatar"),
    ("google_dork",    "Google",    "SERPAPI_KEY",        "No", "Run targeted dork queries via SerpAPI"),
    ("email_discovery", "Google",   "SERPAPI_KEY",        "No", "Find other emails tied to recovered real names"),
    ("wayback",        "Wayback",   "—",                 "No", "Find historical archived pages mentioning the email"),
    ("github_commits", "GitHub",    "GITHUB_TOKEN",       "No", "Search commit authorship history by email"),
    ("google_search",  "Google",    "—",                 "No", "General Google search for email mentions"),
    ("shodan",         "Shodan",    "SHODAN_API_KEY",    "No", "IP/domain intelligence via Shodan"),
    ("dns_lookup",     "DNS",       "—",                 "No", "DNS record enumeration for email domain"),
    ("whois_lookup",   "WHOIS",     "—",                 "No", "WHOIS registration data for email domain"),
    ("social_links",   "Multi",     "—",                 "No", "Check email on social platforms"),
    ("domain_intel",   "Multi",     "SHODAN_API_KEY",    "No", "Domain intelligence and infrastructure recon"),
    ("ransomware_intel", "Ransomware", "—",              "No", "Check if domain is a ransomware victim"),
]

OPT_IN_MODULES = {
    "breach_deep":       "enable_breach_deep",
    "ghunt":             "enable_ghunt",
    "email_discovery":   "enable_email_discovery",
    "press_intel":       "enable_press_intel",
}


# ── Global callback (banner) ──────────────────────────────────────────────────

@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the ASCII banner (for CI/scripting)"),
) -> None:
    import sys
    if sys.stderr.isatty() and not no_banner:
        err_console.print(BANNER)
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


# ── Config ────────────────────────────────────────────────────────────────────

def get_backend_url() -> str:
    url = os.environ.get("MAILACCESS_URL")
    if url:
        return url.rstrip("/")
    if CONFIG_FILE.exists():
        with contextlib.suppress(Exception):
            with open(CONFIG_FILE) as f:
                data = json.load(f)
                url = data.get("url")
                if url:
                    return url.rstrip("/")
    return "http://localhost:8000"


def set_backend_url(url: str) -> None:
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {}
    if CONFIG_FILE.exists():
        with contextlib.suppress(Exception):
            with open(CONFIG_FILE) as f:
                data = json.load(f)
    data["url"] = url
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)


config_app = typer.Typer(name="config", help="Manage configuration", invoke_without_command=True, no_args_is_help=True)
app.add_typer(config_app)


@config_app.callback(invoke_without_command=True)
def config_callback(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


@config_app.command(name="set-url")
def config_set_url(
    url: str = typer.Argument(..., help="Backend URL (e.g. http://localhost:8000)"),
) -> None:
    """Set the backend URL."""
    set_backend_url(url)
    console.print(f"[green]Backend URL set to:[/] {url}")


# ── Keys ──────────────────────────────────────────────────────────────────────

keys_app = typer.Typer(name="keys", help="Manage API keys stored in ~/.mailaccess/.env", invoke_without_command=True, no_args_is_help=True)
app.add_typer(keys_app)


@keys_app.callback(invoke_without_command=True)
def keys_callback(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


@keys_app.command(name="list")
def keys_list() -> None:
    """Show all supported API keys and their current status."""
    table = Table(title="API Keys")
    table.add_column("Key Name", style="cyan")
    table.add_column("Required For")
    table.add_column("Service")
    table.add_column("Status", justify="center")

    for key_name, module, service in _API_KEYS:
        value = os.environ.get(key_name)
        status = "[green]SET[/green]" if value else "[red]NOT SET[/red]"
        table.add_row(key_name, module, service, status)

    console.print(table)


@keys_app.command(name="set")
def keys_set(
    key_name: str = typer.Argument(..., help="API key name (e.g. HIBP_API_KEY)"),
    value: str = typer.Argument(..., help="The key value to store"),
) -> None:
    """Save an API key to ~/.mailaccess/.env."""
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not ENV_FILE.exists():
        ENV_FILE.touch()
    set_key(str(ENV_FILE), key_name, value)
    console.print(f"[green]✓ {key_name} saved to ~/.mailaccess/.env[/green]")
    console.print("[dim]Restart MailAccess server for changes to take effect[/dim]")


@keys_app.command(name="unset")
def keys_unset(
    key_name: str = typer.Argument(..., help="API key name to remove"),
) -> None:
    """Remove an API key from ~/.mailaccess/.env."""
    if not ENV_FILE.exists():
        console.print("[yellow]~/.mailaccess/.env not found — nothing to remove.[/yellow]")
        return
    removed, _ = unset_key(str(ENV_FILE), key_name)
    if removed:
        console.print(f"[green]✓ {key_name} removed from ~/.mailaccess/.env[/green]")
    else:
        console.print(f"[yellow]{key_name} was not found in ~/.mailaccess/.env[/yellow]")


# ── Commands overview ─────────────────────────────────────────────────────────

@app.command(name="commands")
def commands_overview() -> None:
    """Show all available commands with descriptions."""
    content = (
        "  [cyan]investigate <email>[/cyan]   Run full OSINT on an email address\n"
        "  [cyan]serve[/cyan]                 Start the backend server locally\n"
        "  [cyan]history[/cyan]               View past investigations\n"
        "  [cyan]keys list[/cyan]             Show API key status\n"
        "  [cyan]keys set <k> <v>[/cyan]      Save an API key to ~/.mailaccess/.env\n"
        "  [cyan]keys unset <k>[/cyan]        Remove an API key\n"
        "  [cyan]config set-url <url>[/cyan]  Set backend server URL\n"
        "  [cyan]modules[/cyan]               List available investigation modules\n"
        "  [cyan]commands[/cyan]              Show this help panel"
    )
    console.print(Panel(content, title="MailAccess Commands", border_style="cyan"))


@app.command(name="serve")
def serve_command(
    host: str = typer.Option("127.0.0.1", "--host", help="Host IP to bind to"),
    port: int = typer.Option(8000, "--port", help="Port to bind to"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload (dev mode)"),
) -> None:
    """Start the MailAccess backend server."""
    import asyncio
    import uvicorn
    from backend.db.database import init_db

    asyncio.run(init_db())

    err_console.print("[green]Starting MailAccess server...[/green]")
    err_console.print(f"[dim]Listening on http://{host}:{port}[/dim]")
    err_console.print("[dim]Press Ctrl+C to stop[/dim]")

    uvicorn.run(
        "backend.main:app",
        host=host,
        port=port,
        reload=reload
    )


# ── Modules ───────────────────────────────────────────────────────────────────

@app.command(name="modules")
def modules_list(
    timeout: int = typer.Option(5, help="Timeout in seconds when contacting server"),
) -> None:
    """List all available investigation modules."""
    server_modules: list[str] | None = None
    with contextlib.suppress(Exception):
        resp = httpx.get(f"{get_backend_url()}/health", timeout=timeout)
        if resp.status_code == 200:
            server_modules = resp.json().get("modules_loaded")

    table = Table(title="Available Modules")
    table.add_column("Module", style="cyan")
    table.add_column("Platforms")
    table.add_column("Requires Key")
    table.add_column("Opt-in")
    table.add_column("Description")

    for name, platform, key_req, opt_in, desc in _HARDCODED_MODULES:
        label = name
        if server_modules is not None:
            label += " [green]●[/green]" if name in server_modules else " [dim]○[/dim]"
        table.add_row(label, platform, key_req, opt_in, desc)

    console.print(table)
    if server_modules is None:
        console.print("[dim]Could not reach server — showing hardcoded module list.[/dim]")


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_risk_color(risk_level: str) -> str:
    risk_level = risk_level.lower()
    if risk_level == "low":
        return "green"
    elif risk_level == "medium":
        return "yellow"
    elif risk_level == "high":
        return "red"
    elif risk_level == "critical":
        return "bright_red"
    return "white"


def get_status_color(status: str) -> str:
    status = status.lower()
    if status in ("success", "complete"):
        return "green"
    elif status == "failed":
        return "red"
    elif status in ("pending", "running"):
        return "cyan"
    elif status == "partial":
        return "yellow"
    return "white"


def _normalize_module_name(name: str) -> str:
    return name.replace("_", " ").upper()


def _short_id(inv_id: str, length: int = 8) -> str:
    return inv_id[:length]


def _display_url(value: str, max_len: int = 50) -> str:
    cleaned = value.strip()
    for prefix in ("https://", "http://"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
            break
    if cleaned.startswith("www."):
        cleaned = cleaned[4:]
    if len(cleaned) <= max_len:
        return cleaned
    return f"{cleaned[: max_len - 3]}..."


def _score_color(score: int | None) -> str:
    if score is None:
        return "white"
    if score <= 15:
        return "green"
    if score <= 35:
        return "yellow"
    if score <= 65:
        return "dark_orange"
    return "red"


_PLATFORM_DISPLAY_NAMES: dict[str, str] = {
    "github_user": "GitHub Profile",
    "github_commit": "GitHub",
    "twitter_profile": "Twitter/X",
    "linkedin_snippet": "LinkedIn",
    "gravatar_profile": "Gravatar",
    "keybase_profile": "Keybase",
    "keybase_proof_twitter": "Keybase Proof: Twitter",
    "keybase_proof_github": "Keybase Proof: GitHub",
    "keybase_proof_reddit": "Keybase Proof: Reddit",
    "keybase_proof_hackernews": "Keybase Proof: HN",
    "keybase_proof_dns": "Keybase Proof: DNS",
    "keybase_proof_generic_web_site": "Keybase Proof: Web",
    "etsy_shop": "Etsy",
    "ebay_profile": "eBay",
    "wayback_machine": "Wayback Machine",
    "commoncrawl": "Common Crawl",
    "alternate_email": "Alternate Email",
    "email_credibility": None,
}


def _platform_display_name(raw: str) -> str:
    if raw in _PLATFORM_DISPLAY_NAMES:
        mapped = _PLATFORM_DISPLAY_NAMES[raw]
        return raw if mapped is None else mapped
    for prefix in ("keybase_proof_",):
        if raw.startswith(prefix):
            proof_type = raw[len(prefix):].replace("_", " ").title()
            return f"Keybase Proof: {proof_type}"
    return raw


def _extract_finding_line(finding: dict[str, Any], default_name: str) -> tuple[str, str]:
    raw_platform = (
        finding.get("platform")
        or finding.get("service")
        or finding.get("source")
        or finding.get("site")
        or default_name
    )
    platform = _platform_display_name(raw_platform)
    url_like = (
        finding.get("url")
        or finding.get("profile_url")
        or finding.get("link")
        or finding.get("domain")
        or finding.get("website")
        or ""
    )
    if not url_like:
        display_name = finding.get("display_name")
        username = finding.get("username")
        breach_name = finding.get("breach_name")
        severity = finding.get("severity")
        extra = next(
            (v for v in (display_name, username, breach_name, severity) if isinstance(v, str) and v.strip()),
            "",
        )
        url_like = extra
    return str(platform), _display_url(str(url_like)) if url_like else ""


def _format_duration(run: dict[str, Any]) -> str:
    duration = run.get("duration_seconds")
    if isinstance(duration, (int, float)):
        return f"{duration:.1f}s"
    started = run.get("started_at")
    finished = run.get("completed_at") or run.get("finished_at")
    if isinstance(started, str) and isinstance(finished, str):
        try:
            start_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(finished.replace("Z", "+00:00"))
            return f"{max((end_dt - start_dt).total_seconds(), 0):.1f}s"
        except ValueError:
            return "—"
    return "..."


# ── Investigate ───────────────────────────────────────────────────────────────

async def _investigate(
    email: str,
    output_format: str,
    modules: str | None,
    timeout: int,
    output_file: str | None,
    force: bool = False,
    show_collisions: bool = False,
    enable: str | None = None,
    no_brief: bool = False,
) -> int:
    base_url = get_backend_url()
    out = err_console if output_format in ("json", "jsonl") else console

    enable_modules_list = []
    if enable:
        if enable.strip().lower() == "all":
            enable_modules_list = list(OPT_IN_MODULES.keys())
        else:
            for m in enable.split(","):
                m_strip = m.strip()
                if not m_strip:
                    continue
                if m_strip in OPT_IN_MODULES:
                    enable_modules_list.append(m_strip)
                else:
                    err_console.print(f"[yellow]Unknown opt-in module: {m_strip}. Valid: {', '.join(OPT_IN_MODULES.keys())}[/yellow]")

    payload: dict[str, Any] = {"email": email}
    if modules:
        payload["modules"] = [m.strip() for m in modules.split(",") if m.strip()]
    if force:
        payload["force"] = True
    if enable_modules_list:
        payload["enable_modules"] = enable_modules_list
        err_console.print(f"[dim]Opt-in modules enabled: {', '.join(enable_modules_list)}[/dim]")

    try:
        async with httpx.AsyncClient() as check_client:
            await check_client.get(f"{base_url}/health", timeout=3.0)
    except Exception:
        err_console.print(f"[yellow]No backend found at {base_url}[/yellow]")
        err_console.print("[dim]Starting embedded server...[/dim]")
        
        import threading
        import uvicorn
        from backend.db.database import init_db
        await init_db()

        server_thread = threading.Thread(
            target=uvicorn.run,
            args=("backend.main:app",),
            kwargs={"host": "127.0.0.1", "port": 8000, "log_level": "error"},
            daemon=True
        )
        server_thread.start()
        
        server_ready = False
        for _ in range(30):
            await asyncio.sleep(0.5)
            err_console.print(".", end="", style="dim")
            try:
                async with httpx.AsyncClient() as check_client:
                    resp = await check_client.get(f"{base_url}/health", timeout=1.0)
                    if resp.status_code == 200:
                        server_ready = True
                        break
            except Exception:
                pass
        err_console.print()
        if not server_ready:
            err_console.print("[red]Error:[/] Server failed to start within 15 seconds")
            return 3
        err_console.print("[dim]Server started. Will stop when investigation completes.[/dim]")

    async with httpx.AsyncClient(base_url=base_url, timeout=timeout) as client:
        err_console.print(f"[dim]Backend: {base_url}[/dim]")
        try:
            resp = await client.post("/api/investigate", json=payload)
            resp.raise_for_status()
            data = resp.json()
            inv_id = data["id"]
            cached = bool(data.get("cached"))
        except httpx.ConnectError:
            out.print("[red]Error:[/] cannot connect to MailAccess server", style="bold red")
            return 3
        except httpx.HTTPStatusError as e:
            out.print(f"[red]Error starting investigation:[/] {e.response.text}", style="bold red")
            return 3
        except Exception as e:
            out.print(f"[red]Error:[/] {e}", style="bold red")
            return 3

        if output_format == "jsonl":
            sys.stdout.write(json.dumps({"type": "start", "email": email, "id": inv_id}) + "\n")
            sys.stdout.flush()

        if output_format not in ("json", "jsonl"):
            started_time = datetime.now().strftime("%H:%M:%S")
            header = Text()
            header.append("🔍  ", style="bold")
            header.append(email, style="bold cyan")
            header.append("\n")
            header.append(
                f"ID: {_short_id(inv_id)} · Started: {started_time}",
                style="dim",
            )
            out.print(Rule(style="dim"))
            out.print(header)
            out.print(Rule(style="dim"))

        if cached and output_format not in ("json", "jsonl"):
            try:
                created_dt = datetime.fromisoformat(data["created_at"])
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=timezone.utc)
                age_min = int(
                    (datetime.now(timezone.utc) - created_dt).total_seconds() // 60
                )
                out.print(
                    f"[dim]Using recent result from {age_min} minute{'s' if age_min != 1 else ''} ago "
                    f"(pass --force to re-run)[/dim]\n"
                )
            except Exception:
                out.print("[dim]Using recent cached result (pass --force to re-run)[/dim]\n")

        status = "complete" if cached else "pending"
        report_data: dict[str, Any] = {}

        def _get_score(rep: dict[str, Any]) -> int | float | None:
            score = rep.get("exposure_score")
            if score is None:
                summary = rep.get("summary")
                if isinstance(summary, dict):
                    score = summary.get("exposure_score")
            if isinstance(score, (int, float)):
                return score
            return None

        def _get_risk(rep: dict[str, Any]) -> str:
            risk = rep.get("risk_level")
            if risk is None:
                summary = rep.get("summary")
                if isinstance(summary, dict):
                    risk = summary.get("risk_level")
            return str(risk) if risk is not None else "unknown"

        def _get_credential_score(rep: dict[str, Any]) -> int | float | None:
            score = rep.get("credential_risk_score")
            if isinstance(score, (int, float)):
                return score
            return None

        def _get_credential_band(rep: dict[str, Any]) -> str:
            band = rep.get("credential_risk_band")
            return str(band) if band is not None else "UNKNOWN"

        def _cred_meta(rep: dict[str, Any]) -> dict[str, Any]:
            cred = rep.get("email_credibility")
            return cred if isinstance(cred, dict) else {}

        def _cred_provider(rep: dict[str, Any]) -> str:
            cred = _cred_meta(rep)
            canonical = str(
                cred.get("canonical_email")
                or rep.get("canonical_email")
                or rep.get("email")
                or ""
            ).strip()
            if "@" in canonical:
                return canonical.rsplit("@", 1)[-1]
            return str(cred.get("provider_family") or "other")

        def render_credibility_banner(rep: dict[str, Any]) -> None:
            cred = _cred_meta(rep)
            canonical = str(
                cred.get("canonical_email")
                or rep.get("canonical_email")
                or rep.get("email")
                or ""
            ).strip()
            original = str(rep.get("email") or "").strip()
            provider = _cred_provider(rep)
            aliases = cred.get("aliases_detected") if isinstance(cred.get("aliases_detected"), list) else []
            verdict = str(cred.get("reputation_verdict") or "clean").lower()
            flags = [str(flag) for flag in cred.get("reputation_flags", []) if str(flag).strip()]
            is_disposable = bool(cred.get("is_disposable"))
            is_malicious = bool(cred.get("is_malicious"))

            if is_disposable:
                out.print("[yellow]⚠ DISPOSABLE EMAIL DETECTED[/yellow]")
                out.print(f"Provider: {provider or 'unknown'}")
                out.print("[yellow]This address is unlikely to represent a persistent identity.[/yellow]")
            elif verdict == "malicious" or is_malicious:
                out.print("[yellow]⚠ SUSPICIOUS EMAIL ADDRESS[/yellow]")
                if flags:
                    out.print(f"Flags: {', '.join(flags)}")
                out.print("[yellow]Context: this may be a threat actor address, not a victim address.[/yellow]")
            else:
                out.print(f"[green]✓ {provider or 'other'} — established provider[/green]")

            if canonical and original and canonical != original:
                if aliases:
                    out.print(f"[dim]Aliases: {' = '.join(str(a) for a in aliases if str(a).strip())}[/dim]")
                else:
                    out.print(f"[dim]Alias detected: {original}[/dim]")
                out.print(f"[dim]Investigating canonical: {canonical}[/dim]")
            out.print()

        _progress_table = Table(title="Module Progress", box=None)

        def update_progress_table(rep: dict[str, Any]) -> Table:
            _progress_table.columns.clear()
            _progress_table.add_column("Module", style="cyan")
            _progress_table.add_column("Status", justify="right")
            _progress_table.add_column("Time", justify="right", style="dim")
            for run in rep.get("module_runs", []):
                mod_name = run.get("module_name", "Unknown")
                mod_status = run.get("status", "unknown")
                color = get_status_color(mod_status)
                duration = _format_duration(run)
                _progress_table.add_row(mod_name, f"[{color}]{mod_status.upper()}[/]", duration)
            return _progress_table

        def _get_email_discovery_findings(rep: dict[str, Any]) -> list[dict[str, Any]]:
            findings = rep.get("findings_by_module", {}).get("email_discovery", [])
            return [f for f in findings if isinstance(f, dict)]

        def _get_discovered_emails(rep: dict[str, Any]) -> list[str]:
            emails_seen: dict[str, str] = {}
            for finding in _get_email_discovery_findings(rep):
                meta = finding.get("metadata", {})
                if not isinstance(meta, dict):
                    continue
                discovered = meta.get("discovered_email")
                if isinstance(discovered, str) and discovered.strip():
                    emails_seen.setdefault(discovered.lower(), discovered.strip())
            return [emails_seen[key] for key in sorted(emails_seen)]

        def _get_alternate_emails(rep: dict[str, Any]) -> list[dict[str, Any]]:
            findings = rep.get("findings_by_module", {}).get("alternate_email", [])
            return [f for f in findings if isinstance(f, dict)]

        def _name_consensus(rep: dict[str, Any]) -> dict[str, Any]:
            consensus = rep.get("name_consensus")
            if isinstance(consensus, dict):
                return consensus
            return {
                "confirmed_name": rep.get("confirmed_name"),
                "name_confidence": rep.get("name_confidence") or "unknown",
                "name_reasoning": rep.get("name_reasoning") or "",
                "name_sources": rep.get("name_sources") or [],
            }

        def _format_name_sources(sources: Any) -> str:
            if not isinstance(sources, list):
                return ""
            return " · ".join(str(src).replace("_", " ").title() for src in sources if src)

        def render_summary(rep: dict[str, Any]) -> None:
            score = _get_score(rep)
            risk = _get_risk(rep)
            credential_score = _get_credential_score(rep)
            credential_band = _get_credential_band(rep)
            cred = _cred_meta(rep)
            findings_count = len(rep.get("findings", []))
            
            module_runs = rep.get("module_runs", [])
            total_modules = len(module_runs)
            skipped_count = sum(1 for r in module_runs if str(r.get("status", "")).lower() == "skipped")
            ran_modules = total_modules - skipped_count
            
            score_val = str(score) if score is not None else "N/A"
            if score is not None:
                score_val = f"{score}/100"
            score_str = f"{score_val} ({ran_modules}/{total_modules} modules)"
            
            risk_color = get_risk_color(risk)
            score_color = _score_color(score if isinstance(score, int) else None)
            credential_color = _score_color(
                credential_score if isinstance(credential_score, int) else None
            )
            credential_summary = (
                f"{credential_score} {credential_band}"
                if credential_score is not None
                else f"N/A {credential_band}"
            )
            provider = _cred_provider(rep)
            disposable = bool(cred.get("is_disposable"))
            malicious = bool(cred.get("is_malicious"))
            def _finding_payload(finding: dict[str, Any]) -> dict[str, Any]:
                data = finding.get("data")
                return data if isinstance(data, dict) else finding

            breach_count = 0
            paste_count = 0
            stealer_count = 0
            for f in rep.get("findings", []):
                if not isinstance(f, dict):
                    continue
                payload = _finding_payload(f)
                mod = str(f.get("module_name", "")).lower()
                src = str(payload.get("source", "")).lower()
                plat = str(payload.get("platform", "")).lower()
                sig = str(payload.get("signal_type", "")).lower()
                
                if sig == "stealer_signal" or mod == "hudson_rock" or src == "hudson_rock":
                    stealer_count += 1
                elif sig == "paste_exposure" or src == "xposedornot_pastes":
                    paste_count += 1
                elif any(m in (src, plat, mod) for m in ("hibp", "breachdirectory", "hudson_rock", "haveibeenpwned", "breach_deep", "xposedornot")):
                    if mod != "hudson_rock" and src != "hudson_rock":
                        breach_count += 1

            provider_segment = f"[bold]{provider}[/]" if provider and not disposable else "[bold]⚠ DISPOSABLE[/]"
            summary = (
                f" [bold]Exposure:[/] [{score_color}]{score_str}[/]  |  "
                f"[bold]Cred Risk:[/] [{credential_color}]{credential_summary}[/]  |  "
                f"{provider_segment}  |  "
                f"[bold]Risk:[/] [{risk_color}]{risk.upper()}[/]  |  "
                f"[bold]Breaches:[/] {breach_count} | [bold]Pastes:[/] {paste_count} | [bold]Stealer:[/] {stealer_count} "
            )
            consensus = _name_consensus(rep)
            if (
                consensus.get("confirmed_name")
                and str(consensus.get("name_confidence") or "").lower() == "confirmed"
            ):
                summary += f" | [bold]{consensus.get('confirmed_name')}[/]"
            if malicious and not disposable:
                summary += " | [bold red]SUSPICIOUS[/bold red]"
            timeline = rep.get("timeline") if isinstance(rep.get("timeline"), dict) else {}
            first_seen = str(timeline.get("first_seen_date") or "")
            first_seen_year = first_seen[:4] if len(first_seen) >= 4 else "-"
            try:
                active_risk_count = int(timeline.get("active_risk_count") or 0)
            except (TypeError, ValueError):
                active_risk_count = 0
            active_risk_text = (
                "[red]YES[/red]" if active_risk_count > 0 else "[green]NO[/green]"
            )
            summary += (
                f" | [bold]First seen:[/] {first_seen_year} "
                f"| [bold]Active risk:[/] {active_risk_text}"
            )
            
            alt_emails = _get_alternate_emails(rep)
            if alt_emails:
                summary += f" | [bold]Alt emails:[/] {len(alt_emails)}"
                
            out.print(Panel(summary, border_style=score_color))
            if skipped_count > 3:
                out.print(f"[dim]{skipped_count} modules skipped — set API keys to improve coverage. Run: mailaccess keys list[/dim]")
            out.print()

        def render_defenders_brief(rep: dict[str, Any]) -> None:
            brief = rep.get("defenders_brief")
            if not isinstance(brief, dict) or not brief:
                return
            risk_level = str(brief.get("risk_level") or "UNKNOWN").upper()
            summary = str(brief.get("risk_summary") or "").strip()
            findings = [
                finding
                for finding in brief.get("top_findings", [])
                if isinstance(finding, dict)
            ][:3]
            has_medium_or_above = any(
                str(finding.get("severity") or "").lower()
                in {"medium", "high", "critical"}
                for finding in findings
            )

            out.print(Rule("DEFENDER'S BRIEF", style="bold magenta"))
            if not has_medium_or_above:
                condensed = f"  Risk: {risk_level}"
                if summary:
                    condensed += f" - {summary.split(' - ', 1)[-1]}"
                out.print(condensed)
                out.print(Rule(style="dim"))
                out.print()
                return

            out.print(f"  {'Risk:':<10} {risk_level}")
            if summary:
                out.print(f"  {'Summary:':<10} {summary}")
            out.print()
            for index, finding in enumerate(findings, 1):
                title = str(finding.get("title") or "").strip()
                severity = str(finding.get("severity") or "").upper()
                detail = str(finding.get("detail") or "").strip()
                remediation = str(finding.get("remediation") or "").strip()
                out.print(f"  {index}. [bold]{title}[/bold]   [{severity}]")
                if detail:
                    out.print(f"     {detail}")
                if remediation:
                    out.print(f"     -> {remediation}")
                out.print()
            next_action = str(brief.get("next_action") or "").strip()
            if next_action:
                out.print(f"  [bold]Next action:[/bold] {next_action}")
            out.print(Rule(style="dim"))
            out.print()

        def render_timeline(rep: dict[str, Any]) -> None:
            timeline = rep.get("timeline") if isinstance(rep.get("timeline"), dict) else {}
            events = timeline.get("events") if isinstance(timeline.get("events"), list) else []
            events = [event for event in events if isinstance(event, dict)]
            if not events:
                return

            def _date_obj(value: Any):
                text = str(value or "").strip()
                if not text:
                    return None
                try:
                    if len(text) == 7:
                        return datetime.fromisoformat(f"{text}-01").date()
                    return datetime.fromisoformat(text[:10]).date()
                except Exception:
                    return None

            def _age_text(value: Any) -> str:
                parsed = _date_obj(value)
                if parsed is None:
                    return "unknown age"
                days = max((datetime.now(timezone.utc).date() - parsed).days, 0)
                if days < 60:
                    return f"{days} day{'s' if days != 1 else ''} ago"
                months = max(round(days / 30), 1)
                if months < 24:
                    return f"{months} month{'s' if months != 1 else ''} ago"
                years = max(days // 365, 1)
                return f"{years} year{'s' if years != 1 else ''} ago"

            def _event_sort_key(event: dict[str, Any]):
                return _date_obj(event.get("date")) or datetime.min.date()

            def _event_style(event: dict[str, Any]) -> tuple[str, str]:
                event_type = str(event.get("event_type") or "")
                active = bool(event.get("is_active_risk"))
                if event_type == "stealer_log":
                    return "red", "\u26a0 "
                if event_type == "breach" and active:
                    return "yellow", "\u26a0 "
                if event_type == "breach":
                    return "dim", ""
                if event_type in ("commit", "archive_snapshot"):
                    return "dim cyan", ""
                if event_type == "first_seen":
                    return "green", ""
                return "dim", ""

            events.sort(key=_event_sort_key)
            first_seen = timeline.get("first_seen_date")
            first_event = next(
                (event for event in events if event.get("date") == first_seen),
                None,
            )
            first_source = (
                first_event.get("title")
                if isinstance(first_event, dict) and first_event.get("title")
                else timeline.get("first_seen_source") or "unknown"
            )
            most_recent = timeline.get("most_recent_date")
            most_recent_event = timeline.get("most_recent_event") or "unknown"
            age_years = timeline.get("identity_age_years")
            age_label = (
                f"{age_years} year{'s' if age_years != 1 else ''} ago"
                if isinstance(age_years, int)
                else _age_text(first_seen)
            )

            out.print(Rule("EXPOSURE TIMELINE", style="bold magenta"))
            out.print(
                f"  [bold]First seen:[/]   {first_seen or '-'} ({age_label}) - {first_source}"
            )
            out.print(
                f"  [bold]Most recent:[/]  {most_recent or '-'} - {most_recent_event}"
            )
            out.print()

            commit_events = [
                event for event in events if str(event.get("event_type") or "") == "commit"
            ]
            visible_commit_events = sorted(
                commit_events,
                key=_event_sort_key,
                reverse=True,
            )[:3]
            visible_commit_ids = {id(event) for event in visible_commit_events}

            for event in events:
                if str(event.get("event_type") or "") == "commit":
                    if id(event) in visible_commit_ids:
                        continue
                    continue
                style, marker = _event_style(event)
                event_type = str(event.get("event_type") or "")[:16]
                title = str(event.get("title") or "")
                detail = str(event.get("detail") or "")
                suffix = " (active risk)" if event.get("is_active_risk") else ""
                line = (
                    f"  {event.get('date', ''):<10}  {event_type:<16} "
                    f"{marker}{title}{suffix}"
                )
                out.print(f"[{style}]{line}[/{style}]")
                if detail:
                    out.print(f"    [dim]{detail}[/dim]")

            if visible_commit_events:
                out.print()
                for event in visible_commit_events:
                    style = "dim cyan"
                    date_text = str(event.get("date") or "")[:7] or "-"
                    event_type = str(event.get("event_type") or "")[:16]
                    title = str(event.get("title") or "")
                    detail = str(event.get("detail") or "")
                    line = f"  {date_text:<10}  {event_type:<16} {title}"
                    if detail:
                        line = f"{line} — {detail}"
                    out.print(f"[{style}]{line}[/{style}]")
                remaining_commits = len(commit_events) - len(visible_commit_events)
                if remaining_commits > 0:
                    out.print(f"  [dim]+{remaining_commits} more commits[/dim]")

            active_events = [event for event in events if event.get("is_active_risk")]
            if active_events:
                latest_active = max(active_events, key=_event_sort_key)
                out.print()
                out.print(
                    f"  [red]\u26a0 ACTIVE RISK[/red] - "
                    f"{latest_active.get('title', 'exposure')} detected "
                    f"{latest_active.get('date', '-')}"
                )
                out.print(
                    f"    [dim]Most recent exposure: {_age_text(most_recent)}[/dim]"
                )

            if timeline.get("established_identity"):
                out.print(
                    f"  [dim]Established identity - first seen {age_label}[/dim]"
                )
            else:
                out.print(
                    "  [yellow]New or throwaway - first seen less than 3 years ago[/yellow]"
                )
            out.print()

        def render_findings(rep: dict[str, Any]) -> None:
            findings_by_module = rep.get("findings_by_module", {})
            if findings_by_module:
                def _format_records(value: Any) -> str:
                    try:
                        count = int(value or 0)
                    except (TypeError, ValueError):
                        count = 0
                    if count >= 1_000_000_000:
                        return f"{count / 1_000_000_000:.1f}B records"
                    if count >= 1_000_000:
                        return f"{round(count / 1_000_000):.0f}M records"
                    if count >= 1_000:
                        return f"{round(count / 1_000):.0f}K records"
                    return f"{count} records"

                def _render_breach_deep(findings: list[Any]) -> None:
                    out.print(Rule(f"BREACH DEEP  ({len(findings)} hits)", style="cyan"))
                    total_records = 0
                    for finding in findings:
                        if not isinstance(finding, dict):
                            continue
                        meta = finding.get("metadata", {})
                        if not isinstance(meta, dict):
                            meta = {}
                        severity = str(finding.get("severity", "")).lower()
                        symbol = "⚠" if severity == "critical" else "✓"
                        style = "red" if severity == "critical" else "yellow"
                        platform = str(finding.get("platform") or "")
                        pwn_count = meta.get("pwn_count", 0)
                        with contextlib.suppress(Exception):
                            total_records += int(pwn_count or 0)
                        severity_label = severity.upper() if severity else "MEDIUM"
                        classes = meta.get("data_classes") or []
                        classes_text = ", ".join(str(c) for c in classes)
                        out.print(
                            f"  [{style}]{symbol}[/{style}] {platform[:20]:<20} "
                            f"[{style}]{severity_label:<8}[/{style}] {_format_records(pwn_count)}"
                        )
                        if classes_text:
                            out.print(f"    [dim][{classes_text}][/dim]")
                    out.print()
                    if findings:
                        out.print(
                            f"  [dim]~{_format_records(total_records)} across {len(findings)} "
                            "breaches potentially include this email's credentials[/dim]"
                        )
                        out.print()

                def _render_email_discovery(findings: list[Any]) -> None:
                    usable = [f for f in findings if isinstance(f, dict)]
                    out.print(Rule(f"EMAIL DISCOVERY  ({len(usable)} found)", style="cyan"))
                    source_names: list[str] = []
                    for finding in usable:
                        meta = finding.get("metadata", {})
                        if not isinstance(meta, dict):
                            meta = {}
                        discovered = str(meta.get("discovered_email") or "").strip()
                        if not discovered:
                            continue
                        source_name = str(meta.get("source_name") or "").strip()
                        if source_name and source_name not in source_names:
                            source_names.append(source_name)
                        source_url = str(meta.get("source_url") or finding.get("profile_url") or "")
                        snippet = str(meta.get("snippet") or "").strip()
                        out.print(f"  [green]âœ“[/green] {discovered}")
                        if source_url:
                            out.print(f"    [dim]found at:[/dim] {_display_url(source_url)}")
                        if snippet:
                            out.print(f"    [dim]context:[/dim] \"{snippet}\"")
                        out.print()
                    if source_names:
                        names_text = ", ".join(f'"{name}"' for name in source_names)
                        out.print(f"  [dim]Discovered via name: {names_text}[/dim]")
                        out.print()

                def _module_meta(module_name: str) -> dict[str, Any]:
                    table = rep.get("metadata_table", {})
                    if isinstance(table, dict) and isinstance(table.get(module_name), dict):
                        return table[module_name]
                    for run in rep.get("module_runs", []):
                        if not isinstance(run, dict):
                            continue
                        if run.get("module_name") == module_name and isinstance(run.get("run_metadata"), dict):
                            return run["run_metadata"]
                    return {}

                def _date_year(value: Any) -> str:
                    text = str(value or "").strip()
                    return text[:4] if len(text) >= 4 else text

                def _date_month(value: Any) -> str:
                    text = str(value or "").strip()
                    return text[:7] if len(text) >= 7 else text

                def _render_wayback(findings: list[Any]) -> None:
                    usable = [f for f in findings if isinstance(f, dict)]
                    meta = _module_meta("wayback")
                    out.print(Rule(f"WAYBACK MACHINE  ({len(usable)} pages)", style="cyan"))
                    for finding in usable:
                        f_meta = finding.get("metadata", {})
                        if not isinstance(f_meta, dict):
                            f_meta = {}
                        domain = str(f_meta.get("original_domain") or "archived page")
                        archive_year = _date_year(f_meta.get("archive_date"))
                        snippet = str(f_meta.get("context_snippet") or "").strip()
                        title = str(f_meta.get("page_title") or "").strip()
                        archive = str(finding.get("profile_url") or "")
                        label = f"{domain} (archived {archive_year})" if archive_year else domain
                        out.print(f"  [green]✓[/green] {label}")
                        if snippet:
                            out.print(f"    \"{snippet}\"")
                        elif title:
                            out.print(f"    [dim]{title}[/dim]")
                        if archive:
                            out.print(f"    [dim]Archive:[/dim] {_display_url(archive, 80)}")
                        out.print()
                    first_seen = _date_year(meta.get("earliest_mention"))
                    last_seen = _date_year(meta.get("latest_mention"))
                    if first_seen or last_seen:
                        out.print(f"  [dim]First seen: {first_seen or '?'} · Last seen: {last_seen or '?'}[/dim]")
                        out.print()

                def _render_github_commits(findings: list[Any]) -> None:
                    usable = [f for f in findings if isinstance(f, dict)]
                    commits = [f for f in usable if f.get("platform") == "github_commit"]
                    users = [f for f in usable if f.get("platform") == "github_user"]
                    meta = _module_meta("github_commits")
                    out.print(Rule(f"GITHUB COMMITS  ({len(commits)} commits)", style="cyan"))
                    for finding in commits:
                        f_meta = finding.get("metadata", {})
                        if not isinstance(f_meta, dict):
                            f_meta = {}
                        repo = str(f_meta.get("repo") or "unknown/repo")
                        sha = str(f_meta.get("commit_sha") or "")
                        message = str(f_meta.get("commit_message") or "")
                        date = _date_month(f_meta.get("commit_date"))
                        language = str(f_meta.get("repo_language") or "Unknown")
                        stars = f_meta.get("repo_stars")
                        out.print(f"  [green]✓[/green] {repo}")
                        details = " · ".join(part for part in (sha, f'"{message}"' if message else "", date) if part)
                        if details:
                            out.print(f"    {details}")
                        out.print(f"    [dim]Language: {language} · ★ {stars if stars is not None else 0}[/dim]")
                        out.print()
                    for finding in users:
                        f_meta = finding.get("metadata", {})
                        if not isinstance(f_meta, dict):
                            f_meta = {}
                        login = str(f_meta.get("login") or "GitHub user")
                        profile_url = str(finding.get("profile_url") or "")
                        out.print(f"  [green]✓[/green] GitHub user: {login}")
                        if profile_url:
                            out.print(f"    [dim]{_display_url(profile_url, 80)}[/dim]")
                        out.print()
                    real_name = meta.get("real_name_from_git")
                    if real_name:
                        out.print(f"  [dim]Real name from git: {real_name}[/dim]")
                    earliest = _date_year(meta.get("earliest_commit"))
                    latest = _date_year(meta.get("latest_commit"))
                    primary_language = meta.get("primary_language")
                    active = f"{earliest}-{latest}" if earliest and latest else earliest or latest
                    if active or primary_language:
                        out.print(
                            f"  [dim]Active: {active or '?'} · Primary language: {primary_language or 'Unknown'}[/dim]"
                        )
                    if real_name or active or primary_language:
                        out.print()

                def _render_ransomware_intel(findings: list[Any]) -> None:
                    usable = [f for f in findings if isinstance(f, dict)]
                    out.print(Rule(f"RANSOMWARE INTEL  ({len(usable)} hits)", style="red"))
                    for finding in usable:
                        f_meta = finding.get("metadata", {})
                        group = str(f_meta.get("group_name") or "Unknown Group")
                        date = str(f_meta.get("attack_date") or "Unknown Date")
                        note = str(f_meta.get("note") or "")
                        domain = str(f_meta.get("domain") or "")
                        out.print(f"  [red]⚠[/red] {group} [dim]Date: {date} · Domain: {domain}[/dim]")
                        if note:
                            out.print(f"    [dim][yellow]{note}[/yellow][/dim]")
                    out.print()

                def _render_paste_exposure(findings: list[Any]) -> None:
                    usable = [f for f in findings if isinstance(f, dict)]
                    out.print(Rule(f"PASTE EXPOSURE  ({len(usable)} hits)", style="cyan"))
                    for finding in usable:
                        f_meta = finding.get("metadata", {})
                        source = str(f_meta.get("paste_source") or finding.get("platform") or "Paste")
                        date = f_meta.get("date")
                        emails = f_meta.get("email_count") or f_meta.get("emails_count")
                        date_str = f"Date: {_date_year(date) if date else 'Unknown'}"
                        email_str = f" · Emails: {emails}" if emails else ""
                        out.print(f"  [yellow]⚠[/yellow] {source[:30]:<30} [dim]{date_str}{email_str}[/dim]")
                    out.print()

                paste_findings = []
                for module_name, findings in findings_by_module.items():
                    paste_findings.extend([f for f in findings if isinstance(f, dict) and f.get("signal_type") == "paste_exposure"])
                
                if paste_findings:
                    _render_paste_exposure(paste_findings)

                for module_name, findings in findings_by_module.items():
                    non_paste_findings = [f for f in findings if not (isinstance(f, dict) and f.get("signal_type") == "paste_exposure")]
                    if not non_paste_findings:
                        continue

                    if module_name == "breach_deep":
                        _render_breach_deep(non_paste_findings)
                        continue
                    if module_name == "email_discovery":
                        _render_email_discovery(non_paste_findings)
                        continue
                    if module_name == "wayback":
                        _render_wayback(non_paste_findings)
                        continue
                    if module_name == "github_commits":
                        _render_github_commits(non_paste_findings)
                        continue
                    if module_name == "ransomware_intel":
                        _render_ransomware_intel(non_paste_findings)
                        continue
                    out.print(Rule(f"{_normalize_module_name(module_name)}  ({len(non_paste_findings)} hits)", style="cyan"))
                    for finding in non_paste_findings:
                        if not isinstance(finding, dict):
                            continue
                        confidence = str(finding.get("confidence", "")).lower()
                        severity = str(finding.get("severity", "")).lower()
                        symbol = "✓"
                        style = "green"
                        if confidence == "low":
                            symbol = "~"
                            style = "dim"
                        if severity == "critical":
                            symbol = "⚠"
                            style = "red"
                        platform, detail = _extract_finding_line(finding, module_name)
                        meta = finding.get("metadata", {})
                        if "common_variations" in meta:
                            detail = "→ " + ", ".join(meta["common_variations"])

                        if module_name in ("account_discovery", "user_scanner") or str(finding.get("source", "")) in ("account_discovery", "user_scanner"):
                            platform = platform.title()
                            detail_text = "[dim][email registration confirmed][/dim]"
                        elif module_name == "dns_lookup":
                            pt = str(finding.get("platform", ""))
                            if pt == "dns_mx" and meta.get("mx_provider"):
                                detail_text = f"MX: {meta.get('mx_provider')}"
                            elif pt == "dns_spf" and meta.get("spf_record"):
                                detail_text = f"SPF: {str(meta.get('spf_record'))[:40]}"
                            elif pt == "dns_dmarc" and meta.get("dmarc_policy"):
                                detail_text = f"DMARC: {meta.get('dmarc_policy')}"
                            elif pt == "dns_a" and meta.get("ip_address"):
                                detail_text = f"A: {meta.get('ip_address')}"
                            elif pt == "dns_ns" and meta.get("nameservers"):
                                ns = meta.get("nameservers")
                                ns_val = ns[0] if isinstance(ns, list) and ns else ns
                                detail_text = f"NS: {ns_val}"
                            elif pt == "dns_dkim" and meta.get("selector"):
                                detail_text = f"DKIM: selector={meta.get('selector')}"
                            else:
                                detail_text = "record found"
                        else:
                            detail_text = detail if detail else "account found"
                        
                        platform_label = f"{platform[:20]:<20}"
                        out.print(f"  [{style}]{symbol}[/{style}] {platform_label} {detail_text}")
                        metadata = []
                        for key in ("display_name", "username", "breach_name", "severity"):
                            value = finding.get(key)
                            if value:
                                metadata.append(f"{key}: {value}")
                        sources = finding.get("sources")
                        if isinstance(sources, list) and len(sources) > 1:
                            metadata.append(f"sources: {json.dumps(sources)}")
                        if confidence == "low":
                            metadata.append("low confidence")
                        if metadata:
                            out.print(f"    [dim][{' · '.join(metadata)}][/dim]")
                    out.print()
            else:
                out.print("[dim]No findings to display.[/]")

        def render_skipped(rep: dict[str, Any]) -> None:
            module_runs = rep.get("module_runs", [])
            skipped_runs = [r for r in module_runs if str(r.get("status", "")).lower() == "skipped"]
            
            groups = {
                "BREACH SOURCES": [
                    "hibp",
                    "haveibeenpwned",
                    "breachdirectory",
                    "hudson_rock",
                    "breach_deep",
                    "ransomware_intel",
                ],
                "RECON MODULES": ["dns_lookup", "whois_lookup", "domain_intel", "google_dork", "email_discovery", "wayback", "github_commits", "shodan", "hunter_io"],
                "OPTIONAL MODULES": ["ghunt", "user_scanner", "account_discovery", "whatsmyname", "username_pivot", "permutation_discovery", "phone_intel"]
            }
            
            key_hints = {
                "hibp": "set HIBP_API_KEY",
                "haveibeenpwned": "set HIBP_API_KEY",
                "breach_deep": "set ENABLE_BREACH_DEEP=true or use --modules breach_deep",
                "google_dork": "set SERPAPI_KEY",
                "email_discovery": "set SERPAPI_KEY",
                "github_commits": "set GITHUB_TOKEN for higher GitHub limits",
                "shodan": "set SHODAN_API_KEY",
                "domain_intel": "set SHODAN_API_KEY",
                "hunter_io": "set HUNTER_IO_API_KEY",
                "emailrep": "set EMAILREP_API_KEY",
                "ghunt": "run mailaccess keys set GHUNT_CREDS_PATH /path/to/creds"
            }

            for group_name, mods in groups.items():
                group_skipped = [r for r in skipped_runs if r.get("module_name", "unknown") in mods]
                if group_skipped:
                    out.print(Rule(group_name, style="dim"))
                    for run in group_skipped:
                        m_name = run.get("module_name", "unknown")
                        errors = run.get("errors") or []
                        hint = str(errors[0]) if errors else key_hints.get(m_name, "see docs")
                        if "api key" in str(run.get("error", "")).lower() or "api key" in hint.lower():
                            hint = key_hints.get(m_name, "missing api key")
                        if m_name == "whois_lookup" and "free provider" in hint.lower():
                            hint = "free email provider"
                        if len(hint) > 50:
                            hint = hint[:47] + "..."
                        out.print(f"  [dim]— {_normalize_module_name(m_name)}: skipped ({hint})[/dim]")
                    out.print()

            other_skipped = [r for r in skipped_runs if not any(r.get("module_name", "unknown") in g for g in groups.values())]
            if other_skipped:
                out.print(Rule("OTHER MODULES", style="dim"))
                for run in other_skipped:
                    m_name = run.get("module_name", "unknown")
                    errors = run.get("errors") or []
                    hint = str(errors[0]) if errors else key_hints.get(m_name, "see docs")
                    if "api key" in str(run.get("error", "")).lower() or "api key" in hint.lower():
                        hint = key_hints.get(m_name, "missing api key")
                    if m_name == "whois_lookup" and "free provider" in hint.lower():
                        hint = "free email provider"
                    if len(hint) > 50:
                        hint = hint[:47] + "..."
                    out.print(f"  [dim]— {_normalize_module_name(m_name)}: skipped ({hint})[/dim]")
                out.print()

            out.print("[dim]Legend: ✓ confirmed  ~ low confidence  — skipped[/dim]")
            out.print(f"[dim]💾 Save report: mailaccess investigate {email} -o report.pdf[/dim]")

        if cached:
            try:
                resp = await client.get(f"/api/report/{inv_id}", timeout=30)
                resp.raise_for_status()
                report_data = resp.json()
                status = report_data.get("status", status)
            except Exception:
                # Fallback to normal polling if immediate report fetch fails.
                status = "pending"

        _MAX_POLL_ATTEMPTS = 60  # 60 × 2 s = 120 s hard timeout

        if output_format not in ("json", "jsonl") and not cached:
            ws_base = base_url.replace("https://", "wss://").replace("http://", "ws://")
            ws_url = f"{ws_base}/ws/investigate/{inv_id}"
            err_console.print(f"[dim]Connecting: {ws_url}[/dim]")
            _ws_modules: dict[str, dict[str, Any]] = {}
            _live = None
            if output_format != "jsonl":
                _live = Live(_progress_table, console=out, refresh_per_second=4)
                _live.start()
                _live.update(update_progress_table({}))
            try:
                try:
                    async with websockets.connect(ws_url, open_timeout=10) as ws:
                        _deadline = asyncio.get_running_loop().time() + 360
                        while True:
                            remaining = _deadline - asyncio.get_running_loop().time()
                            if remaining <= 0:
                                err_console.print("[yellow]WS deadline reached (360 s), falling back to polling[/yellow]")
                                break
                            try:
                                raw = await asyncio.wait_for(ws.recv(), timeout=min(remaining, 150))
                            except asyncio.TimeoutError:
                                err_console.print("[yellow]WS receive timed out (150 s), falling back to polling[/yellow]")
                                break
                            event = json.loads(raw)
                            ev_type = event.get("type")
                            if ev_type == "module_start":
                                mod = event.get("module", "unknown")
                                _ws_modules[mod] = {"module_name": mod, "status": "running", "started_at": event.get("timestamp")}
                            elif ev_type in ("module_result", "module_error"):
                                mod = event.get("module", "unknown")
                                if mod not in _ws_modules:
                                    _ws_modules[mod] = {"module_name": mod}
                                _ws_modules[mod]["status"] = event.get("status", "complete")
                                _ws_modules[mod]["completed_at"] = datetime.now(timezone.utc).isoformat()
                                # JSONL is emitted from the final merged report below so
                                # breach findings only appear once, with the richest metadata.
                            elif ev_type == "investigation_complete":
                                status = "complete"
                            if _ws_modules and _live:
                                _live.update(update_progress_table({"module_runs": list(_ws_modules.values())}))
                            if status == "complete":
                                with contextlib.suppress(Exception):
                                    resp = await client.get(f"/api/report/{inv_id}", timeout=30)
                                    resp.raise_for_status()
                                    report_data = resp.json()
                                break
                except Exception as _ws_exc:
                    err_console.print(f"[yellow]WS unavailable, falling back to polling ({_ws_exc})[/yellow]")
                    err_console.print(f"[dim]Tried: {ws_url}[/dim]")
                    err_console.print("[dim]Is the backend running?[/dim]")
                if status not in ("complete", "failed"):
                    _attempts = 0
                    while status not in ("complete", "failed"):
                        if _attempts >= _MAX_POLL_ATTEMPTS:
                            err_console.print("[red]Timed out waiting for investigation to complete (120 s)[/red]")
                            return 3
                        await asyncio.sleep(2)
                        _attempts += 1
                        with contextlib.suppress(Exception):
                            resp = await client.get(f"/api/report/{inv_id}")
                            resp.raise_for_status()
                            report_data = resp.json()
                            status = report_data.get("status", status)
                            if _live:
                                _live.update(update_progress_table(report_data))
            finally:
                if _live:
                    _live.stop()
        else:
            _attempts = 0
            while status not in ("complete", "failed"):
                if _attempts >= _MAX_POLL_ATTEMPTS:
                    err_console.print("[red]Timed out waiting for investigation to complete (120 s)[/red]")
                    return 3
                await asyncio.sleep(2)
                _attempts += 1
                with contextlib.suppress(Exception):
                    resp = await client.get(f"/api/report/{inv_id}")
                    resp.raise_for_status()
                    report_data = resp.json()
                    status = report_data.get("status", status)

        if output_format not in ("json", "jsonl") and cached:
            module_runs = report_data.get("module_runs", [])
            statuses = [
                f"{run.get('module_name', 'unknown')}:{str(run.get('status', 'unknown')).upper()}"
                for run in module_runs
            ]
            if statuses:
                out.print(f"[dim]Modules: {', '.join(statuses)}[/dim]")

        if not report_data:
            try:
                resp = await client.get(f"/api/report/{inv_id}", timeout=30)
                resp.raise_for_status()
                report_data = resp.json()
            except Exception as _e:
                out.print(f"[red]Error:[/] Could not fetch report: {_e}")
                return 3
        if not report_data:
            out.print("[red]Error:[/] Report is empty — investigation may have failed.")
            return 3

        if output_file:
            ext = Path(output_file).suffix.lower()
            if ext not in _EXPORT_FORMATS:
                out.print(f"[red]Unsupported extension:[/] {ext}. Supported: {', '.join(sorted(_EXPORT_FORMATS))}")
            else:
                fmt = ext.lstrip(".")
                try:
                    export_resp = await client.get(
                        f"/api/report/{inv_id}/export",
                        params={"format": fmt},
                    )
                    export_resp.raise_for_status()
                    Path(output_file).write_bytes(export_resp.content)
                    out.print(f"[green]✓ Report saved to {output_file}[/green]")
                except Exception as e:
                    out.print(f"[red]Failed to save report:[/] {e}")

        # Determine exit code
        findings_count = len(report_data.get("findings", []))
        breaches_found = False
        for f in report_data.get("findings", []):
            if isinstance(f, dict):
                src = str(f.get("source", "")).lower()
                plat = str(f.get("platform", "")).lower()
                mod = str(f.get("module_name", "")).lower()
                breach_markers = (
                    "hibp",
                    "breachdirectory",
                    "hudson_rock",
                    "haveibeenpwned",
                    "breach_deep",
                )
                if any(marker in (src, plat, mod) for marker in breach_markers):
                    breaches_found = True
                    break
        
        exit_code = 0
        if breaches_found:
            exit_code = 2
        elif findings_count > 0:
            exit_code = 1

        if output_format == "jsonl":
            for mod, findings in report_data.get("findings_by_module", {}).items():
                for f in findings:
                    if not isinstance(f, dict):
                        continue
                    finding_obj = {
                        "email": email,
                        "investigation_id": inv_id,
                        "module": mod,
                        "platform": str(
                            f.get("platform")
                            or f.get("service")
                            or f.get("source")
                            or f.get("site")
                            or mod
                        ),
                        "profile_url": str(
                            f.get("url") or f.get("profile_url") or f.get("link") or ""
                        ),
                        "confidence": f.get("confidence", "unknown"),
                        "severity": f.get("severity", "info"),
                        "metadata": {
                            k: v
                            for k, v in f.items()
                            if k
                            not in (
                                "platform",
                                "service",
                                "source",
                                "site",
                                "url",
                                "profile_url",
                                "link",
                                "confidence",
                                "severity",
                            )
                        },
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    sys.stdout.write(json.dumps(finding_obj) + "\n")
            sys.stdout.flush()
            score = _get_score(report_data)
            risk = _get_risk(report_data)
            credential_score = _get_credential_score(report_data)
            credential_band = _get_credential_band(report_data)
            sys.stdout.write(json.dumps({
                "type": "complete",
                "email": email,
                "canonical_email": report_data.get("canonical_email"),
                "score": score,
                "risk": risk,
                "credential_risk_score": credential_score,
                "credential_risk_band": credential_band,
                "total_findings": findings_count
            }) + "\n")
            sys.stdout.flush()
            return exit_code

        if output_format == "json":
            console.print_json(json.dumps(report_data, indent=2))
            return exit_code

        async def render_clusters_output() -> None:
            discovered_emails = _get_discovered_emails(report_data)
            consensus = _name_consensus(report_data)
            confirmed_name = str(consensus.get("confirmed_name") or "").strip()
            name_confidence = str(consensus.get("name_confidence") or "unknown").lower()
            reasoning = str(consensus.get("name_reasoning") or "").strip()
            inference_skipped = (
                reasoning == "Role/system email address — name inference skipped"
            )
            show_name_consensus = bool(
                (confirmed_name and name_confidence != "unknown") or inference_skipped
            )
            try:
                resp = await client.get(f"/api/report/{inv_id}/clusters", timeout=30)
                resp.raise_for_status()
                data = resp.json()
                clusters = data.get("clusters", [])
                if not clusters and not discovered_emails and not show_name_consensus:
                    return
            except httpx.TimeoutException:
                out.print(
                    f"[dim]Identity analysis unavailable (large investigation — view at /investigation/{inv_id}/graph)[/dim]"
                )
                return
            except Exception:
                return
                
            out.print(Rule("IDENTITY ANALYSIS", style="bold blue"))
            out.print()

            if show_name_consensus:
                sources = _format_name_sources(consensus.get("name_sources"))
                conflict = "conflict" in reasoning.lower()
                label = name_confidence.upper()
                if conflict:
                    label += " - conflict"
                title = (
                    "NAME INFERENCE SKIPPED"
                    if inference_skipped
                    else
                    "CONFIRMED IDENTITY"
                    if name_confidence in ("confirmed", "probable")
                    else "POSSIBLE IDENTITY"
                )
                out.print(f"  [bold cyan]{title}[/bold cyan]")
                if confirmed_name:
                    out.print(f"    {'Name:':<10} {confirmed_name}  [bold][{label}][/bold]")
                if sources:
                    out.print(f"    {'Sources:':<10} {sources}")
                if reasoning:
                    field = (
                        "Reasoning:"
                        if name_confidence in ("confirmed", "probable")
                        else "Note:"
                    )
                    out.print(f"    {field:<10} {reasoning}")
                out.print()
            
            for i, cluster in enumerate(clusters or [], 1):
                conf = cluster.get("confidence", 0.0)
                label = cluster.get("label", "unknown")
                reasoning = cluster.get("reasoning", [])
                findings = cluster.get("findings", [])
                is_col = cluster.get("is_collision", False)
                
                out.print(f"  [bold]IDENTITY {i}[/] — {label}  [dim][confidence: {conf:.2f}][/dim]")
                for reason in reasoning:
                    out.print(f"    [dim]\"{reason}\"[/dim]")
                out.print()
                
                if is_col and not show_collisions:
                    out.print(f"    [dim]~ {len(findings)} platforms with bare username match[/dim]")
                    out.print("      [dim](use --show-collisions to expand)[/dim]")
                    out.print()
                    continue
                    
                shown = 0
                for finding in findings:
                    item = finding.get("data", finding)
                    mod_name = finding.get("module_name", "unknown")
                    platform, detail = _extract_finding_line(item, mod_name)
                    
                    detail_text = detail
                    if mod_name in ("account_discovery", "user_scanner") or str(item.get("source", "")) in ("account_discovery", "user_scanner"):
                        platform = platform.title()
                        detail_text = "[email registration confirmed]"
                        
                    p_label = f"{platform[:16]:<16}"
                    out.print(f"    [green]✓[/green] {p_label} [dim]{detail_text}[/dim]")
                    shown += 1
                    if not is_col and shown >= 5 and len(findings) > 5:
                        out.print(f"    [dim]+ {len(findings) - 5} more accounts[/dim]")
                        break
                out.print()
            alt_emails = _get_alternate_emails(report_data)
            all_other = list(discovered_emails)
            for f in alt_emails:
                e = f.get("metadata", {}).get("discovered_email")
                if e and e not in all_other:
                    all_other.append(e)
            
            if all_other:
                out.print("  [cyan]→ Other emails found:[/cyan]")
                for discovered in all_other:
                    out.print(f"    {discovered}")
                out.print(
                    f"  [dim]Run: mailaccess investigate {all_other[0]} "
                    "to continue investigation[/dim]"
                )
                out.print()
                
            if alt_emails:
                out.print(Rule(f"ALTERNATE EMAILS  ({len(alt_emails)} found)", style="bold cyan"))
                for f in alt_emails:
                    meta = f.get("metadata", {})
                    disc_email = meta.get("discovered_email", "unknown")
                    conf = str(f.get("confidence", "unknown")).upper()
                    source = meta.get("source", "unknown")
                    source_detail = meta.get("source_detail", "")
                    reason = meta.get("reason", "")
                    
                    symbol = "✓" if conf == "HIGH" else "~"
                    style = "green" if conf == "HIGH" else "yellow"
                    
                    out.print(f"  [{style}]{symbol}[/{style}] {disc_email:<29} {conf}")
                    source_text = f"Source: {_normalize_module_name(source)}"
                    if source_detail:
                        source_text += f" ({source_detail})"
                    out.print(f"    [dim]{source_text}[/dim]")
                    if reason:
                        out.print(f"    [dim]\"{reason}\"[/dim]")
                    out.print()
                out.print("  [dim]These emails belong to the same person.")
                out.print("  Run mailaccess investigate <email> on each.[/dim]")
                out.print()
            
            if not all_other and not alt_emails:
                out.print()

        def render_profile_intelligence(rep: dict[str, Any]) -> None:
            fbm = rep.get("findings_by_module", {})

            # --- GitHub profile ---
            gh_findings = [
                f for f in fbm.get("github_commits", [])
                if isinstance(f, dict) and f.get("platform") == "github_user"
            ]
            gh_profile: dict[str, Any] = {}
            if gh_findings:
                gh_profile = gh_findings[0].get("metadata", {}) or {}

            # --- Gravatar profile ---
            grav_findings = [
                f for f in fbm.get("gravatar", [])
                if isinstance(f, dict) and f.get("platform") == "gravatar_profile"
            ]
            grav_profile: dict[str, Any] = {}
            if grav_findings:
                grav_profile = grav_findings[0].get("metadata", {}) or {}

            # --- Keybase profile ---
            kb_findings = [
                f for f in fbm.get("keybase", [])
                if isinstance(f, dict) and f.get("platform") == "keybase_profile"
            ]
            kb_profile: dict[str, Any] = {}
            if kb_findings:
                kb_profile = kb_findings[0].get("metadata", {}) or {}

            # --- PyPI packages ---
            pypi_findings = [
                f for f in fbm.get("pypi_discovery", [])
                if isinstance(f, dict) and f.get("signal_type") == "package_authorship"
            ]

            # --- npm packages ---
            npm_findings = [
                f for f in fbm.get("npm_discovery", [])
                if isinstance(f, dict) and f.get("signal_type") == "package_authorship"
            ]

            # --- Twitter/X profile ---
            tw_findings = [
                f for f in fbm.get("twitter_profile", [])
                if isinstance(f, dict) and f.get("platform") == "twitter_profile"
            ]
            tw_profile: dict[str, Any] = {}
            if tw_findings:
                tw_profile = tw_findings[0].get("metadata", {}) or {}

            # --- LinkedIn SERP snippet ---
            li_findings = [
                f for f in fbm.get("linkedin_serp", [])
                if isinstance(f, dict) and f.get("platform") == "linkedin_snippet"
            ]
            li_profile: dict[str, Any] = {}
            if li_findings:
                li_profile = li_findings[0].get("metadata", {}) or {}

            # --- Marketplace profiles ---
            etsy_findings = [
                f for f in fbm.get("marketplace_profile", [])
                if isinstance(f, dict) and f.get("platform") == "etsy_shop"
            ]
            etsy_profile: dict[str, Any] = {}
            if etsy_findings:
                etsy_profile = etsy_findings[0].get("metadata", {}) or {}

            ebay_findings = [
                f for f in fbm.get("marketplace_profile", [])
                if isinstance(f, dict) and f.get("platform") == "ebay_profile"
            ]
            ebay_profile: dict[str, Any] = {}
            if ebay_findings:
                ebay_profile = ebay_findings[0].get("metadata", {}) or {}

            has_content = any([
                gh_profile, grav_profile, kb_profile,
                pypi_findings, npm_findings,
                tw_profile, li_profile, etsy_profile, ebay_profile,
            ])
            if not has_content:
                return

            out.print(Rule("PROFILE INTELLIGENCE", style="bold cyan"))
            out.print()

            if gh_profile:
                login = str(gh_profile.get("login") or "")
                label = f"GitHub ({login})" if login else "GitHub"
                out.print(f"  [bold cyan]{label}[/bold cyan]")
                for field_key, field_label in (
                    ("name", "Name"),
                    ("company", "Company"),
                    ("location", "Location"),
                    ("blog", "Website"),
                    ("twitter_username", "Twitter"),
                    ("public_email", "Email"),
                ):
                    val = str(gh_profile.get(field_key) or "").strip()
                    if val:
                        out.print(f"    {field_label:<10} {val}")
                repos = int(gh_profile.get("public_repos") or 0)
                followers = int(gh_profile.get("followers") or 0)
                if repos or followers:
                    out.print(f"    [dim]{repos} repos · {followers} followers[/dim]")
                created = str(gh_profile.get("created_at") or "")[:4]
                if created:
                    out.print(f"    [dim]Joined: {created}[/dim]")
                out.print()

            if grav_profile:
                grav_name = str(grav_profile.get("username") or grav_profile.get("name") or "")
                label = f"Gravatar ({grav_name})" if grav_name else "Gravatar"
                out.print(f"  [bold cyan]{label}[/bold cyan]")
                for field_key, field_label in (
                    ("name", "Name"),
                    ("location", "Location"),
                    ("bio", "Bio"),
                ):
                    val = str(grav_profile.get(field_key) or "").strip()
                    if val:
                        display = val[:60] + "..." if len(val) > 60 else val
                        out.print(f"    {field_label:<10} {display}")
                verified = grav_profile.get("verified_accounts")
                if isinstance(verified, list) and verified:
                    out.print(f"    Verified:  {', '.join(str(v) for v in verified[:8])}")
                out.print()

            if kb_profile:
                kb_user = str(kb_profile.get("username") or "")
                label = f"Keybase ({kb_user})" if kb_user else "Keybase"
                out.print(f"  [bold cyan]{label}[/bold cyan]")
                for field_key, field_label in (
                    ("name", "Name"),
                    ("location", "Location"),
                    ("bio", "Bio"),
                    ("twitter", "Twitter"),
                    ("github", "GitHub"),
                ):
                    val = str(kb_profile.get(field_key) or "").strip()
                    if val:
                        out.print(f"    {field_label:<10} {val}")
                proofs = kb_profile.get("verified_proofs")
                if isinstance(proofs, list) and proofs:
                    proof_str = ", ".join(
                        f"{p} [green]✓[/green]" for p in dict.fromkeys(proofs)
                    )
                    out.print(f"    Verified:  {proof_str}")
                out.print()

            if pypi_findings:
                out.print(f"  [bold cyan]PyPI packages: {len(pypi_findings)} found[/bold cyan]")
                parts: list[str] = []
                for f in pypi_findings[:6]:
                    meta = f.get("metadata", {}) or {}
                    pkg = str(meta.get("package_name") or "")
                    role = str(meta.get("role") or "")
                    if pkg:
                        parts.append(f"{pkg} ({role})" if role else pkg)
                if parts:
                    out.print(f"    {', '.join(parts)}")
                out.print()

            if npm_findings:
                out.print(f"  [bold cyan]npm packages: {len(npm_findings)} found[/bold cyan]")
                parts2: list[str] = []
                for f in npm_findings[:6]:
                    meta = f.get("metadata", {}) or {}
                    pkg = str(meta.get("package_name") or "")
                    role = str(meta.get("role") or "")
                    if pkg:
                        parts2.append(f"{pkg} ({role})" if role else pkg)
                if parts2:
                    out.print(f"    {', '.join(parts2)}")
                out.print()

            if tw_profile:
                tw_user = str(
                    tw_profile.get("username")
                    or (tw_findings[0].get("username") if tw_findings else "")
                    or ""
                )
                note = str(tw_profile.get("note") or "")
                blocked = "existence_only" in str(tw_profile.get("extraction_method") or "")
                label = f"Twitter/X (@{tw_user})" if tw_user else "Twitter/X"
                out.print(f"  [bold cyan]{label}[/bold cyan]")
                if blocked:
                    out.print(f"    [dim]{note or 'Profile data unavailable without authentication'}[/dim]")
                else:
                    for field_key, field_label in (
                        ("display_name", "Name"),
                        ("bio", "Bio"),
                        ("location", "Location"),
                        ("website", "Website"),
                        ("join_date", "Joined"),
                    ):
                        val = str(tw_profile.get(field_key) or "").strip()
                        if val:
                            display = val[:60] + "..." if len(val) > 60 else val
                            out.print(f"    {field_label:<10} {display}")
                    followers = tw_profile.get("followers_count")
                    following = tw_profile.get("following_count")
                    if followers is not None or following is not None:
                        out.print(
                            f"    [dim]Followers: {followers or 0} · "
                            f"Following: {following or 0}[/dim]"
                        )
                out.print()

            if li_profile:
                li_url = str(li_profile.get("linkedin_url") or "")
                slug = li_url.rstrip("/").rsplit("/", 1)[-1] if li_url else ""
                label = f"LinkedIn ({slug})" if slug else "LinkedIn"
                out.print(f"  [bold cyan]{label}[/bold cyan]")
                for field_key, field_label in (
                    ("display_name", "Name"),
                    ("headline", "Headline"),
                    ("employer", "Employer"),
                    ("location", "Location"),
                ):
                    val = str(li_profile.get(field_key) or "").strip()
                    if val:
                        out.print(f"    {field_label:<10} {val}")
                if li_url:
                    out.print(f"    [dim]{_display_url(li_url)}[/dim]")
                out.print(
                    "    [dim yellow][medium confidence — from search snippet][/dim yellow]"
                )
                out.print()

            if etsy_profile:
                shop = str(etsy_profile.get("shop_name") or etsy_profile.get("username") or "")
                label = f"Etsy Shop ({shop})" if shop else "Etsy Shop"
                out.print(f"  [bold cyan]{label}[/bold cyan]")
                for field_key, field_label in (
                    ("owner_name", "Owner"),
                    ("location", "Location"),
                    ("member_since", "Member"),
                ):
                    val = str(etsy_profile.get(field_key) or "").strip()
                    if val:
                        out.print(f"    {field_label:<10} {val}")
                sales = etsy_profile.get("sales_count")
                if sales is not None:
                    out.print(f"    [dim]{sales:,} sales[/dim]")
                out.print()

            if ebay_profile:
                ebay_user_str = str(ebay_profile.get("username") or "")
                label = f"eBay ({ebay_user_str})" if ebay_user_str else "eBay"
                out.print(f"  [bold cyan]{label}[/bold cyan]")
                for field_key, field_label in (
                    ("location", "Location"),
                    ("member_since", "Member"),
                ):
                    val = str(ebay_profile.get(field_key) or "").strip()
                    if val:
                        out.print(f"    {field_label:<10} {val}")
                score = ebay_profile.get("feedback_score")
                if score is not None:
                    top = " · Top Rated" if ebay_profile.get("top_rated_seller") else ""
                    out.print(f"    [dim]Feedback: {score}{top}[/dim]")
                out.print()

        def render_pii_findings(rep: dict[str, Any]) -> None:
            pii_items: list[tuple[str, str, str, str]] = []  # (type, value, confidence, source_label)

            # Scan all findings for PII signal types
            for module_name, findings in rep.get("findings_by_module", {}).items():
                for f in findings:
                    if not isinstance(f, dict):
                        continue
                    sig = str(f.get("signal_type") or "")
                    meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
                    conf = str(f.get("confidence") or "medium").upper()
                    source_field = str(meta.get("source_field") or "")
                    source_platform = str(meta.get("source_platform") or module_name)
                    source_label = f"{source_platform} {source_field}".strip().title()

                    if sig == "phone_in_bio":
                        phone = str(meta.get("phone") or "").strip()
                        if phone:
                            pii_items.append(("phone", phone, conf, source_label))
                    elif sig == "phone_number":
                        phone = str(meta.get("phone") or meta.get("phone_number") or "").strip()
                        if phone:
                            label_map = {
                                "whois_lookup": "WHOIS registrant",
                                "whois_phone": "WHOIS registrant",
                                "press_intel": "Press release",
                                "sec_edgar": "SEC EDGAR",
                            }
                            platform = str(f.get("platform") or "").strip().lower()
                            label = label_map.get(platform) or label_map.get(module_name, source_label)
                            pii_items.append(("phone", phone, conf, label))
                    elif sig == "email_in_bio":
                        discovered = str(meta.get("email") or "").strip()
                        if discovered:
                            pii_items.append(("email", discovered, conf, source_label))
                    elif sig == "company_registration" and module_name == "companies_house":
                        addr = str(meta.get("registered_address") or "").strip()
                        company = str(meta.get("company_name") or "").strip()
                        if addr:
                            label = f"Companies House - {company}" if company else "Companies House"
                            pii_items.append(("address", addr, conf, label))

            # OpenCorporates addresses
            for f in rep.get("findings_by_module", {}).get("opencorporates", []):
                if not isinstance(f, dict):
                    continue
                meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
                addr = str(meta.get("registered_address") or "").strip()
                company = str(meta.get("company_name") or "").strip()
                if addr:
                    label = f"OpenCorporates — {company}" if company else "OpenCorporates"
                    pii_items.append(("address", addr, "MEDIUM", label))

            if not pii_items:
                return

            out.print(Rule("PII EXTRACTED", style="bold yellow"))
            out.print()
            for pii_type, value, conf, source_label in pii_items:
                conf_color = "green" if conf == "HIGH" else "yellow"
                if pii_type == "phone":
                    icon = "📞"
                elif pii_type == "address":
                    icon = "📍"
                else:
                    icon = "✉"
                out.print(
                    f"  {icon} [bold]{value}[/bold]   [{conf_color}][{conf}][/{conf_color}] {source_label}"
                )
            out.print()

        out.print("\n[bold green]Investigation Complete[/]\n")
        render_credibility_banner(report_data)
        render_summary(report_data)
        if not no_brief:
            render_defenders_brief(report_data)
        await render_clusters_output()
        render_profile_intelligence(report_data)
        render_pii_findings(report_data)
        render_timeline(report_data)
        out.print(Rule("Full Results", style="bold"))
        render_findings(report_data)
        render_skipped(report_data)

    return exit_code


@app.command()
def investigate(
    email: str = typer.Argument(..., help="Email address to investigate."),
    output_format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table|json|jsonl"
    ),
    modules: str = typer.Option(
        None, "--modules", help="Comma-separated list of modules to run."
    ),
    timeout: int = typer.Option(
        30, "--timeout", "-t", help="Timeout in seconds for API calls."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save report to file (.json .csv .md .pdf .stix .mtgx)"
    ),
    force: bool = typer.Option(
        False, "--force", help="Bypass recent-result cache and re-run all modules."
    ),
    show_collisions: bool = typer.Option(
        False, "--show-collisions", help="Expands collision clusters in output."
    ),
    enable: str = typer.Option(
        None, "-m", "--enable",
        help="Enable opt-in modules for this run. Comma-separated or 'all'. Example: -m breach_deep,whatsmyname"
    ),
    no_brief: bool = typer.Option(
        False, "--no-brief", help="Suppress the Defender's Brief section."
    ),
) -> None:
    """Run a full OSINT investigation against an email address.
    Exit codes: 0=clean 1=findings 2=breaches 3=error"""
    if email == "-":
        emails = [l.strip() for l in sys.stdin if l.strip() and not l.startswith("#")]
    else:
        emails = [email]

    # Route bare filenames (no directory component) into results/
    if output_file and Path(output_file).parent == Path("."):
        results_dir = Path(__file__).resolve().parent.parent / "results"
        results_dir.mkdir(exist_ok=True)
        output_file = str(results_dir / output_file)

    max_code = 0
    for i, target_email in enumerate(emails):
        if i > 0 and output_format not in ("json", "jsonl"):
            err_console.print("━" * 80)
        code = asyncio.run(_investigate(target_email, output_format, modules, timeout, output_file, force, show_collisions, enable, no_brief))
        if code > max_code:
            max_code = code

    sys.exit(max_code)


# ── History ───────────────────────────────────────────────────────────────────

@app.command()
def history(
    page: int = typer.Option(1, help="Page number"),
    page_size: int = typer.Option(20, help="Items per page"),
    timeout: int = typer.Option(10, help="Timeout in seconds"),
) -> None:
    """List past investigations."""
    asyncio.run(_history(page, page_size, timeout))


async def _history(page: int, page_size: int, timeout: int) -> None:
    base_url = get_backend_url()
    async with httpx.AsyncClient(base_url=base_url, timeout=timeout) as client:
        try:
            resp = await client.get(
                "/api/investigations", params={"page": page, "page_size": page_size}
            )
            resp.raise_for_status()
            data = resp.json()
        except httpx.ConnectError:
            console.print("[red]Error:[/] cannot connect to MailAccess server", style="bold red")
            raise typer.Exit(1)
        except Exception as e:
            console.print(f"[red]Error:[/] {e}", style="bold red")
            raise typer.Exit(1)

    table = Table(title=f"Past Investigations (Page {data['page']}/{data['pages']})")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Email")
    table.add_column("Status")
    table.add_column("Score", justify="right")
    table.add_column("Created At")

    for item in data.get("items", []):
        status = item.get("status", "unknown")
        color = get_status_color(status)
        score = item.get("exposure_score")
        score_str = str(score) if score is not None else "-"
        table.add_row(
            item.get("id"),
            item.get("email"),
            f"[{color}]{status}[/]",
            score_str,
            item.get("created_at"),
        )

    console.print(table)


if __name__ == "__main__":
    app()
