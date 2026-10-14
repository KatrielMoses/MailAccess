"""Partner placements — one disclosed, throttled one-liner per surface.

Every placement renders the same shape::

    Partner · <Name> - <tagline> → <domain>

The literal ``Partner ·`` prefix is the disclosure and always stays. Lines go
to an interactive terminal only: they are suppressed when the console is not a
TTY (piped / redirected), when ``--no-banner`` was passed, or in CI, so logs,
pipes and exports never carry them. ``NO_COLOR`` keeps the line but drops all
styling (no colour, no hyperlink escapes).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.style import Style
from rich.text import Text


@dataclass(frozen=True)
class Partner:
    name: str
    tagline: str
    domain: str
    color: str
    # Named ANSI colour for 16-colour terminals, where Rich's nearest-match
    # downgrade of the hex can land on the wrong hue (amber → red).
    low_color: str
    url_override: str = ""

    @property
    def url(self) -> str:
        return self.url_override or f"https://{self.domain}"


# Integration credits only ("enriched by ..."). Paid placements (banner, proxy
# prompts) come from the remote sponsor feed in cli/sponsor_feed.py.
NETLAS = Partner(
    name="Netlas",
    tagline="internet-wide recon data we lean on",
    domain="netlas.io",
    color="#5BA4F5",
    low_color="bright_blue",
)
IPGEO = Partner(
    name="ipgeolocation.io",
    tagline="location, owner and risk context for IPs",
    domain="ipgeolocation.io",
    color="#51BFA5",
    low_color="green",
)

_no_banner = False
_shown_surfaces: set[str] = set()


def set_no_banner(flag: bool) -> None:
    """Record the global ``--no-banner`` flag (set once by the CLI callback)."""
    global _no_banner
    _no_banner = bool(flag)


def _env_flag(name: str) -> bool:
    value = os.environ.get(name)
    return value is not None and value.strip().lower() not in ("", "0", "false", "no")


def _no_color() -> bool:
    # https://no-color.org — any non-empty value disables colour.
    return bool(os.environ.get("NO_COLOR"))


def placements_enabled(console: Console) -> bool:
    """True when a partner line may be shown on *console* at all."""
    if _no_banner or _env_flag("CI"):
        return False
    return console.is_terminal


def _name_color(partner: Partner, console: Console | None) -> str:
    if console is not None and console.color_system in ("standard", "windows"):
        return partner.low_color
    return partner.color


def render_line(partner: Partner, *, plain: bool = False, console: Console | None = None) -> Text:
    """Build the one-liner; *plain* drops every style and the hyperlink."""
    if plain:
        return Text(f"Partner · {partner.name} - {partner.tagline} → {partner.domain}")
    line = Text()
    line.append("Partner · ", style="dim")
    line.append(partner.name, style=Style(color=_name_color(partner, console), bold=True))
    line.append(f" - {partner.tagline} ", style="dim")
    line.append(f"→ {partner.domain}", style=Style(link=partner.url))
    return line


def show(partner: Partner, console: Console, *, surface: str) -> bool:
    """Print *partner*'s line once per *surface* per process. Returns True if shown."""
    if surface in _shown_surfaces or not placements_enabled(console):
        return False
    _shown_surfaces.add(surface)
    console.print(
        render_line(partner, plain=_no_color(), console=console),
        highlight=False,
        soft_wrap=True,
    )
    return True


def _banner_partner_line(
    partner: Partner,
    *,
    plain: bool,
    console: Console | None,
) -> Text:
    """One partner row for the banner panel — name is the link, no trailing URL."""
    if plain:
        return Text(f"  Partner · {partner.name}  {partner.tagline}")
    line = Text()
    line.append("  Partner · ", style=Style(color="#888888"))
    line.append(
        partner.name,
        style=Style(
            color=_name_color(partner, console),
            bold=True,
            underline=True,
            link=partner.url,
        ),
    )
    line.append(f"  {partner.tagline}", style=Style(color="#AAAAAA"))
    return line


def show_banner_footer(console: Console) -> None:
    """Bordered partner panel under the interactive banner, once per process."""
    if "banner:sponsors" in _shown_surfaces or not placements_enabled(console):
        return
    _shown_surfaces.add("banner:sponsors")
    from cli import sponsor_feed

    sponsors = sponsor_feed.for_surface("cli.banner")
    if not sponsors:
        return

    plain = _no_color()

    body = Text()
    for index, sponsor in enumerate(sponsors):
        if index:
            body.append("\n")
        body.append_text(_banner_partner_line(sponsor, plain=plain, console=console))

    if plain:
        console.print(Panel(body, expand=False, padding=(0, 1)), highlight=False)
    else:
        console.print(
            Panel(
                body,
                border_style=Style(color="#444444"),
                expand=False,
                padding=(0, 1),
            ),
            highlight=False,
        )


def show_netlas_credit(console: Console) -> bool:
    """Result footer for a run Netlas actually contributed to."""
    if "netlas-credit" in _shown_surfaces or not placements_enabled(console):
        return False
    _shown_surfaces.add("netlas-credit")
    if _no_color():
        console.print(Text(f"✓ enriched by Netlas.io → {NETLAS.domain}"), highlight=False)
        return True
    line = Text()
    line.append("✓ enriched by ", style="dim")
    line.append("Netlas.io", style=Style(color=_name_color(NETLAS, console)))
    line.append(f" → {NETLAS.domain}", style=Style(dim=True, link=NETLAS.url))
    console.print(line, highlight=False)
    return True


def proxy_configured(settings: object) -> bool:
    """True when a ScrapingAnt proxy transport has usable credentials."""
    if not bool(getattr(settings, "scrapingant_enabled", False)):
        return False
    pairs = (
        ("scrapingant_proxy_residential_username", "scrapingant_proxy_residential_password"),
        ("scrapingant_proxy_datacenter_username", "scrapingant_proxy_datacenter_password"),
    )
    return any(
        str(getattr(settings, user, "") or "").strip()
        and str(getattr(settings, pw, "") or "").strip()
        for user, pw in pairs
    )


def show_proxy_sponsor(console: Console) -> bool:
    """Contextual proxy-partner line — proxy wizard, unconfigured --use-proxies, big runs."""
    if "proxy:sponsor" in _shown_surfaces or not placements_enabled(console):
        return False
    from cli import sponsor_feed

    sponsors = sponsor_feed.for_surface("cli.proxy")
    return bool(sponsors) and show(sponsors[0], console, surface="proxy:sponsor")


def _reset_for_tests() -> None:
    global _no_banner
    _no_banner = False
    _shown_surfaces.clear()


def show_ipgeo_result(
    console: Console,
    findings: list,
    *,
    infrastructure: dict | None = None,
    email: str | None = None,
) -> bool:
    """Disclosed result credit or keyless nudge, with the shared placement rules."""
    if not placements_enabled(console):
        return False
    from backend.config import settings
    from backend.core.ipgeo_client import public_ips

    rows = (infrastructure or {}).get("ips", [])
    data = [f.get("data", f) for f in findings if isinstance(f, dict)]
    contributed = any(row.get("tier") for row in rows) or any(
        f.get("platform") == "ip_intel" for f in data
    )
    if contributed:
        if "ipgeo-credit" in _shown_surfaces:
            return False
        _shown_surfaces.add("ipgeo-credit")
        line = Text("✓ enriched by ipgeolocation.io → ipgeolocation.io")
        if not _no_color():
            line.stylize(Style(color=_name_color(IPGEO, console), link=IPGEO.url))
        console.print(line, highlight=False)
        return True
    if settings.ipgeolocation_api_key:
        return False
    from backend.modules.domain_intel import _FREE_PROVIDERS

    free_provider = bool(email and email.rsplit("@", 1)[-1].lower() in _FREE_PROVIDERS)
    raw = [row.get("ip") for row in rows]
    for finding in data:
        if free_provider and finding.get("platform") == "dns_a":
            continue
        meta = finding.get("metadata") or {}
        raw.append(meta.get("ip_address") or meta.get("ip"))
        raw.extend(
            row.get("ip_address") or row.get("ip")
            for row in meta.get("breach_data", [])
            if isinstance(row, dict)
        )
    count = len(public_ips(raw))
    if not count:
        return False
    console.print(
        Text(f"{count} IPs found, add an ipgeolocation key to locate them."), highlight=False
    )
    return True
