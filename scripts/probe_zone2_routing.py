"""
Real-run probe for S5 ScrapingAnt routing audit.

Confirms both sides of the Zone 2 decision table with mocked transports:

- KEEP: SocialModule routes LinkedIn/profile-page traffic through ScrapingAnt.
- DROP: PastebinSearchModule hits the direct psbdmp JSON endpoint, not the
  ScrapingAnt REST API.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from urllib.parse import quote, unquote

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import httpx  # noqa: E402

from backend.config import Settings  # noqa: E402
from backend.core import http_client as http_client_mod  # noqa: E402
from backend.core import scrapingant as scrapingant_mod  # noqa: E402
from backend.core.scrapingant import ScrapingAntConfig, ScrapingAntMode  # noqa: E402
from backend.modules.pastebin_search import PastebinSearchModule  # noqa: E402
from backend.modules.social import SocialModule  # noqa: E402

captured_scrapingant_urls: list[str] = []
captured_direct_urls: list[str] = []
captured_proxy_urls: list[str] = []


def _capture_rest_handler(request: httpx.Request) -> httpx.Response:
    """Capture the ScrapingAnt REST URL."""
    captured_scrapingant_urls.append(str(request.url))
    return httpx.Response(
        200,
        json={
            "html": "<html></html>",
            "status_code": 404,
            "headers": [],
        },
        request=request,
    )


def _capture_direct_handler(request: httpx.Request) -> httpx.Response:
    """Capture direct, non-ScrapingAnt URLs."""
    captured_direct_urls.append(str(request.url))
    if request.url.host == "psbdmp.ws":
        return httpx.Response(204, request=request)
    return httpx.Response(404, request=request)


def _capture_proxy_handler(request: httpx.Request) -> httpx.Response:
    captured_proxy_urls.append(str(request.url))
    return httpx.Response(200, text="<html></html>", request=request)


def _decoded_q(url: str) -> str:
    if "q=" not in url:
        return ""
    return unquote(url.split("q=", 1)[1].split("&", 1)[0])


async def _run_probe_module(label: str, coro) -> None:
    print(f"\nRunning {label}...")
    try:
        await coro
    except Exception as exc:  # noqa: BLE001 - capture is what matters
        print(f"  module raised (expected for probe): {type(exc).__name__}: {exc}")


def _print_urls(label: str, urls: list[str]) -> None:
    print(f"  captured {len(urls)} {label} URL(s)")
    for url in urls[:3]:
        print(f"  - {url}")
    if len(urls) > 3:
        print(f"  ... ({len(urls) - 3} more)")


async def main() -> int:
    fake_settings = Settings(
        scrapingant_api_key="fake-probe-key-not-real",
        scrapingant_enabled_platforms=True,
        scrapingant_enabled_dorking=False,
        scrapingant_proxy_type="residential",
        enable_pastebin_search=True,
    )
    fake_config = ScrapingAntConfig(
        api_key=fake_settings.scrapingant_api_key,
        enabled_dorking=fake_settings.scrapingant_enabled_dorking,
        enabled_platforms=fake_settings.scrapingant_enabled_platforms,
        proxy_type=fake_settings.scrapingant_proxy_type,
        transport=ScrapingAntMode.REST_API.value,
    )
    scrapingant_mod.scrapingant_config = fake_config
    http_client_mod.scrapingant_config = fake_config

    rest_transport = httpx.MockTransport(_capture_rest_handler)
    direct_transport = httpx.MockTransport(_capture_direct_handler)
    real_build_client = http_client_mod.build_client
    real_build_routed_client = http_client_mod.build_routed_client

    def patched_build_routed_client(zone: str, **kwargs):
        kwargs["_scrapingant_rest_transport"] = rest_transport
        kwargs["transport"] = direct_transport
        return real_build_routed_client(zone, **kwargs)

    def patched_build_client(*, scrapingant_zone: str | None = None, **kwargs):
        if scrapingant_zone is not None:
            return patched_build_routed_client(scrapingant_zone, **kwargs)
        kwargs["transport"] = direct_transport
        return real_build_client(**kwargs)

    http_client_mod.build_client = patched_build_client
    http_client_mod.build_routed_client = patched_build_routed_client

    import backend.modules.pastebin_search as pastebin_search_mod
    import backend.modules.social as social_mod

    social_mod.build_client = patched_build_client
    pastebin_search_mod.build_client = patched_build_client
    pastebin_search_mod.settings = fake_settings

    scrapingant_start = len(captured_scrapingant_urls)
    await _run_probe_module(
        "SocialModule KEEP route",
        SocialModule().run("probe@example.com", timeout=5.0),
    )
    social_scrapingant_urls = captured_scrapingant_urls[scrapingant_start:]

    direct_start = len(captured_direct_urls)
    scrapingant_start = len(captured_scrapingant_urls)
    await _run_probe_module(
        "PastebinSearchModule DROP route",
        PastebinSearchModule().run("probe@example.com", force=True),
    )
    pastebin_direct_urls = captured_direct_urls[direct_start:]
    pastebin_scrapingant_urls = captured_scrapingant_urls[scrapingant_start:]

    expected_prefix = "https://api.scrapingant.com/v2/extended?q="
    social_keep = any(
        url.startswith(expected_prefix) and "linkedin.com" in _decoded_q(url)
        for url in social_scrapingant_urls
    )
    pastebin_drop = (
        any(
            url == "https://psbdmp.ws/api/v3/search/probe@example.com"
            for url in pastebin_direct_urls
        )
        and not pastebin_scrapingant_urls
    )

    print("\nKEEP probe: SocialModule")
    _print_urls("ScrapingAnt", social_scrapingant_urls)
    if social_keep:
        print("  PASS: LinkedIn/profile-page URL routed via ScrapingAnt.")
        print(f"  Sample decoded q={_decoded_q(social_scrapingant_urls[0])!r}")
    else:
        print("  FAIL: no LinkedIn/profile-page ScrapingAnt URL captured.")

    print("\nDROP probe: PastebinSearchModule")
    _print_urls("direct", pastebin_direct_urls)
    _print_urls("ScrapingAnt", pastebin_scrapingant_urls)
    if pastebin_drop:
        print("  PASS: psbdmp JSON endpoint was called directly.")
    else:
        print("  FAIL: psbdmp JSON endpoint was not proven direct.")

    proxy_probe = await _run_residential_proxy_section(real_build_routed_client)

    return 0 if social_keep and pastebin_drop and proxy_probe else 1


async def _run_residential_proxy_section(real_build_routed_client) -> bool:
    username = os.environ.get("SCRAPINGANT_PROXY_RESIDENTIAL_USERNAME")
    password = os.environ.get("SCRAPINGANT_PROXY_RESIDENTIAL_PASSWORD")
    print("\nResidential proxy transport probe")
    if not username or not password:
        print(
            "  SKIP: set SCRAPINGANT_PROXY_RESIDENTIAL_USERNAME and "
            "SCRAPINGANT_PROXY_RESIDENTIAL_PASSWORD to enable."
        )
        return True

    proxy_config = ScrapingAntConfig(
        api_key=None,
        enabled_dorking=False,
        enabled_platforms=True,
        proxy_type="residential",
        transport=ScrapingAntMode.RESIDENTIAL_PROXY.value,
        proxy_residential_username=username,
        proxy_residential_password=password,
    )
    proxy_transport = httpx.MockTransport(_capture_proxy_handler)

    def patched_proxy_build_client(*, scrapingant_zone: str | None = None, **kwargs):
        if scrapingant_zone is not None:
            kwargs["_scrapingant_config"] = proxy_config
            kwargs["_scrapingant_proxy_transport"] = proxy_transport
            return real_build_routed_client(scrapingant_zone, **kwargs)
        kwargs["transport"] = proxy_transport
        return http_client_mod.build_client(**kwargs)

    import backend.modules.social as social_mod

    previous_build_client = social_mod.build_client
    social_mod.build_client = patched_proxy_build_client
    proxy_start = len(captured_proxy_urls)
    try:
        await _run_probe_module(
            "SocialModule residential proxy route",
            SocialModule().run("probe@example.com", timeout=5.0),
        )
    finally:
        social_mod.build_client = previous_build_client

    urls = captured_proxy_urls[proxy_start:]
    expected_username = quote(username, safe="")
    proxy_url = proxy_config.residential_proxy_url() or ""
    ok = (
        bool(urls)
        and all(url.startswith("http") for url in urls)
        and expected_username in proxy_url
    )
    _print_urls("residential proxy", urls)
    if ok:
        print("  PASS: SocialModule dispatched through residential proxy transport.")
        print(f"  Proxy URL user={expected_username}")
    else:
        print("  FAIL: residential proxy transport dispatch was not proven.")
    return ok


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
