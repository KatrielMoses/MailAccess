"""UC7.3 false-positive fix: OK.ru recovery existence keys on the recovery-offer
container, not ``registrationcontainer`` (page chrome present on every response, which
reported every address as existing). Synthetic page fixtures only."""

from __future__ import annotations

import asyncio

import httpx

from backend.core.account_probe_handlers import odnoklassniki_recovery

_DEFN = {"id": "odnoklassniki", "name": "odnoklassniki", "domain": "ok.ru",
         "check_type": "email-existence"}


def _run(page_html):
    def handler(request):
        return httpx.Response(200, text=page_html)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await odnoklassniki_recovery(client, _DEFN, "sample@example.test", 10.0)

    return asyncio.run(go())


def test_recovery_offer_means_exists():
    html = '<div class="offer_contact_rest">We can send a code to s***@e***.test</div>'
    assert _run(html)["exists"] is True


def test_registration_prompt_only_means_absent():
    # the "register instead" chrome is present on EVERY response — it must not read as exists
    html = '<div id="registrationContainer">Create a new profile</div>'
    assert _run(html)["exists"] is False


def test_home_page_means_absent():
    assert _run('<div class="home_rest">OK</div>')["exists"] is False
