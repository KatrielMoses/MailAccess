"""UC2.1: each extended (``default_off``) registration def classifies a registered
and an unregistered response correctly. Responses are synthetic fixtures modelled on
the live shapes recorded during validation; no real test-set email appears here.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from backend.core.account_probe_ported import ported_sites, run_spec

SAMPLE = "sampleperson@example.com"

# site id -> (registered-response, unregistered-response) as (status, body) pairs.
# Bodies mirror the live API shapes; the addresses in them are synthetic.
FIXTURES = {
    "adobe": (
        (200, '[{"type":"individual","authenticationMethods":[{"id":"otp","url":null},'
              '{"id":"google","url":"https://adobe.example/g"}]}]'),
        (200, "[]"),
    ),
}


def _run(defn, status, body):
    def handler(request):
        return httpx.Response(status, text=body)

    async def go():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            return await run_spec(client, defn, SAMPLE, 10.0)

    return asyncio.run(go())


@pytest.mark.parametrize("site_id", list(FIXTURES))
def test_extended_def_discriminates(site_id):
    defn = ported_sites()[site_id]
    assert defn.get("default_off") is True, f"{site_id} must be default_off"
    reg, unreg = FIXTURES[site_id]
    assert _run(defn, *reg)["exists"] is True, f"{site_id}: registered should be exists"
    assert _run(defn, *unreg)["exists"] is False, f"{site_id}: unregistered should be absent"


def test_every_extended_def_has_a_fixture():
    """No extended def ships without a both-ways classification fixture (UC2.1)."""
    extended = {s_id for s_id, d in ported_sites().items() if d.get("default_off")}
    assert extended, "expected at least one default_off def"
    missing = extended - set(FIXTURES)
    assert not missing, f"extended defs with no validation fixture: {sorted(missing)}"
