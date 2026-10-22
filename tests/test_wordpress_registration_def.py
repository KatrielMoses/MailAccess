"""The WordPress auth-options def treats a known-but-unverified account as exists.

The public-api.wordpress.com auth-options endpoint returns an ``email_verified`` flag
only for a real account (verified or not); a genuinely unknown address returns
``unknown_user``. So ``email_verified: false`` must classify as exists, not absent.
Bodies are synthetic (http_envelope shape); no real test-set email appears here.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from backend.core.account_probe_ported import ported_sites, run_spec

SAMPLE = "sampleperson@example.com"

# (label, response-body, expected-exists). http_envelope=1 wraps the payload in "body".
CASES = [
    ("verified account", '{"body":{"email_verified":true,"passwordless":false},"status":200}', True),
    ("unverified account", '{"body":{"email_verified":false,"passwordless":false},"status":200}', True),
    ("unknown address", '{"body":{"error":"unknown_user","message":"User does not exist."},"status":200}', False),
    ("login-not-allowed", '{"body":{"error":"email_login_not_allowed"},"status":200}', False),
]


def _run(body):
    defn = ported_sites()["wordpress"]

    def handler(request):
        return httpx.Response(200, text=body)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await run_spec(client, defn, SAMPLE, 10.0)

    return asyncio.run(go())


@pytest.mark.parametrize("label,body,expected", CASES)
def test_wordpress_classification(label, body, expected):
    assert _run(body)["exists"] is expected, label
