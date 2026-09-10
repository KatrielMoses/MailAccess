"""Tests for the native account-existence engine."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from backend.core.account_probe import probe_site
from backend.core.mailaccess_sites_loader import load_mailaccess_sites, sites_for_paradigm
from backend.core.pre_check import apply_pre_check_values


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------- #
# Declarative probe: hit / miss / rate-limit                                  #
# --------------------------------------------------------------------------- #

SPOTIFY = {
    "id": "spotify", "name": "spotify", "domain": "spotify.com", "dedup_key": "spotify.com",
    "check_type": "email-existence",
    "uri_check": "https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={email}",
    "requestMethod": "GET",
    "e_code": 200, "e_string": '"status":20', "m_code": 200, "m_string": '"status":1',
}


def test_declarative_hit():
    def handler(request: httpx.Request) -> httpx.Response:
        assert "taken@x.com" in str(request.url)
        return httpx.Response(200, text='{"status":20}')

    rec = _run(probe_site(_c := _client(handler), asyncio.Semaphore(1), SPOTIFY, "taken@x.com"))
    assert rec["exists"] is True and rec["rateLimit"] is False
    _run(_c.aclose())


def test_declarative_miss():
    rec = _run(
        probe_site(_client(lambda r: httpx.Response(200, text='{"status":1}')),
                   asyncio.Semaphore(1), SPOTIFY, "free@x.com")
    )
    assert rec["exists"] is False


def test_rate_limited_status():
    rec = _run(
        probe_site(_client(lambda r: httpx.Response(429, text="slow down")),
                   asyncio.Semaphore(1), SPOTIFY, "x@x.com")
    )
    assert rec["rateLimit"] is True and rec["exists"] is None


def test_rate_limited_marker():
    defn = {**SPOTIFY, "rate_limited_strings": ["Trop rapide"]}
    rec = _run(
        probe_site(_client(lambda r: httpx.Response(200, text="Trop rapide")),
                   asyncio.Semaphore(1), defn, "x@x.com")
    )
    assert rec["rateLimit"] is True


# --------------------------------------------------------------------------- #
# pre_check extension: regex token scrape + substitution (MyBB pattern)       #
# --------------------------------------------------------------------------- #

def test_pre_check_regex_token_and_form_post():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("member.php"):
            return httpx.Response(200, text='var my_post_key = "ABC123";')
        # main POST must carry the scraped token + form body
        body = request.content.decode()
        seen["body"] = body
        seen["ct"] = request.headers.get("content-type", "")
        return httpx.Response(200, text="already in use by another member")

    defn = {
        "id": "mybb", "name": "mybb", "domain": "community.mybb.com",
        "check_type": "email-existence",
        "uri_check": "https://community.mybb.com/xmlhttp.php?action=email_availability",
        "requestMethod": "POST", "body_type": "form",
        "requestPayload": {"email": "{email}", "my_post_key": "{my_post_key}"},
        "pre_check": {"url": "https://community.mybb.com/member.php", "method": "GET",
                      "extract_regex": {"my_post_key": r'my_post_key\s*=\s*"([^"]+)"'}},
        "e_code": 200, "e_string": "already in use by another member",
        "m_code": 200, "m_string": "",
        "rate_limited_strings": ["Your request was blocked"],
    }
    rec = _run(probe_site(_client(handler), asyncio.Semaphore(1), defn, "taken@x.com"))
    assert rec["exists"] is True
    # scraped token substituted into the form body, email present (urlencoded)
    assert "ABC123" in seen["body"]
    assert "taken" in seen["body"] and "x.com" in seen["body"]
    assert "application/x-www-form-urlencoded" in seen["ct"]


def test_pre_check_backward_compatible_csrf_meta():
    # The legacy meta[name='csrf-token'] selector must still resolve.
    from backend.core.pre_check import _extract_selector_value  # noqa: PLC2701
    body = '<meta name="csrf-token" content="TOK">'
    assert _extract_selector_value(body, "meta[name='csrf-token']") == "TOK"
    # arbitrary names now work too
    body2 = '<input name="authenticity_token" value="AT">'
    assert _extract_selector_value(body2, "input[name='authenticity_token']") == "AT"


def test_apply_pre_check_named_tokens():
    out = apply_pre_check_values(
        {"k": "{my_post_key}", "c": "{csrf_token}", "x": "{sess_value}"},
        {"sess": "COOKIEVAL"}, "CSRF", {"my_post_key": "MPK"},
    )
    assert out == {"k": "MPK", "c": "CSRF", "x": "COOKIEVAL"}


# --------------------------------------------------------------------------- #
# Recovery extraction (mail_ru pattern) + masking                             #
# --------------------------------------------------------------------------- #

def test_recovery_extraction_masks():
    defn = {
        "id": "mail_ru", "name": "mail_ru", "domain": "mail.ru", "check_type": "email-existence",
        "uri_check": "https://account.mail.ru/api/v1/user/password/restore",
        "requestMethod": "POST",
        "body_type": "form", "requestPayload": {"email": "{email}", "htmlencoded": "false"},
        "e_code": 200, "e_string": '"status":200', "m_code": 200, "m_string": "",
        "recovery": True,
        "extract_fields": {
            "phone_hint": {
                "source": "json", "path": "body.phones", "join": ", ", "mask": "phone"},
            "email_recovery": {
                "source": "json", "path": "body.emails", "join": ", ", "mask": "email"},
        },
    }
    payload = {"status": 200, "body": {"phones": ["+16505551234"], "emails": ["bob@work.com"]}}
    body_text = json.dumps(payload, separators=(",", ":"))  # minified, as the API returns

    rec = _run(
        probe_site(_client(lambda r: httpx.Response(200, text=body_text)),
                   asyncio.Semaphore(1), defn, "taken@mail.ru")
    )
    assert rec["exists"] is True
    assert rec["phoneNumber"] and rec["phoneNumber"].endswith("1234")
    assert "***" in rec["phoneNumber"]
    assert rec["emailrecovery"] == "b***@work.com"


def test_no_password_recovery_skips_recovery_sites():
    defn = {"id": "mail_ru", "name": "mail_ru", "domain": "mail.ru",
            "check_type": "email-existence",
            "uri_check": "https://x/y", "requestMethod": "GET", "recovery": True,
            "e_code": 200, "e_string": "", "m_code": 404, "m_string": ""}
    rec = _run(probe_site(_client(lambda r: httpx.Response(200)), asyncio.Semaphore(1), defn,
                          "x@x.com", no_password_recovery=True))
    assert rec is None


# --------------------------------------------------------------------------- #
# Handlers: control-email disambiguation                                       #
# --------------------------------------------------------------------------- #

CONTROL_DEFN = {
    "id": "ello", "name": "ello", "domain": "ello.co", "check_type": "email-existence",
    "handler": "control_email",
    "uri_check": "https://ello.co/api/v2/availability", "requestMethod": "POST",
    "requestPayload": {"email": "{email}"}, "headers": {"Content-Type": "application/json"},
    "e_code": 200, "e_string": '"email":false', "m_code": 200, "m_string": '"email":true',
}


def test_control_email_true_when_real_taken_control_free():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        taken = body["email"] == "real@ello.co"
        return httpx.Response(
            200, text=json.dumps({"availability": {"email": not taken}}, separators=(",", ":"))
        )

    rec = _run(probe_site(_client(handler), asyncio.Semaphore(1), CONTROL_DEFN, "real@ello.co"))
    assert rec["exists"] is True


def test_control_email_false_when_catchall():
    # Everything reads taken -> catch-all -> not a genuine account.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, text=json.dumps({"availability": {"email": False}}, separators=(",", ":"))
        )

    rec = _run(probe_site(_client(handler), asyncio.Semaphore(1), CONTROL_DEFN, "real@ello.co"))
    assert rec["exists"] is False


# --------------------------------------------------------------------------- #
# Disabled sites + loader corpus                                               #
# --------------------------------------------------------------------------- #

def test_disabled_site_returns_none():
    defn = {"id": "venmo", "name": "venmo", "domain": "venmo.com",
            "check_type": "email-existence",
            "disabled": True, "disabled_reason": "broken upstream"}
    rec = _run(
        probe_site(_client(lambda r: httpx.Response(200)), asyncio.Semaphore(1), defn, "x@x.com")
    )
    assert rec is None


def test_corpus_covers_email_existence_site_floor():
    sites, meta = load_mailaccess_sites()
    email_sites = sites_for_paradigm("email-existence")
    # The native corpus must carry a substantial email-existence site set.
    assert len(email_sites) >= 250
    # forward-compatibility: the schema also represents a username-url probe.
    assert len(sites_for_paradigm("username-url")) >= 1
    # every referenced handler is registered
    from backend.core.account_probe_handlers import HANDLERS
    referenced = {d["handler"] for d in sites.values() if d.get("handler")}
    assert referenced <= set(HANDLERS)


def test_username_url_row_is_representable():
    sites, _ = load_mailaccess_sites()
    row = sites.get("github_username")
    assert row and row["check_type"] == "username-url"
    assert "{username}" in row["uri_check"]


# --------------------------------------------------------------------------- #
# Merged email-existence corpus: one entry per platform, no duplicates         #
# --------------------------------------------------------------------------- #

def test_corpus_email_existence_has_no_duplicate_dedup_keys():
    """Every email-existence platform appears exactly once (overlaps collapsed)."""
    sites, meta = load_mailaccess_sites()
    email_sites = sites_for_paradigm("email-existence")
    keys = [d.get("dedup_key") for d in email_sites.values()]
    assert len(keys) == len(set(keys)), "duplicate dedup_key — overlaps not deduped"


def test_message_mode_detection_hit_and_miss():
    """checkType:'message' (presence/absence markers) resolves hit vs miss."""
    defn = {
        "id": "duolingo", "name": "duolingo", "domain": "duolingo.com",
        "check_type": "email-existence",
        "uri_check": "https://duolingo.com/users?email={email}", "requestMethod": "GET",
        "checkType": "message",
        "presenseStrs": ['"users":[{'], "absenceStrs": ['"users":[]'],
    }
    hit = _run(probe_site(_client(lambda r: httpx.Response(200, text='{"users":[{"id":1}]}')),
                          asyncio.Semaphore(1), defn, "taken@duolingo.com"))
    assert hit["exists"] is True
    miss = _run(probe_site(_client(lambda r: httpx.Response(200, text='{"users":[]}')),
                           asyncio.Semaphore(1), defn, "free@duolingo.com"))
    assert miss["exists"] is False


def test_follow_redirects_false_classifies_on_3xx():
    """A site that signals existence with a redirect keeps the 3xx status."""
    defn = {
        "id": "axonaut", "name": "axonaut", "domain": "axonaut.com",
        "check_type": "email-existence",
        "uri_check": "https://axonaut.com/onboarding/?email={email}", "requestMethod": "GET",
        "follow_redirects": False,
        "e_code": 302, "e_string": "", "m_code": 200, "m_string": "",
    }
    taken = _run(probe_site(
        _client(lambda r: httpx.Response(302, headers={"Location": "/login?email=x"})),
        asyncio.Semaphore(1), defn, "taken@axonaut.com"))
    assert taken["exists"] is True
    free = _run(probe_site(_client(lambda r: httpx.Response(200, text="signup")),
                           asyncio.Semaphore(1), defn, "free@axonaut.com"))
    assert free["exists"] is False


# --------------------------------------------------------------------------- #
# Handler: OkCupid (anon-token + inverted isEmailValid + control disambiguation)#
# --------------------------------------------------------------------------- #

OKCUPID_DEFN = {
    "id": "okcupid", "name": "OkCupid", "domain": "okcupid.com",
    "check_type": "email-existence", "handler": "okcupid",
}


def _okcupid_transport(valid_for):
    """MockTransport: token mint always OK; ValidateEmail returns isEmailValid
    per the ``valid_for`` predicate on the probed address."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("AnonAuthToken"):
            return httpx.Response(200, json={"data": {"authAnonymous": {"token": "T"}}})
        body = json.loads(request.content.decode())
        addr = body["variables"]["email"]
        return httpx.Response(200, json={"data": {"auth": {"isEmailValid": valid_for(addr)}}})
    return httpx.MockTransport(handler)


def test_okcupid_valid_means_not_registered():
    # isEmailValid True -> registerable -> account does NOT exist.
    client = httpx.AsyncClient(transport=_okcupid_transport(lambda a: True))
    rec = _run(probe_site(client, asyncio.Semaphore(1), OKCUPID_DEFN, "free@x.com"))
    assert rec["exists"] is False


def test_okcupid_invalid_target_valid_control_means_taken():
    # target invalid, a random control valid -> the address itself is taken.
    client = httpx.AsyncClient(
        transport=_okcupid_transport(lambda a: not a.startswith("taken@")))
    rec = _run(probe_site(client, asyncio.Semaphore(1), OKCUPID_DEFN, "taken@x.com"))
    assert rec["exists"] is True


def test_okcupid_domain_refused_means_not_registered():
    # every address at the domain is invalid -> domain refused, not a real account.
    client = httpx.AsyncClient(transport=_okcupid_transport(lambda a: False))
    rec = _run(probe_site(client, asyncio.Semaphore(1), OKCUPID_DEFN, "x@refused.com"))
    assert rec["exists"] is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
