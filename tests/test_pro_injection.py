"""0.17.0 Phase 2 — governed corpus-lead injection into a serving-only channel.

Gate these (policy/honesty suite). Network-free: the connector is mocked and the
injection/attribution functions are exercised directly. Proves the honesty model:
corpus leads are net-new, unverified, resolved by the SAME 1E pass as native
findings, never duplicate or downgrade a native row, gated to lead-gen + key, and
capped at REVIEW by the eligibility gate. The channel is a dedicated list — corpus
rows are NEVER appended to the native aggregate (``final``).
"""

from __future__ import annotations

import asyncio
import copy
from typing import Any

import pytest

import backend.config as config_mod
from backend.core import mailaccess_pro_connector
from backend.core.domain_harvest_orchestrator import (
    MODULE_MAILACCESS_PRO,
    HarvestedEmail,
    _fetch_pro_leads,
    _inject_pro_leads,
    _pro_injection_active,
)
from backend.core.lead_person import resolve_person_fields
from backend.core.product_mode import ProductMode

PUBLIC = ProductMode.PUBLIC_BUSINESS_CONTACT
ORG = ProductMode.ORG_AUTHORIZED_VERIFICATION
SECURITY = ProductMode.SECURITY_INVESTIGATION

_KEY = "map_test_key"


def _lead(**over: Any) -> dict[str, Any]:
    ld = {
        "name": "Jane Doe",
        "title": "VP of Engineering",
        "email": "jane@acme.com",
        "linkedin_slug": "janedoe",
        "linkedin_url": "https://linkedin.com/in/janedoe",
        "source": "linkedin",
        "corpus_verified": True,
    }
    ld.update(over)
    return ld


def _native(email: str, **over: Any) -> HarvestedEmail:
    kw: dict[str, Any] = {
        "email": email,
        "on_domain": True,
        "is_role": False,
        "role_match_type": None,
        "confidence_score": 0.9,
        "confidence_label": "CONFIRMED",
    }
    kw.update(over)
    return HarvestedEmail(**kw)


def _inject(final: list[HarvestedEmail], leads, **kw) -> list[HarvestedEmail]:
    """Inject into a dedicated channel and return it (never touches ``final``)."""
    channel: list[HarvestedEmail] = []
    _inject_pro_leads(final, leads, corpus_leads_out=channel, **kw)
    return channel


# ---------------------------------------------------------------------------
# 1. Net-new rows: unverified, labeled, evidence carries the corpus fields.
# ---------------------------------------------------------------------------
def test_injection_creates_netnew_unverified_rows() -> None:
    final: list[HarvestedEmail] = []
    channel = _inject(final, [_lead()], mode=PUBLIC, key=_KEY, domain="acme.com")
    assert final == []  # corpus never lands in the native aggregate
    assert len(channel) == 1
    row = channel[0]
    assert row.email == "jane@acme.com"
    assert row.verification == "unverified"
    assert row.found_by_modules == [MODULE_MAILACCESS_PRO]
    assert row.on_domain is True and row.is_role is False
    ev = row.evidence[0]
    assert ev["module"] == MODULE_MAILACCESS_PRO
    meta = ev["metadata"]
    assert meta["full_name"] == "Jane Doe"
    assert meta["job_title"] == "VP of Engineering"
    assert meta["linkedin_url"] == "https://linkedin.com/in/janedoe"
    assert meta["corpus_verified"] is True
    assert meta["corpus_source"] == "linkedin"
    # seniority is NEVER injected — it derives from title downstream.
    assert "seniority" not in meta


# ---------------------------------------------------------------------------
# 2. Person attribution resolves name/title/linkedin; seniority derives.
# ---------------------------------------------------------------------------
def test_person_attribution_from_injected_evidence() -> None:
    channel = _inject([], [_lead()], mode=PUBLIC, key=_KEY, domain="acme.com")
    person = resolve_person_fields(channel[0], mode=PUBLIC)
    assert person.full_name == "Jane Doe"
    assert person.job_title == "VP of Engineering"
    assert person.linkedin_url == "https://linkedin.com/in/janedoe"
    # Derived, not injected.
    assert person.seniority == "vp"
    assert person.field_provenance["seniority"]["derived_from"] == "job_title"


# ---------------------------------------------------------------------------
# 3. A2 — a native row is NEVER influenced by corpus evidence, full stop.
#    An address already covered by a native row is left entirely untouched: no
#    duplicate, no corpus evidence appended, no ``mailaccess_pro`` module stamped,
#    and no corpus row emitted into the channel for that address.
# ---------------------------------------------------------------------------
def test_native_row_untouched_by_corpus() -> None:
    native = _native("jane@acme.com", verification=None)
    native.found_by_modules = ["company_page"]
    native.evidence = [{"module": "company_page", "metadata": {"full_name": "J. Doe"}}]
    final = [native]
    channel = _inject(final, [_lead()], mode=PUBLIC, key=_KEY, domain="acme.com")
    assert len(final) == 1  # not duplicated
    assert channel == []  # colliding address → no corpus row emitted
    row = final[0]
    # A2: corpus never touches a native row.
    assert row.found_by_modules == ["company_page"]
    assert MODULE_MAILACCESS_PRO not in row.found_by_modules
    assert len(row.evidence) == 1  # native only — no corpus evidence appended
    assert row.evidence[0]["module"] == "company_page"
    assert row.verification is None  # native claim not overwritten


# ---------------------------------------------------------------------------
# 4. Observed-beats-inferred: native confirmed verification preserved.
# ---------------------------------------------------------------------------
def test_native_confirmed_not_downgraded() -> None:
    native = _native("jane@acme.com", verification="smtp_verified", is_smtp_verified=True)
    final = [native]
    channel = _inject(final, [_lead()], mode=PUBLIC, key=_KEY, domain="acme.com")
    assert len(final) == 1
    assert channel == []  # colliding address → no corpus row
    assert final[0].verification == "smtp_verified"  # not downgraded to unverified


# ---------------------------------------------------------------------------
# 5. Mode gate: security+key → none; public/org+key → inject; no key → no-op.
# ---------------------------------------------------------------------------
def test_mode_and_key_gate() -> None:
    assert _pro_injection_active(PUBLIC, _KEY) is True
    assert _pro_injection_active(ORG, _KEY) is True
    assert _pro_injection_active(SECURITY, _KEY) is False  # key present, wrong mode
    assert _pro_injection_active(PUBLIC, None) is False  # right mode, no key

    # security + key → no injection (channel empty, aggregate unchanged).
    final_sec: list[HarvestedEmail] = [_native("bob@acme.com")]
    before = copy.deepcopy(final_sec)
    channel_sec = _inject(final_sec, [_lead()], mode=SECURITY, key=_KEY, domain="acme.com")
    assert channel_sec == []
    assert [e.email for e in final_sec] == [e.email for e in before]

    # no key (any mode) → Stream 1 identical (channel empty).
    final_nokey: list[HarvestedEmail] = [_native("bob@acme.com")]
    channel_nokey = _inject(final_nokey, [_lead()], mode=PUBLIC, key=None, domain="acme.com")
    assert channel_nokey == []
    assert len(final_nokey) == 1 and final_nokey[0].email == "bob@acme.com"

    # public + key → injected into the channel.
    channel_pub = _inject([], [_lead()], mode=PUBLIC, key=_KEY, domain="acme.com")
    assert len(channel_pub) == 1


# ---------------------------------------------------------------------------
# 6. Fail-open: dead API / unavailable / raises → native byte-identical.
# ---------------------------------------------------------------------------
def _run(coro):
    return asyncio.run(coro)


def test_fetch_fail_open(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod.settings, "mailaccess_pro_key", _KEY)

    async def _unavailable(*a, **k):
        return {"status": "unavailable", "leads": []}

    monkeypatch.setattr(mailaccess_pro_connector, "fetch_leads", _unavailable)
    res = _run(_fetch_pro_leads("acme.com", PUBLIC))
    assert res["leads"] == [] and res["requested"] is True

    async def _raises(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(mailaccess_pro_connector, "fetch_leads", _raises)
    res2 = _run(_fetch_pro_leads("acme.com", PUBLIC))
    assert res2["leads"] == [] and res2["status"] == "unavailable"


def test_fetch_gated_off_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    # security mode / no key must NOT call the connector at all.
    called = {"n": 0}

    async def _spy(*a, **k):
        called["n"] += 1
        return {"status": "ok", "leads": [_lead()]}

    monkeypatch.setattr(mailaccess_pro_connector, "fetch_leads", _spy)
    monkeypatch.setattr(config_mod.settings, "mailaccess_pro_key", _KEY)
    sec = _run(_fetch_pro_leads("acme.com", SECURITY))  # wrong mode
    assert sec["leads"] == [] and sec["requested"] is False
    monkeypatch.setattr(config_mod.settings, "mailaccess_pro_key", None)
    nok = _run(_fetch_pro_leads("acme.com", PUBLIC))  # no key
    assert nok["leads"] == [] and nok["requested"] is False
    assert called["n"] == 0  # connector never invoked


def test_fetch_serves_leads_when_gate_open(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _ok(*a, **k):
        return {"status": "ok", "leads": [_lead(), _lead(email="bob@acme.com")]}

    monkeypatch.setattr(mailaccess_pro_connector, "fetch_leads", _ok)
    monkeypatch.setattr(config_mod.settings, "mailaccess_pro_key", _KEY)
    res = _run(_fetch_pro_leads("acme.com", PUBLIC))
    assert len(res["leads"]) == 2 and res["status"] == "ok"


# ---------------------------------------------------------------------------
# 7. Eligibility: injected leads cap at REVIEW purely from verification.
# ---------------------------------------------------------------------------
def test_injected_lead_caps_at_review() -> None:
    from backend.core.eligibility import Eligibility, evaluate

    channel = _inject([], [_lead()], mode=PUBLIC, key=_KEY, domain="acme.com")
    row = channel[0]
    assert row.verification == "unverified"
    # Even at a high (hypothetical) confidence, verification=unverified caps REVIEW.
    verdict = evaluate(
        mode=PUBLIC,
        policy_status="lawful-public",
        suppressed=False,
        confidence=0.95,
        verification=row.verification,
    )
    assert verdict.verdict is Eligibility.REVIEW
    # And its own fixed prior also lands at REVIEW (never ELIGIBLE).
    verdict2 = evaluate(
        mode=PUBLIC,
        policy_status="lawful-public",
        suppressed=False,
        confidence=row.confidence_score,
        verification=row.verification,
    )
    assert verdict2.verdict is Eligibility.REVIEW
