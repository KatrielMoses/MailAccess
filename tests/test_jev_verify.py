"""Phase JEV-2 — verification intelligence: reply_classify, catchall_judge,
m365_signal_read.

Every JEV call runs through the real seam (validation, cache, breaker, metrics)
against an httpx.MockTransport fake model routed by task. Network-free. Covers
keyless byte-identity, each verdict + defer path, the conservatism guard (a wrong
positive never survives), the pre-filter (unambiguous replies never sent), and the
score-path guarantee that grading inputs are unchanged when JEV is off.
"""

from __future__ import annotations

import inspect
import json
from collections import deque
from typing import Any

import httpx
import pytest

import backend.config as config_mod
from backend.core import jev, jev_verify
from backend.core import smtp_verifier as smtp
from backend.core.jev import breaker as jev_breaker
from backend.core.jev import client as jev_client
from backend.core.jev import metrics as jev_metrics
from backend.core.jev.tasks.verify import CATCHALL_JUDGE, M365_SIGNAL_READ, REPLY_CLASSIFY
from backend.core.mx_resolver import MXRecord
from backend.modules import imap_existence as imap
from backend.modules import m365_active_intel as m365


# ---------------------------------------------------------------------------
# Fake model routed by task
# ---------------------------------------------------------------------------
class FakeJev:
    _MARKERS = {
        REPLY_CLASSIFY: "classify what it means",
        CATCHALL_JUDGE: "accepts every address",
        M365_SIGNAL_READ: "interpret Microsoft 365",
    }

    def __init__(self, **answers: Any) -> None:
        self.answers = {
            REPLY_CLASSIFY: answers.get("reply"),
            CATCHALL_JUDGE: answers.get("catchall"),
            M365_SIGNAL_READ: answers.get("m365"),
        }
        self.calls: dict[str, list[dict[str, Any]]] = {t: [] for t in self.answers}

    def _task(self, system: str) -> str:
        for task, marker in self._MARKERS.items():
            if marker in system:
                return task
        raise AssertionError("unrouted JEV prompt")

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        task = self._task(body["messages"][0]["content"])
        self.calls[task].append(json.loads(body["messages"][1]["content"]))
        answer = self.answers[task]
        if isinstance(answer, Exception):
            raise answer
        if callable(answer):
            answer = answer(self.calls[task][-1])
        if answer is None:
            return httpx.Response(500, content=b"no answer")
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(answer)}}]})

    def n(self, task: str) -> int:
        return len(self.calls[task])


@pytest.fixture(autouse=True)
def _jev_on(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    s = config_mod.settings
    for name, value in {
        "jev_provider": "openai", "jev_enabled": True,
        "jev_api_key": "test-key-not-real", "jev_force_off": False,
        "jev_base_url": "https://jev.invalid/v1", "jev_model": "jev-test",
        "jev_timeout_ms": 2000, "jev_max_concurrency": 4, "jev_cache_ttl_seconds": 3600,
        "jev_cache_path": str(tmp_path / "jev-cache"), "jev_cache_refresh": False,
        "jev_min_confidence": 0.7, "jev_run_ceiling_seconds": 20.0, "jev_metrics_dir": "",
        "jev_breaker_failure_threshold": 3, "jev_breaker_cooldown_seconds": 120.0,
    }.items():
        monkeypatch.setattr(s, name, value)
    jev_metrics.reset()
    jev_breaker.reset()


def _install(monkeypatch: pytest.MonkeyPatch, fake: FakeJev) -> FakeJev:
    monkeypatch.setattr(jev_client, "_TRANSPORT", httpx.MockTransport(fake))
    return fake


def _no_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod.settings, "jev_api_key", None)

    async def _boom(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("jev.judge called on a keyless install")

    monkeypatch.setattr(jev, "judge", _boom)


# ---------------------------------------------------------------------------
# jev_verify helpers directly (task routing, floors, conservatism)
# ---------------------------------------------------------------------------
async def test_reply_verdict_maps_and_defers(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(reply={"verdict": "no_such_user", "confidence": 0.95}))
    assert await jev_verify.reply_verdict(protocol="smtp_rcpt", text="550 nope") == "no_such_user"


@pytest.mark.parametrize("answer", [
    {"verdict": "exists", "confidence": 0.5},         # below 0.9 floor → DEFER
    {"verdict": "unknown", "confidence": 0.99},        # explicit unknown → None
    {"verdict": "exists", "reason": 5, "confidence": 0.95},  # schema fail
    httpx.ConnectError("down"),
])
async def test_reply_verdict_conservative_none(
    monkeypatch: pytest.MonkeyPatch, answer: Any
) -> None:
    _install(monkeypatch, FakeJev(reply=answer))
    assert await jev_verify.reply_verdict(protocol="smtp_rcpt", text="452 weird") is None


async def test_reply_verdict_empty_text_never_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install(monkeypatch, FakeJev(reply={"verdict": "exists", "confidence": 0.95}))
    assert await jev_verify.reply_verdict(protocol="imap_login", text="  ") is None
    assert fake.n(REPLY_CLASSIFY) == 0


async def test_catchall_yes_only_on_confident_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(catchall={"catch_all": "yes", "confidence": 0.95}))
    assert await jev_verify.catchall_yes(
        domain="x.com", provider=None, control_code=250, control_text="250 ok") is True


@pytest.mark.parametrize("answer", [
    {"catch_all": "no", "confidence": 0.95},
    {"catch_all": "unclear", "confidence": 0.95},
    {"catch_all": "yes", "confidence": 0.6},   # below floor
    httpx.ConnectError("down"),
])
async def test_catchall_no_upgrade(monkeypatch: pytest.MonkeyPatch, answer: Any) -> None:
    _install(monkeypatch, FakeJev(catchall=answer))
    assert await jev_verify.catchall_yes(
        domain="x.com", provider=None, control_code=451, control_text="451 later") is False


async def test_m365_verdict_maps_and_defers(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(m365={"mailbox": "exists", "managed_tenant": "yes",
                                        "confidence": 0.95}))
    assert await jev_verify.m365_verdict({"check": "aadsts"}) == ("exists", "yes")
    _install(monkeypatch, FakeJev(m365={"mailbox": "unknown", "managed_tenant": "unknown",
                                        "confidence": 0.95}))
    # Different signals → a different cache key, so the second answer is used.
    assert await jev_verify.m365_verdict({"check": "wstrust"}) == (None, None)


# ---------------------------------------------------------------------------
# IMAP call site
# ---------------------------------------------------------------------------
def test_imap_clear_phrases_unchanged() -> None:
    # A clear phrase resolves on the fast matcher; JEV is never consulted for it.
    assert imap.classify_imap_response("NO [AUTHENTICATIONFAILED] bad")[0] == "exists"
    assert imap.classify_imap_response("NO no such user here")[0] == "not_found"


async def test_imap_ambiguous_reply_uses_jev(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(reply={"verdict": "no_such_user", "confidence": 0.95}))
    # Bare "NO" + slow timing → today: exists@0.55 (timing_slow_lookup).
    status, conf, detail = imap.classify_imap_response("A1 NO", elapsed_ms=500.0)
    assert (status, detail) == ("exists", "timing_slow_lookup")
    new_status, new_conf, new_detail, assisted = await imap._jev_refine_imap(
        "A1 NO", status, conf, detail)
    assert (new_status, new_detail, assisted) == ("not_found", "jev_text_not_found", True)


async def test_imap_defer_keeps_timing_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(reply={"verdict": "unknown", "confidence": 0.95}))
    out = await imap._jev_refine_imap("A1 NO", "exists", 0.55, "timing_slow_lookup")
    assert out == ("exists", 0.55, "timing_slow_lookup", False)


async def test_imap_keyless_never_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_key(monkeypatch)
    out = await imap._jev_refine_imap("A1 NO", "exists", 0.55, "timing_slow_lookup")
    assert out == ("exists", 0.55, "timing_slow_lookup", False)


# ---------------------------------------------------------------------------
# SMTP call site
# ---------------------------------------------------------------------------
class _MockTransport:
    def __init__(self, responses: list[str]) -> None:
        self.responses = deque(responses)

    async def send(self, host: str, port: int, command: str) -> str:
        return self.responses.popleft() if self.responses else "221 Bye"

    async def close(self) -> None:
        return None


def _verifier(rcpt_code_or_reply: str) -> smtp.SMTPVerifier:
    responses = [
        "220 mx1 ESMTP", "250-mx1\r\n250 OK", "250 OK",
        rcpt_code_or_reply, "250 OK", "221 Bye",
    ]
    return smtp.SMTPVerifier(
        mx_records=[MXRecord(host="mx1", priority=10)],
        sender_address=smtp.DEFAULT_SENDER,
        probe_delay_seconds=0.0, greylist_retry_delay=0.0,
        connect_timeout_seconds=1.0, transport=_MockTransport(responses),
    )


async def test_smtp_known_code_never_sent_to_jev(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install(monkeypatch, FakeJev(reply={"verdict": "exists", "confidence": 0.95}))
    res = await _verifier("550 User unknown").verify_single("a@x.com")
    assert res.exists is False and res.jev_assisted is False
    assert fake.n(REPLY_CLASSIFY) == 0  # 550 resolves on the fast matcher


async def test_smtp_novel_code_uses_jev(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(reply={"verdict": "no_such_user", "confidence": 0.95}))
    res = await _verifier("599 mailbox disabled permanently").verify_single("a@x.com")
    assert res.exists is False and res.jev_assisted is True


async def test_smtp_novel_code_jev_defer_stays_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, FakeJev(reply={"verdict": "unknown", "confidence": 0.95}))
    res = await _verifier("599 weird").verify_single("a@x.com")
    assert res.exists is None and res.verification_status == "inconclusive"
    assert res.jev_assisted is False


async def test_smtp_keyless_novel_code_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_key(monkeypatch)
    res = await _verifier("599 weird").verify_single("a@x.com")
    assert res.exists is None and res.verification_status == "inconclusive"
    assert res.jev_assisted is False


async def test_smtp_catchall_control_ambiguous_jev_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    # Control probe gets a novel code; reply_classify defers, catchall_judge says yes.
    _install(monkeypatch, FakeJev(
        reply={"verdict": "unknown", "confidence": 0.95},
        catchall={"catch_all": "yes", "confidence": 0.95}))
    v = _verifier("599 accepts whatever")
    assert await v.check_catchall("x.com") is True


async def test_smtp_catchall_keyless_stays_none(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_key(monkeypatch)
    v = _verifier("599 weird")
    assert await v.check_catchall("x.com") is None


# ---------------------------------------------------------------------------
# M365 call site
# ---------------------------------------------------------------------------
async def test_m365_inconclusive_uses_jev(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(m365={"mailbox": "exists", "managed_tenant": "yes",
                                        "confidence": 0.95}))
    base = m365.ActiveProbeResult(email="a@x.com", check="aadsts", status="inconclusive")
    out = await m365._jev_refine_m365(base, provider="m365")
    assert out.status == "exists" and out.jev_assisted is True and out.managed_tenant is True


async def test_m365_defer_keeps_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(m365={"mailbox": "unknown", "managed_tenant": "unknown",
                                        "confidence": 0.95}))
    base = m365.ActiveProbeResult(email="a@x.com", check="aadsts", status="inconclusive")
    out = await m365._jev_refine_m365(base, provider="m365")
    assert out.status == "inconclusive" and out.jev_assisted is False


async def test_m365_never_fabricates_from_low_confidence(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(m365={"mailbox": "exists", "managed_tenant": "no",
                                        "confidence": 0.6}))
    base = m365.ActiveProbeResult(email="a@x.com", check="aadsts", status="inconclusive")
    out = await m365._jev_refine_m365(base, provider="m365")
    assert out.status == "inconclusive" and out.jev_assisted is False


async def test_m365_keyless_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_key(monkeypatch)
    base = m365.ActiveProbeResult(email="a@x.com", check="aadsts", status="inconclusive")
    out = await m365._jev_refine_m365(base, provider="m365")
    assert out.status == "inconclusive" and out.jev_assisted is False


# ---------------------------------------------------------------------------
# Score-path guarantees
# ---------------------------------------------------------------------------
def test_grading_and_eligibility_never_reference_jev() -> None:
    from backend.core import deliverability_grade, deliverability_score, eligibility
    for mod in (deliverability_grade, deliverability_score, eligibility):
        assert "jev" not in inspect.getsource(mod).lower()


def test_verify_task_outputs_cannot_express_a_verified_label() -> None:
    from backend.core.jev.tasks.verify import CatchallOutput, M365Output, ReplyOutput
    blob = json.dumps([
        m.model_json_schema() for m in (ReplyOutput, CatchallOutput, M365Output)
    ]).lower()
    assert "verified" not in blob and "provider_verified" not in blob and '"valid"' not in blob


def test_verify_tasks_have_high_confidence_floors() -> None:
    for name in (REPLY_CLASSIFY, CATCHALL_JUDGE, M365_SIGNAL_READ):
        assert jev.get_task(name).min_confidence == 0.9
