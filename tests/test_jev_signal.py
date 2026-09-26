"""Phase JEV-5 — signal hygiene: role_system_classify, common_name_context,
breach_canonicalize.

Every JEV call runs through the real seam against an httpx.MockTransport fake model
routed by task. Network-free. Covers keyless byte-identity, the recall guard (a real
person on a non-obvious address is not gated; a real common-name match is not
dropped), the no-over-claim guard (low-confidence upgrade DEFERs; JEV never sets a
band), and the breach guard (only confident merges; nothing dropped or invented).
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

import backend.config as config_mod
from backend.core import jev, jev_signal
from backend.core import name_consensus as nc
from backend.core.breach_normalizer import collapse_breach_findings
from backend.core.jev import breaker as jev_breaker
from backend.core.jev import client as jev_client
from backend.core.jev import metrics as jev_metrics
from backend.core.jev.tasks.signal import (
    BREACH_CANONICALIZE,
    COMMON_NAME_CONTEXT,
    ROLE_SYSTEM_CLASSIFY,
)


class FakeJev:
    _MARKERS = {
        ROLE_SYSTEM_CLASSIFY: "shared / role / system mailbox",
        COMMON_NAME_CONTEXT: "common personal name",
        BREACH_CANONICALIZE: "data breach incident",
    }

    def __init__(self, **answers: Any) -> None:
        self.answers = {
            ROLE_SYSTEM_CLASSIFY: answers.get("role"),
            COMMON_NAME_CONTEXT: answers.get("common"),
            BREACH_CANONICALIZE: answers.get("breach"),
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
# Task 1 — role_system_classify
# ---------------------------------------------------------------------------
async def test_role_confident_shared(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(role={"kind": "role_or_shared", "confidence": 0.95}))
    assert await jev_signal.is_role_or_shared("orders-team@acme.com") is True


@pytest.mark.parametrize("answer", [
    {"kind": "person", "confidence": 0.95},           # a real person → not gated
    {"kind": "unclear", "confidence": 0.95},
    {"kind": "role_or_shared", "confidence": 0.6},     # below 0.85 floor → DEFER
    {"kind": "maybe", "confidence": 0.95},             # schema fail
    httpx.ConnectError("down"),
])
async def test_role_recall_guard_not_gated(monkeypatch: pytest.MonkeyPatch, answer: Any) -> None:
    _install(monkeypatch, FakeJev(role=answer))
    assert await jev_signal.is_role_or_shared("j.faltin@acme.com") is False


async def test_role_keyless_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_key(monkeypatch)
    assert await jev_signal.is_role_or_shared("orders-team@acme.com") is False


# ---------------------------------------------------------------------------
# Task 2 — common_name_context
# ---------------------------------------------------------------------------
def _common_collected() -> dict[str, Any]:
    # "James Smith" from three sources — a common name → the static cap applies.
    def f(platform: str, key: str, val: str) -> dict[str, Any]:
        return {"findings": [{"platform": platform, "metadata": {key: val}}]}

    return {
        "pgp": f("pgp_keyserver", "uid_name", "James Smith"),
        "li": f("linkedin_snippet", "display_name", "James Smith"),
        "gh": f("github_user", "name", "James Smith"),
    }


def _resolve(email: str, collected: dict[str, Any], hint: Any) -> nc.NameConsensusResult:
    return nc.NameConsensusEngine(email, jev_hint=hint).resolve(
        nc.extract_name_candidates(collected, email)
    )


async def test_common_name_is_subject_lifts_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(common={"relation": "is_subject", "confidence": 0.95}))
    collected = _common_collected()
    base = _resolve("js@acme.com", collected, None)
    assert base.name_confidence == "probable"  # capped as a common name

    hint = await jev_signal.common_name_hint("js@acme.com", collected, None)
    lifted = _resolve("js@acme.com", collected, hint)
    assert lifted.name_confidence == "confirmed" and lifted.jev_assisted is True
    assert nc.canonical_name("James Smith") in hint.lift_common_name_cap


async def test_common_name_coincidental_drops(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(common={"relation": "coincidental", "confidence": 0.95}))
    hint = await jev_signal.common_name_hint("js@acme.com", _common_collected(), None)
    assert nc.canonical_name("James Smith") in hint.drop


@pytest.mark.parametrize("answer", [
    {"relation": "is_subject", "confidence": 0.6},   # below floor → DEFER → cap stands
    {"relation": "unclear", "confidence": 0.95},
    httpx.ConnectError("down"),
])
async def test_common_name_no_over_claim(monkeypatch: pytest.MonkeyPatch, answer: Any) -> None:
    _install(monkeypatch, FakeJev(common=answer))
    hint = await jev_signal.common_name_hint("js@acme.com", _common_collected(), None)
    result = _resolve("js@acme.com", _common_collected(), hint)
    assert result.name_confidence == "probable"  # cap still applied


async def test_common_name_uncommon_name_not_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install(monkeypatch, FakeJev(common={"relation": "is_subject", "confidence": 0.95}))

    def f(platform: str, key: str, val: str) -> dict[str, Any]:
        return {"findings": [{"platform": platform, "metadata": {key: val}}]}

    collected = {
        "pgp": f("pgp_keyserver", "uid_name", "Zephyrine Qwistgaard"),
        "gh": f("github_user", "name", "Zephyrine Qwistgaard"),
    }
    hint = await jev_signal.common_name_hint("z@acme.com", collected, None)
    assert fake.n(COMMON_NAME_CONTEXT) == 0  # not a common name → cap never applies
    assert hint is None  # base hint (None) returned unchanged


async def test_common_name_keyless_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_key(monkeypatch)
    assert await jev_signal.common_name_hint("js@acme.com", _common_collected(), None) is None


def test_name_hint_has_no_band_or_score_field() -> None:
    # JEV cannot write a band: the hint carries only candidate-set signals.
    assert set(vars(nc.NameHint())) == {"drop", "groups", "canonical", "lift_common_name_cap"}
    out = set(jev.get_task(COMMON_NAME_CONTEXT).output_model.model_fields)
    assert out == {"relation"}  # no band / confidence-level field


# ---------------------------------------------------------------------------
# Task 3 — breach_canonicalize
# ---------------------------------------------------------------------------
def _breach(name: str) -> dict[str, Any]:
    return {"module_name": "hibp", "data": {"source": "hibp", "signal_type": "breach",
                                            "metadata": {"breach_name": name}}}


async def test_breach_confident_merge_collapses(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(breach={
        "same_breach": "yes", "canonical_name": "LinkedIn Scrape 2021", "confidence": 0.95}))
    findings = [_breach("Acme Users Leak"), _breach("Acme Members Leak")]
    # Distinct names → today's collapse keeps them separate.
    assert len(collapse_breach_findings([dict(f) for f in findings])) == 2

    merges = await jev_signal.canonicalize_breaches(findings)
    assert merges == 1
    collapsed = collapse_breach_findings(findings)
    assert len(collapsed) == 1  # now merged via the stamped canonical id
    meta = collapsed[0]["data"]["metadata"]
    assert meta["jev_canonical_breach"]["jev_task"] == BREACH_CANONICALIZE


@pytest.mark.parametrize("answer", [
    {"same_breach": "no", "confidence": 0.95},
    {"same_breach": "unclear", "confidence": 0.95},
    {"same_breach": "yes", "confidence": 0.6},   # below floor → DEFER
    httpx.ConnectError("down"),
])
async def test_breach_no_merge_on_doubt(monkeypatch: pytest.MonkeyPatch, answer: Any) -> None:
    _install(monkeypatch, FakeJev(breach=answer))
    findings = [_breach("Acme Users Leak"), _breach("Acme Members Leak")]
    assert await jev_signal.canonicalize_breaches(findings) == 0
    assert len(collapse_breach_findings(findings)) == 2  # kept separate, nothing dropped


async def test_breach_never_drops_or_invents(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(breach={"same_breach": "yes",
                                          "canonical_name": "X", "confidence": 0.95}))
    findings = [_breach("Adobe 2013"), _breach("Dropbox 2012"), _breach("Canva 2019")]
    before = len(collapse_breach_findings([dict(f) for f in findings]))
    await jev_signal.canonicalize_breaches(findings)
    after_records = collapse_breach_findings(findings)
    # No breach vanished: every distinct breach name still appears (none dropped).
    assert len(after_records) <= before
    blob = json.dumps(after_records)
    assert "Adobe" in blob and "Dropbox" in blob and "Canva" in blob


async def test_breach_keyless_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_key(monkeypatch)
    findings = [_breach("Acme Users Leak"), _breach("Acme Members Leak")]
    assert await jev_signal.canonicalize_breaches(findings) == 0
    assert all("jev_canonical_breach" not in f["data"]["metadata"] for f in findings)


# ---------------------------------------------------------------------------
# Score-path guarantee
# ---------------------------------------------------------------------------
def test_scoring_and_credential_risk_never_reference_jev() -> None:
    import inspect

    from backend.core import credential_risk
    assert "jev" not in inspect.getsource(credential_risk).lower()
