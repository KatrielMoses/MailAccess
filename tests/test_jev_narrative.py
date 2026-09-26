"""Phase JEV-6 — narrative output: brief_wording, finding_correlation.

Every JEV call runs through the real seam against an httpx.MockTransport fake model
routed by task. Network-free. Covers keyless byte-identity, the grounding guard
(a rewrite that injects a new email/domain DEFERs to the template; a lead citing a
non-existent finding or naming a new entity is dropped), the preservation guard
(risk level, finding count, next action unchanged), and the no-verified-claim rule.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

import backend.config as config_mod
from backend.core import jev, jev_narrative
from backend.core.jev import breaker as jev_breaker
from backend.core.jev import client as jev_client
from backend.core.jev import metrics as jev_metrics
from backend.core.jev.tasks.narrative import BRIEF_WORDING, FINDING_CORRELATION


class FakeJev:
    _MARKERS = {
        BRIEF_WORDING: "Defender's Brief",
        FINDING_CORRELATION: "analyst leads",
    }

    def __init__(self, **answers: Any) -> None:
        self.answers = {
            BRIEF_WORDING: answers.get("brief"),
            FINDING_CORRELATION: answers.get("leads"),
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


def _brief() -> dict[str, Any]:
    return {
        "risk_level": "HIGH",
        "risk_summary": "Templated summary about alice@acme.com.",
        "next_action": "Reset the password on acme.com.",
        "top_findings": [
            {"title": "Breach exposure", "detail": "Found in Adobe 2013.",
             "severity": "high", "remediation": "Rotate credentials."},
            {"title": "Public profile", "detail": "GitHub profile located.",
             "severity": "medium", "remediation": "Review visibility."},
        ],
        "generated_at": "2026-01-01T00:00:00Z",
    }


# ---------------------------------------------------------------------------
# Task 1 — brief_wording
# ---------------------------------------------------------------------------
async def test_brief_reworded_preserves_structure(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(brief={
        "summary": "Your address alice@acme.com shows serious exposure.",
        "next_action": "Change your acme.com password right away.",
        "finding_lines": ["Your data appears in the Adobe 2013 breach.",
                          "A GitHub profile tied to you is public."],
        "confidence": 0.9,
    }))
    out = await jev_narrative.reword_brief(_brief(), email="alice@acme.com", name="Alice Ng")
    assert out["risk_level"] == "HIGH"  # unchanged — JEV cannot set it
    assert out["risk_summary"] == "Your address alice@acme.com shows serious exposure."
    assert len(out["top_findings"]) == 2  # same count/order
    assert out["top_findings"][0]["severity"] == "high"  # severity preserved
    assert out["top_findings"][0]["remediation"] == "Rotate credentials."  # meaning preserved
    assert out["top_findings"][0]["detail"] == "Your data appears in the Adobe 2013 breach."
    assert out["jev_assisted"] is True


async def test_brief_grounding_violation_defers_to_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Injects a NEW domain (evil.com) not in the input → must DEFER to the template.
    _install(monkeypatch, FakeJev(brief={
        "summary": "Exposure found; also check evil.com for related data.",
        "next_action": "Change your acme.com password.",
        "finding_lines": ["Adobe 2013 exposure.", "GitHub profile public."],
        "confidence": 0.9,
    }))
    original = _brief()
    out = await jev_narrative.reword_brief(original, email="alice@acme.com", name="Alice Ng")
    assert out == original  # unchanged; templated brief stands
    assert "jev_assisted" not in out


async def test_brief_wrong_finding_count_defers(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(brief={
        "summary": "Exposure summary.", "next_action": "Reset acme.com password.",
        "finding_lines": ["only one line"], "confidence": 0.9,  # 1 != 2
    }))
    original = _brief()
    out = await jev_narrative.reword_brief(original, email="alice@acme.com", name="Alice Ng")
    assert out == original


@pytest.mark.parametrize("answer", [
    {"summary": "x", "next_action": "y", "finding_lines": ["a", "b"], "confidence": 0.5},
    {"summary": "x", "next_action": "", "finding_lines": ["a", "b"], "confidence": 0.9},
    httpx.ConnectError("down"),
])
async def test_brief_defer_paths(monkeypatch: pytest.MonkeyPatch, answer: Any) -> None:
    _install(monkeypatch, FakeJev(brief=answer))
    original = _brief()
    out = await jev_narrative.reword_brief(original, email="alice@acme.com", name="Alice Ng")
    assert out == original


async def test_brief_keyless_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_key(monkeypatch)
    original = _brief()
    out = await jev_narrative.reword_brief(original, email="alice@acme.com", name="Alice Ng")
    assert out == original and "jev_assisted" not in out


# ---------------------------------------------------------------------------
# Task 2 — finding_correlation
# ---------------------------------------------------------------------------
_FINDINGS = [
    {"id": "hibp:0", "type": "hibp", "summary": "Adobe 2013 breach"},
    {"id": "github_commits:0", "type": "github_commits", "summary": "github profile"},
]


async def test_leads_grounded_and_cite_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(leads={"leads": [
        {"text": "The Adobe 2013 breach password may be reused elsewhere — check.",
         "based_on": ["hibp:0"], "severity_hint": "high"},
        {"text": "The public GitHub profile may reveal work email patterns.",
         "based_on": ["github_commits:0"], "severity_hint": "medium"},
    ], "confidence": 0.9}))
    leads = await jev_narrative.generate_leads(
        email="alice@acme.com", name="Alice Ng", findings=_FINDINGS,
        breaches=["Adobe 2013"], roles=[])
    assert leads is not None and len(leads) == 2
    assert leads[0]["based_on"] == ["hibp:0"] and leads[0]["severity_hint"] == "high"
    assert all(lead["jev_assisted"] for lead in leads)
    assert "verified" not in json.dumps(leads).lower()


async def test_leads_drop_unknown_id_and_new_entity(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(leads={"leads": [
        {"text": "Valid grounded lead about Adobe 2013.",
         "based_on": ["hibp:0"], "severity_hint": "low"},
        {"text": "Lead citing a non-existent finding.",
         "based_on": ["does_not_exist:9"], "severity_hint": "high"},
        {"text": "Also check bob@evil.com for reuse.",   # new entity → dropped
         "based_on": ["hibp:0"], "severity_hint": "high"},
    ], "confidence": 0.9}))
    leads = await jev_narrative.generate_leads(
        email="alice@acme.com", name="Alice Ng", findings=_FINDINGS,
        breaches=["Adobe 2013"], roles=[])
    assert leads is not None and len(leads) == 1  # only the grounded, valid-id lead
    assert leads[0]["based_on"] == ["hibp:0"]


@pytest.mark.parametrize("answer", [
    {"leads": [{"text": "x", "based_on": ["hibp:0"], "severity_hint": "low"}], "confidence": 0.5},
    {"leads": [], "confidence": 0.9},
    httpx.ConnectError("down"),
])
async def test_leads_defer_to_no_section(monkeypatch: pytest.MonkeyPatch, answer: Any) -> None:
    _install(monkeypatch, FakeJev(leads=answer))
    assert await jev_narrative.generate_leads(
        email="alice@acme.com", name="Alice Ng", findings=_FINDINGS,
        breaches=[], roles=[]) is None


async def test_leads_keyless_no_section(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_key(monkeypatch)
    assert await jev_narrative.generate_leads(
        email="alice@acme.com", name=None, findings=_FINDINGS, breaches=[], roles=[]) is None


# ---------------------------------------------------------------------------
# Score/verdict safety
# ---------------------------------------------------------------------------
def test_brief_output_has_no_risk_level_field() -> None:
    from backend.core.jev.tasks.narrative import BriefOutput
    assert "risk_level" not in BriefOutput.model_fields  # JEV cannot change it


async def test_reword_does_not_touch_risk_or_scores(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(brief={
        "summary": "Reworded for alice@acme.com.", "next_action": "Reset acme.com password.",
        "finding_lines": ["Adobe 2013 exposure.", "GitHub profile public."], "confidence": 0.9}))
    original = _brief()
    out = await jev_narrative.reword_brief(original, email="alice@acme.com", name="Alice Ng")
    assert out["risk_level"] == original["risk_level"]
    assert [f["severity"] for f in out["top_findings"]] == [
        f["severity"] for f in original["top_findings"]]  # severity order unchanged
