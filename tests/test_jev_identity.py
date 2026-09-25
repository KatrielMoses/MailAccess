"""Phase JEV-1 — identity resolution: same_person, name_reconcile, bio_extract.

Every JEV call goes through the real seam (validation, cache, breaker, metrics)
against an ``httpx.MockTransport`` fake model that routes by task. Network-free.
Covers: keyless byte-identity, each task's yes/no/defer behavior, bounded call
counts, and the score-path guarantees (no JEV inside scoring; Task 1 and Task 3
leave scores identical; the name band comes from the existing engine).
"""

from __future__ import annotations

import asyncio
import copy
import inspect
import json
from typing import Any

import httpx
import pytest

import backend.config as config_mod
from backend.core import credential_risk, engine, jev, jev_identity
from backend.core import name_consensus as nc
from backend.core.identity_graph import IdentityGraph
from backend.core.jev import breaker as jev_breaker
from backend.core.jev import client as jev_client
from backend.core.jev import metrics as jev_metrics
from backend.core.jev.tasks.identity import BIO_EXTRACT, NAME_RECONCILE, SAME_PERSON
from backend.modules.base import ModuleResult, ModuleStatus

EMAIL = "rsmith@example.com"


# ---------------------------------------------------------------------------
# Fake model routed by task
# ---------------------------------------------------------------------------
class FakeJev:
    """Answers per task; ``answers[task]`` is a dict, a callable(user_json) or an Exception."""

    _MARKERS = {
        SAME_PERSON: "compare two public online profiles",
        NAME_RECONCILE: "reconcile candidate personal names",
        BIO_EXTRACT: "extract structured facts",
    }

    def __init__(self, **answers: Any) -> None:
        self.answers = {
            SAME_PERSON: answers.get("same_person"),
            NAME_RECONCILE: answers.get("names"),
            BIO_EXTRACT: answers.get("bio"),
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
        user = json.loads(body["messages"][1]["content"])
        self.calls[task].append(user)
        answer = self.answers[task]
        if isinstance(answer, Exception):
            raise answer
        if callable(answer):
            answer = answer(user)
        if answer is None:
            return httpx.Response(500, content=b"no answer configured")
        content = json.dumps(answer)
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
BIO = "Staff engineer at Northwind Labs. Based in Leeds, UK. Coffee and climbing."


def _collected() -> dict[str, ModuleResult]:
    def ok(findings: list[dict[str, Any]]) -> ModuleResult:
        return ModuleResult(status=ModuleStatus.SUCCESS, findings=findings)

    return {
        "github_commits": ok([
            {"platform": "github_user", "confidence": "high",
             "metadata": {"name": "Bob Smith", "username": "bsmith", "bio": BIO}},
        ]),
        "gravatar": ok([
            {"platform": "gravatar_profile", "confidence": "medium",
             "metadata": {"display_name": "Robert Smith", "about_me": BIO}},
            {"platform": "gravatar_bio", "signal_type": "phone_in_bio", "confidence": "medium",
             "metadata": {"phone": "+44 20 7946 0000", "bio": BIO}},
        ]),
        "hackernews": ok([
            {"platform": "hackernews_profile", "confidence": "medium",
             "metadata": {"extracted_name": "Deploy Pipeline", "username": "rs",
                          "about": "short"}},
        ]),
    }


GRAPH_FINDINGS = [
    {"module_name": "m", "data": {"platform": "reddit", "metadata": {
        "display_name": "Jane Quill", "username": "jq_reads",
        "bio": "Coffee, books and long walks in Leeds"}}},
    {"module_name": "m", "data": {"platform": "mastodon", "metadata": {
        "display_name": "Jane Quill", "username": "quillj"}}},
    {"module_name": "m", "data": {"platform": "github", "metadata": {
        "username": "nightowl", "display_name": "Priya Raman"}}},
    {"module_name": "m", "data": {"platform": "gitlab", "metadata": {
        "username": "nightowl", "display_name": "Tom Becker"}}},
]


def _graph() -> IdentityGraph:
    return IdentityGraph.build({"email": "x@example.com", "findings": copy.deepcopy(
        GRAPH_FINDINGS)})


def _cluster_values(graph: IdentityGraph) -> list[list[str]]:
    return sorted(sorted(graph.nodes[n].value for n in c) for c in graph.clusters)


def _yes_no_by_platform(yes: set[str]) -> Any:
    def answer(user: dict[str, Any]) -> dict[str, Any]:
        pair = {user["a"]["platform"], user["b"]["platform"]}
        return {"same_person": "yes" if pair <= yes else "no", "reason": "x",
                "confidence": 0.9}
    return answer


# ---------------------------------------------------------------------------
# Keyless: byte-identical, no JEV call
# ---------------------------------------------------------------------------
async def test_keyless_is_identical_and_never_calls_jev(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_key(monkeypatch)
    collected = _collected()
    before = copy.deepcopy(collected)

    assert await jev_identity.enrich_bios(collected, "example.com") == 0
    assert await jev_identity.reconcile_names(EMAIL, collected) is None
    assert collected == before

    graph = _graph()
    snapshot = json.dumps(graph.to_dict(), sort_keys=True)
    await jev_identity.refine_graph(graph, GRAPH_FINDINGS)
    assert json.dumps(graph.to_dict(), sort_keys=True) == snapshot
    assert "jev_review" not in graph.to_dict()

    plain = await engine._build_graph_with_timeout(EMAIL, _collected())
    assert plain == engine._build_graph(EMAIL, _collected())


# ---------------------------------------------------------------------------
# Task 3 — bio_extract
# ---------------------------------------------------------------------------
async def test_bio_fields_are_grounded_attached_and_deduplicated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _install(monkeypatch, FakeJev(bio={
        "employer": "Northwind Labs", "role_title": "Staff engineer",
        "location": "Paris",  # not in the bio → must be dropped
        "entity_type": "person", "confidence": 0.9,
    }))
    collected = _collected()
    assert await jev_identity.enrich_bios(collected, "example.com") == 2

    assert fake.n(BIO_EXTRACT) == 1  # the same bio on two profiles → one call
    assert fake.calls[BIO_EXTRACT][0]["exclude_domain"] == "example.com"
    gh = collected["github_commits"].findings[0]["metadata"]["bio_structured"]
    assert gh == {"employer": "Northwind Labs", "role_title": "Staff engineer",
                  "entity_type": "person", "jev_assisted": True, "jev_task": BIO_EXTRACT}
    assert "verified" not in json.dumps(gh)
    # Regex-bio signal findings and too-short bios are never sent or touched.
    assert "bio_structured" not in collected["gravatar"].findings[1]["metadata"]
    assert "bio_structured" not in collected["hackernews"].findings[0]["metadata"]


@pytest.mark.parametrize("answer", [
    {"employer": "Northwind Labs", "entity_type": "person", "confidence": 0.3},  # low conf
    {"employer": 42, "entity_type": "person", "confidence": 0.9},  # schema fail
    httpx.ConnectError("down"),  # transport
    {"employer": None, "role_title": None, "location": None, "entity_type": "unclear",
     "confidence": 0.9},  # nothing useful
])
async def test_bio_defer_paths_leave_findings_untouched(
    monkeypatch: pytest.MonkeyPatch, answer: Any
) -> None:
    _install(monkeypatch, FakeJev(bio=answer))
    collected = _collected()
    before = copy.deepcopy(collected)
    assert await jev_identity.enrich_bios(collected) == 0
    assert collected == before


async def test_bio_calls_are_capped_per_investigation(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install(monkeypatch, FakeJev(bio={"entity_type": "person", "confidence": 0.9}))
    findings = [
        {"platform": f"site{i}", "metadata": {"bio": f"Profile number {i} with a long bio text"}}
        for i in range(30)
    ]
    collected = {"m": ModuleResult(status=ModuleStatus.SUCCESS, findings=findings)}
    await jev_identity.enrich_bios(collected)
    assert fake.n(BIO_EXTRACT) == jev_identity.MAX_BIOS_PER_RUN


# ---------------------------------------------------------------------------
# Task 2 — name_reconcile
# ---------------------------------------------------------------------------
def _resolve(hint: Any) -> nc.NameConsensusResult:
    return nc.NameConsensusEngine(EMAIL, jev_hint=hint).resolve(
        nc.extract_name_candidates(_collected(), EMAIL)
    )


async def test_name_hint_groups_drops_and_picks_canonical(monkeypatch: pytest.MonkeyPatch) -> None:
    def answer(user: dict[str, Any]) -> dict[str, Any]:
        names = [c["name"] for c in user["candidates"]]
        return {
            "equivalence_groups": [[names.index("Bob Smith"), names.index("Robert Smith")]],
            "drop": [names.index("Deploy Pipeline")],
            "canonical_index": names.index("Robert Smith"),
            "confidence": 0.9,
        }

    fake = _install(monkeypatch, FakeJev(names=answer))
    heuristic = _resolve(None)
    assert heuristic.conflicting_names == ["Bob Smith", "Robert Smith"]

    hint = await jev_identity.reconcile_names(EMAIL, _collected())
    assert fake.n(NAME_RECONCILE) == 1
    assert fake.calls[NAME_RECONCILE][0]["email_localpart"] == "rsmith"

    result = _resolve(hint)
    assert result.confirmed_name == "Robert Smith"
    assert result.conflicting_names == []
    assert result.jev_assisted is True
    assert result.name_reasoning.endswith(nc.JEV_REASONING_NOTE)
    assert "Fuzzy match" not in result.name_reasoning
    assert "verified" not in result.name_reasoning.lower()


async def test_name_band_is_emitted_by_the_existing_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, FakeJev(names=lambda u: {
        "equivalence_groups": [[0, 1]], "canonical_index": 1, "confidence": 0.95,
    }))
    hint = await jev_identity.reconcile_names(EMAIL, _collected())
    assert hint is not None
    # The JEV output schema has no band/confidence-level field to write from.
    out_fields = set(jev.get_task(NAME_RECONCILE).output_model.model_fields)
    assert out_fields == {"canonical_index", "equivalence_groups", "drop"}
    assert not {"band", "name_confidence"} & set(vars(hint))

    emitted: list[str] = []
    real = nc.NameConsensusEngine._confidence_for_cluster

    def spy(self: Any, cluster: dict[str, Any]) -> str:
        band = real(self, cluster)
        emitted.append(band)
        return band

    monkeypatch.setattr(nc.NameConsensusEngine, "_confidence_for_cluster", spy)
    result = _resolve(hint)
    assert emitted and result.name_confidence == emitted[-1]


async def test_confident_names_are_never_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install(monkeypatch, FakeJev(names={"confidence": 0.9}))
    collected = {
        "pgp": ModuleResult(status=ModuleStatus.SUCCESS, findings=[
            {"platform": "pgp_keyserver", "metadata": {"uid_name": "Robert Smith"}}]),
        "keybase": ModuleResult(status=ModuleStatus.SUCCESS, findings=[
            {"platform": "keybase_profile", "metadata": {"full_name": "Robert Smith"}}]),
    }
    assert await jev_identity.reconcile_names(EMAIL, collected) is None
    assert fake.n(NAME_RECONCILE) == 0


@pytest.mark.parametrize("answer", [
    {"equivalence_groups": [[0, 1]], "confidence": 0.2},  # low confidence
    {"equivalence_groups": "all", "confidence": 0.9},  # schema fail
    {"drop": [0, 1, 2], "confidence": 0.9},  # drop-everything is ignored → no hint
    {"canonical_index": 99, "confidence": 0.9},  # out-of-range index → no hint
])
async def test_name_defer_paths_fall_back_to_heuristic(
    monkeypatch: pytest.MonkeyPatch, answer: Any
) -> None:
    _install(monkeypatch, FakeJev(names=answer))
    hint = await jev_identity.reconcile_names(EMAIL, _collected())
    assert hint is None
    baseline = _resolve(None)
    fallback = _resolve(hint)
    assert (fallback.confirmed_name, fallback.name_confidence, fallback.name_reasoning) == (
        baseline.confirmed_name, baseline.name_confidence, baseline.name_reasoning)


# ---------------------------------------------------------------------------
# Task 1 — same_person
# ---------------------------------------------------------------------------
async def test_same_person_no_splits_heuristic_merge_and_yes_keeps_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _install(monkeypatch, FakeJev(same_person=_yes_no_by_platform({"reddit", "mastodon"})))
    graph = _graph()
    assert _cluster_values(graph) == [["github", "gitlab"], ["mastodon", "reddit"]]

    await jev_identity.refine_graph(graph, GRAPH_FINDINGS)

    assert fake.n(SAME_PERSON) == 2
    assert _cluster_values(graph) == [["mastodon", "reddit"]]  # github/gitlab split
    links = graph.to_dict()["links"]
    same = [e for e in links if e["type"] == "same_person"]
    assert len(same) == 1 and same[0]["metadata"] == {"jev_assisted": True,
                                                      "jev_task": SAME_PERSON}
    suppressed = [e for e in links if e["metadata"].get("jev_suppressed")]
    assert {e["type"] for e in suppressed} == {"shared_username"}
    review = {(r["a"], r["b"]): r["jev"] for r in graph.to_dict()["jev_review"]}
    assert set(review.values()) == {"yes", "no"}
    # The model's free-text reason is never persisted anywhere in the graph.
    assert '"x"' not in json.dumps(graph.to_dict())


@pytest.mark.parametrize("answer", [
    {"same_person": "unclear", "reason": "", "confidence": 0.9},
    {"same_person": "no", "reason": "", "confidence": 0.5},  # below the 0.8 task floor
    {"same_person": "nope", "confidence": 0.9},  # schema fail
    httpx.ConnectError("down"),
])
async def test_same_person_unclear_or_defer_keeps_heuristic(
    monkeypatch: pytest.MonkeyPatch, answer: Any
) -> None:
    _install(monkeypatch, FakeJev(same_person=answer))
    graph = _graph()
    before = _cluster_values(graph)
    await jev_identity.refine_graph(graph, GRAPH_FINDINGS)
    assert _cluster_values(graph) == before
    assert not [e for e in graph.edges if e.type == "same_person" or
                e.metadata.get("jev_suppressed")]


async def test_strong_signal_pairs_are_never_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install(monkeypatch, FakeJev(same_person=_yes_no_by_platform(set())))
    findings = [
        {"module_name": "m", "data": {"platform": p, "metadata": {
            "username": "samehandle", "display_name": n,
            "avatar_url": "https://img.example/a.png"}}}
        for p, n in (("github", "Priya Raman"), ("gitlab", "Tom Becker"))
    ]
    graph = IdentityGraph.build({"email": "x@example.com", "findings": findings})
    await jev_identity.refine_graph(graph, findings)
    assert fake.n(SAME_PERSON) == 0  # shared photo = strong signal


async def test_pair_calls_are_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install(monkeypatch, FakeJev(same_person={"same_person": "unclear",
                                                      "confidence": 0.9}))
    findings = []
    for i in range(20):
        for p in (f"a{i}", f"b{i}"):
            findings.append({"module_name": "m", "data": {"platform": p, "metadata": {
                "display_name": f"Shared Name{i}", "username": p}}})
    graph = IdentityGraph.build({"email": "x@example.com", "findings": findings})
    await jev_identity.refine_graph(graph, findings)
    assert fake.n(SAME_PERSON) == jev_identity.MAX_PAIRS_PER_RUN


async def test_breaker_open_defers_every_identity_task(monkeypatch: pytest.MonkeyPatch) -> None:
    def dead(_u: Any) -> Any:
        raise AssertionError("unreachable")

    fake = FakeJev(bio=dead, names=dead, same_person=dead)

    async def quota(request: httpx.Request) -> httpx.Response:
        fake.calls[BIO_EXTRACT].append({})
        return httpx.Response(429, json={"error": {"code": "insufficient_quota"}})

    monkeypatch.setattr(jev_client, "_TRANSPORT", httpx.MockTransport(quota))
    collected = _collected()
    before = copy.deepcopy(collected)
    await jev_identity.enrich_bios(collected)
    assert await jev_identity.reconcile_names(EMAIL, collected) is None
    graph = _graph()
    clusters = _cluster_values(graph)
    await jev_identity.refine_graph(graph, GRAPH_FINDINGS)
    assert collected == before and _cluster_values(graph) == clusters
    assert len(fake.calls[BIO_EXTRACT]) == 1  # one network hit, then the breaker is open
    assert jev_breaker.snapshot()["state"] == "open"


# ---------------------------------------------------------------------------
# Score-path guarantees
# ---------------------------------------------------------------------------
def test_scoring_code_never_references_jev() -> None:
    for fn in (engine._compute_exposure_score, credential_risk.assess_credential_risk_from_results,
               credential_risk._assess):
        assert "jev" not in inspect.getsource(fn).lower()
    assert "jev" not in inspect.getsource(credential_risk).lower()


async def test_no_jev_call_happens_inside_scoring(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    real = jev.judge

    async def spy(task: str, payload: Any) -> Any:
        calls.append(task)
        return await real(task, payload)

    monkeypatch.setattr(jev, "judge", spy)
    _install(monkeypatch, FakeJev(bio={"entity_type": "person", "confidence": 0.9}))
    collected = _collected()
    engine._compute_exposure_score(collected, "possible")
    credential_risk.assess_credential_risk_from_results(collected)
    assert calls == []


async def test_bio_and_graph_tasks_leave_scores_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(
        bio={"employer": "Northwind Labs", "entity_type": "organization", "confidence": 0.9},
        same_person=_yes_no_by_platform(set()),
    ))
    collected = _collected()
    band = "possible"
    exposure_before = engine._compute_exposure_score(collected, band)
    cred_before = credential_risk.assess_credential_risk_from_results(collected)

    assert await jev_identity.enrich_bios(collected) > 0
    graph_data = await engine._build_graph_with_timeout(EMAIL, collected)
    assert graph_data is not None

    assert engine._compute_exposure_score(collected, band) == exposure_before
    cred_after = credential_risk.assess_credential_risk_from_results(collected)
    assert (cred_after.score, cred_after.band) == (cred_before.score, cred_before.band)


async def test_graph_refinement_runs_inside_the_graph_step(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install(monkeypatch, FakeJev(same_person=_yes_no_by_platform(set())))
    collected = {"m": ModuleResult(status=ModuleStatus.SUCCESS, findings=[
        f["data"] for f in copy.deepcopy(GRAPH_FINDINGS)])}
    data = await engine._build_graph_with_timeout("x@example.com", collected)
    assert fake.n(SAME_PERSON) == 2
    assert {r["jev"] for r in data["jev_review"]} == {"no"}
    assert data["clusters"] == []


def test_run_scope_is_task_local() -> None:
    async def body() -> bool:
        token = jev.enter_run_scope(1.0)
        inner = jev.limits.current_scope() is not None
        jev.exit_run_scope(token)
        return inner and jev.limits.current_scope() is None

    assert asyncio.run(body())
