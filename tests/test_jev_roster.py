"""Phase JEV-3 — harvest roster quality: person_filter, title_normalize,
person_dedupe, company_resolve.

Every JEV call runs through the real seam against an httpx.MockTransport fake model
routed by task. Network-free. Covers keyless byte-identity, each verdict + defer
path, the recall guard (no labeled real/distinct person dropped or merged on
doubt), and the Pro invariant that company resolution only picks a real candidate.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

import backend.config as config_mod
from backend.core import jev, jev_roster
from backend.core.jev import breaker as jev_breaker
from backend.core.jev import client as jev_client
from backend.core.jev import metrics as jev_metrics
from backend.core.jev.tasks.roster import (
    COMPANY_RESOLVE,
    PERSON_DEDUPE,
    PERSON_FILTER,
    TITLE_NORMALIZE,
)


class FakeJev:
    _MARKERS = {
        PERSON_FILTER: "a real individual person's name",
        TITLE_NORMALIZE: "map a free-text job title",
        PERSON_DEDUPE: "the SAME real individual",
        COMPANY_RESOLVE: "which candidate organization",
    }

    def __init__(self, **answers: Any) -> None:
        self.answers = {
            PERSON_FILTER: answers.get("filter"),
            TITLE_NORMALIZE: answers.get("title"),
            PERSON_DEDUPE: answers.get("dedupe"),
            COMPANY_RESOLVE: answers.get("company"),
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


# ---------------------------------------------------------------------------
# Task 1 — person_filter
# ---------------------------------------------------------------------------
_CANDS = [
    {"candidate": "Our Leadership Team", "context": "nav", "source": "company_page"},
    {"candidate": "Dana Whitfield", "context": "VP Sales", "source": "linkedin_search"},
]


async def test_person_filter_drops_only_confident_no(monkeypatch: pytest.MonkeyPatch) -> None:
    def answer(u: dict[str, Any]) -> dict[str, Any]:
        is_junk = "Leadership" in u["candidate"]
        return {"is_person_name": "no" if is_junk else "yes",
                "normalized_name": None if is_junk else "Dana Whitfield", "confidence": 0.95}

    _install(monkeypatch, FakeJev(filter=answer))
    drop, norm = await jev_roster.drop_junk_names(_CANDS)
    assert drop == {0} and norm == {1: "Dana Whitfield"}


@pytest.mark.parametrize("answer", [
    {"is_person_name": "no", "confidence": 0.6},        # below 0.85 floor → DEFER → keep
    {"is_person_name": "unclear", "confidence": 0.99},   # unclear → keep
    {"is_person_name": "maybe", "confidence": 0.95},     # schema fail → keep
    httpx.ConnectError("down"),
])
async def test_person_filter_recall_guard_keeps_on_doubt(
    monkeypatch: pytest.MonkeyPatch, answer: Any
) -> None:
    _install(monkeypatch, FakeJev(filter=answer))
    drop, _norm = await jev_roster.drop_junk_names(_CANDS)
    assert drop == set()  # nothing dropped on any doubt


async def test_person_filter_keyless_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_key(monkeypatch)
    assert await jev_roster.drop_junk_names(_CANDS) == (set(), {})


async def test_person_filter_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _install(monkeypatch, FakeJev(filter={"is_person_name": "unclear", "confidence": 0.9}))
    many = [{"candidate": f"Person Number{i}", "context": None, "source": "x"}
            for i in range(60)]
    await jev_roster.drop_junk_names(many)
    assert fake.n(PERSON_FILTER) == jev_roster.MAX_PERSON_FILTER_PER_RUN


# ---------------------------------------------------------------------------
# Task 3 — person_dedupe
# ---------------------------------------------------------------------------
def test_candidate_pairs_are_fuzzy_only() -> None:
    names = ["John Smith", "Jon Smith", "Jane Doe", "Jane Doe"]
    pairs = jev_roster.candidate_dedupe_pairs(names)
    # Fuzzy-close spelling variants pair (0,1); the exact "Jane Doe" dupe (2,3) is
    # excluded. Nicknames (Bob/Robert) are too far apart for the fuzzy pre-filter —
    # that gap is deliberate (JEV only confirms proposed pairs, never invents them).
    assert (0, 1) in pairs
    assert (2, 3) not in pairs
    assert all(names[i].lower() != names[j].lower() for i, j in pairs)


async def test_dedupe_merges_only_confident_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    def answer(u: dict[str, Any]) -> dict[str, Any]:
        same = {u["a"]["name"], u["b"]["name"]} == {"John Smith", "Jon Smith"}
        return {"same_person": "yes" if same else "no", "confidence": 0.95}

    _install(monkeypatch, FakeJev(dedupe=answer))
    entries = [{"name": "John Smith"}, {"name": "Jon Smith"}, {"name": "Jane Stone"}]
    pairs = [(0, 1), (0, 2)]
    confirmed = await jev_roster.same_person_pairs(entries, pairs)
    assert confirmed == [(0, 1)]


@pytest.mark.parametrize("answer", [
    {"same_person": "yes", "confidence": 0.7},   # below 0.85 floor → DEFER
    {"same_person": "no", "confidence": 0.95},
    {"same_person": "unclear", "confidence": 0.95},
    httpx.ConnectError("down"),
])
async def test_dedupe_never_over_merges(monkeypatch: pytest.MonkeyPatch, answer: Any) -> None:
    _install(monkeypatch, FakeJev(dedupe=answer))
    got = await jev_roster.same_person_pairs([{"name": "A"}, {"name": "B"}], [(0, 1)])
    assert got == []


# ---------------------------------------------------------------------------
# Task 2 — title_normalize
# ---------------------------------------------------------------------------
async def test_title_maps_to_bucket(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(title={
        "seniority_bucket": "vp", "normalized_title": "VP of Engineering", "confidence": 0.9}))
    assert await jev_roster.normalize_title("VicePres, Eng (DE)") == ("vp", "VP of Engineering")


@pytest.mark.parametrize("answer", [
    {"seniority_bucket": "vp", "normalized_title": "x", "confidence": 0.5},  # low conf
    {"seniority_bucket": "chief", "normalized_title": "x", "confidence": 0.9},  # bad enum
    httpx.ConnectError("down"),
])
async def test_title_defers(monkeypatch: pytest.MonkeyPatch, answer: Any) -> None:
    _install(monkeypatch, FakeJev(title=answer))
    assert await jev_roster.normalize_title("weird title") == (None, None)


async def test_title_keyless_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_key(monkeypatch)
    assert await jev_roster.normalize_title("VP Eng") == (None, None)


# ---------------------------------------------------------------------------
# Task 4 — company_resolve (Pro invariant: index into real candidates only)
# ---------------------------------------------------------------------------
_ORGS = [
    {"name": "Acme Scam LLC", "domain": "acme-scam.example", "employees": 5},
    {"name": "Acme Corporation", "domain": "acme.example", "employees": 900},
]


async def test_company_resolve_picks_real_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeJev(company={"chosen_index": 1, "reason": "x", "confidence": 0.95}))
    assert await jev_roster.choose_company("Acme", _ORGS) == 1


@pytest.mark.parametrize("answer", [
    {"chosen_index": None, "confidence": 0.95},
    {"chosen_index": 9, "confidence": 0.95},        # out of range → None
    {"chosen_index": 1, "confidence": 0.5},          # low conf → DEFER
    httpx.ConnectError("down"),
])
async def test_company_resolve_defers(monkeypatch: pytest.MonkeyPatch, answer: Any) -> None:
    _install(monkeypatch, FakeJev(company=answer))
    assert await jev_roster.choose_company("Acme", _ORGS) is None


async def test_company_resolve_single_candidate_never_called(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _install(monkeypatch, FakeJev(company={"chosen_index": 0, "confidence": 0.95}))
    assert await jev_roster.choose_company("Acme", _ORGS[:1]) is None
    assert fake.n(COMPANY_RESOLVE) == 0


def test_company_output_is_index_only_never_a_domain() -> None:
    fields = set(jev.get_task(COMPANY_RESOLVE).output_model.model_fields)
    assert fields == {"chosen_index", "reason"}  # no name/domain field to fabricate


# ---------------------------------------------------------------------------
# Integration: employee_name_discovery filter + dedupe methods
# ---------------------------------------------------------------------------
async def test_module_filter_and_dedupe_methods(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.modules.employee_name_discovery import (
        EmployeeNameDiscoveryModule,
        EmployeeNameResult,
        NameDiscovery,
    )

    def filt(u: dict[str, Any]) -> dict[str, Any]:
        junk = "Leadership" in u["candidate"]
        return {"is_person_name": "no" if junk else "unclear", "confidence": 0.95}

    def dedupe(u: dict[str, Any]) -> dict[str, Any]:
        same = {u["a"]["name"], u["b"]["name"]} == {"John Smith", "Jon Smith"}
        return {"same_person": "yes" if same else "no", "confidence": 0.95}

    _install(monkeypatch, FakeJev(filter=filt, dedupe=dedupe))
    mod = EmployeeNameDiscoveryModule()

    # Filter: "Azure Leadership" is accepted-but-penalized by the heuristic, so it is
    # borderline and sent; a clean name like "Dana Whitfield" is not sent (penalty 1.0).
    names = [
        NameDiscovery(name="Azure Leadership", source="company_page", confidence=0.7),
        NameDiscovery(name="Dana Whitfield", source="linkedin_search", confidence=0.7),
    ]
    dropped = await mod._jev_filter_names(names)
    assert "azure leadership" in dropped and "dana whitfield" not in dropped

    # Dedupe: two fuzzy-close rows merge into one; sources union, no row lost twice.
    agg = {
        "john smith": EmployeeNameResult(name="John Smith", sources=["linkedin_search"],
                                         source_count=1, source_urls=["u1"]),
        "jon smith": EmployeeNameResult(name="Jon Smith", sources=["company_page"],
                                        source_count=1, source_urls=["u2"]),
    }
    merged = await mod._jev_dedupe_names(agg)
    assert len(agg) == 1  # one row absorbed the other
    survivor = next(iter(agg.values()))
    assert set(survivor.sources) == {"linkedin_search", "company_page"}
    assert survivor.name.lower() in merged


async def test_module_keyless_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.modules.employee_name_discovery import (
        EmployeeNameDiscoveryModule,
        EmployeeNameResult,
        NameDiscovery,
    )

    _no_key(monkeypatch)
    mod = EmployeeNameDiscoveryModule()
    names = [NameDiscovery(name="Azure Leadership", source="company_page", confidence=0.7)]
    assert await mod._jev_filter_names(names) == set()
    agg = {"a": EmployeeNameResult(name="John Smith"), "b": EmployeeNameResult(name="Jon Smith")}
    assert await mod._jev_dedupe_names(agg) == set() and len(agg) == 2


# ---------------------------------------------------------------------------
# Integration: enrich company disambiguation
# ---------------------------------------------------------------------------
async def test_enrich_jev_pick_org(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.api.routes import enrich

    _install(monkeypatch, FakeJev(company={"chosen_index": 1, "reason": "x", "confidence": 0.95}))
    chosen = await enrich._jev_pick_org("Acme", _ORGS)
    assert chosen == _ORGS[1] and chosen["domain"] == "acme.example"


async def test_enrich_jev_pick_org_keeps_disambiguation_on_defer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from backend.api.routes import enrich

    _install(monkeypatch, FakeJev(company={"chosen_index": None, "confidence": 0.95}))
    assert await enrich._jev_pick_org("Acme", _ORGS) is None


# ---------------------------------------------------------------------------
# Integration: title-normalization pass fills only UNKNOWN seniority
# ---------------------------------------------------------------------------
async def test_title_pass_fills_only_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.core import domain_harvest_orchestrator as orch

    _install(monkeypatch, FakeJev(title={
        "seniority_bucket": "director", "normalized_title": "Director of Ops",
        "confidence": 0.95}))

    class _E:
        def __init__(self, title: str, seniority: str | None) -> None:
            self.job_title = title
            self.seniority = seniority
            self.person_field_provenance: dict[str, Any] = {}

    class _R:
        pass

    resolved = _E("VP Engineering", "vp")   # already resolved → must not change
    unknown = _E("Head Honcho of Stuff", None)  # unknown → filled
    result = _R()
    result.unique_emails = [resolved, unknown]
    await orch._apply_jev_title_normalization(result)

    assert resolved.seniority == "vp" and "seniority_jev" not in resolved.person_field_provenance
    assert unknown.seniority == "director"
    assert unknown.person_field_provenance["seniority_jev"]["jev_assisted"] is True


async def test_title_pass_keyless_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.core import domain_harvest_orchestrator as orch

    _no_key(monkeypatch)

    class _E:
        job_title = "Head Honcho"
        seniority = None
        person_field_provenance: dict[str, Any] = {}

    class _R:
        unique_emails = [_E()]

    r = _R()
    await orch._apply_jev_title_normalization(r)
    assert r.unique_emails[0].seniority is None
