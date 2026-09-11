"""0.16.0 Phase 2 — company email-pattern applier.

Contract under test:

* :func:`_index_norm` is byte-identical to ``pattern_pipeline.sql`` ``norm()``
  (lower -> explicit folds -> NFKD drop combining marks -> keep ``[a-z0-9]``);
* :meth:`CompanyPatternIndex.apply` returns exactly ONE graded, *unverified*,
  provenance-tagged email for an indexed domain and ``None`` (clean fallback)
  otherwise;
* role overrides win when the title/seniority resolves to that role;
* ``applied_confidence`` is the support-aware Wilson lower bound of
  ``confidence`` — monotonic in support;
* confidence flows through the ONE canonical scorer (:mod:`email_confidence`),
  is not freshness-penalised, and is capped below the CONFIRMED band;
* the loader fails soft on a missing index and loud on a schema mismatch.

Pure/unit, no network, no DB. Uses a small SYNTHETIC in-repo index fixture — it
never touches the private ``data/company_patterns.json.gz`` or the gitignored
validation sample. The round-trip symmetry gate (which needs that private
sample) is a maintainer check that skips when the sample is absent.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from backend.core import company_pattern_index as cpi
from backend.core.company_pattern_index import (
    SOURCE_TYPE,
    CompanyPatternIndex,
    PatternEmail,
    _first_last,
    _index_norm,
    _wilson_lb,
    confidence_label,
)
from backend.core.email_confidence import (
    CONFIRMED_THRESHOLD,
    SOURCE_CLASS,
    SOURCE_WEIGHTS,
    compute_confidence,
)

# --------------------------------------------------------------------------- #
# Synthetic index fixture — a handful of crafted domains, no PII.
# --------------------------------------------------------------------------- #
_FIXTURE_INDEX = {
    "_meta": {"schema": "company-patterns/1", "pattern_enum": [f"P{i:02d}" for i in range(1, 16)]},
    # Last-name-only pattern (matches the brief's blibli.com example).
    "blibli.com": {"pattern": "P02", "support_n": 5, "confidence": 0.6, "mx": "other"},
    # first.last base, with an executive role override to f.last.
    "role-corp.com": {
        "pattern": "P04",
        "support_n": 16,
        "confidence": 0.6875,
        "role_overrides": {
            "executive": {"pattern": "P06", "support_n": 4, "confidence": 0.75}
        },
        "mx": "m365",
    },
    # Huge support + perfect confidence -> applied_confidence crosses CONFIRMED.
    "bigcorp.com": {"pattern": "P04", "support_n": 900, "confidence": 1.0, "mx": "other"},
    # Same confidence as bigcorp but thin support -> lower applied_confidence.
    "thincorp.com": {"pattern": "P04", "support_n": 3, "confidence": 1.0, "mx": "google"},
}


@pytest.fixture
def index(tmp_path: Path) -> CompanyPatternIndex:
    path = tmp_path / "company_patterns.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump(_FIXTURE_INDEX, fh)
    idx = CompanyPatternIndex(path)
    assert idx.available
    return idx


# --------------------------------------------------------------------------- #
# _index_norm — the byte-identical contract with pattern_pipeline.sql norm().
# --------------------------------------------------------------------------- #
def test_index_norm_lowercases_and_strips_non_alnum() -> None:
    assert _index_norm("O'Brien") == "obrien"
    assert _index_norm("Mary-Jane") == "maryjane"
    assert _index_norm("  Sm ith ") == "smith"
    assert _index_norm("") == ""
    assert _index_norm(None) == ""


def test_index_norm_strips_combining_accents_via_nfkd() -> None:
    # NFKD drops the combining marks (Mn) — José -> jose, García -> garcia.
    assert _index_norm("José") == "jose"
    assert _index_norm("García") == "garcia"
    assert _index_norm("Zoë") == "zoe"


def test_index_norm_explicit_folds_match_sql_macro() -> None:
    # The non-combining letters DuckDB's replace() chain folds explicitly.
    assert _index_norm("Søren") == "soren"
    assert _index_norm("Łukasz") == "lukasz"
    assert _index_norm("Straße") == "strasse"
    assert _index_norm("Æsop") == "aesop"
    assert _index_norm("Œuvre") == "oeuvre"
    assert _index_norm("Đorđe") == "dorde"


def test_first_last_parsing() -> None:
    assert _first_last("Jane Doe") == ("jane", "doe")
    assert _first_last("Jane Anne Doe") == ("jane", "doe")  # middle tokens dropped
    assert _first_last("  ") is None
    assert _first_last(None) is None
    # A name that normalizes entirely away (no [a-z0-9]) -> None, like the index.
    assert _first_last("张伟") is None


# --------------------------------------------------------------------------- #
# apply() — the one-email contract.
# --------------------------------------------------------------------------- #
def test_apply_p02_last_only(index: CompanyPatternIndex) -> None:
    r = index.apply("Alex Sim", "blibli.com")
    assert isinstance(r, PatternEmail)
    assert r.email == "sim@blibli.com"
    assert r.pattern_id == "P02"
    assert r.role_used is None


def test_apply_returns_single_object_not_a_list(index: CompanyPatternIndex) -> None:
    r = index.apply("Alex Sim", "blibli.com")
    assert isinstance(r, PatternEmail)
    assert not isinstance(r, list | tuple)


def test_apply_strips_www_prefix(index: CompanyPatternIndex) -> None:
    assert index.apply("Alex Sim", "www.blibli.com").email == "sim@blibli.com"


def test_apply_accented_name_norms(index: CompanyPatternIndex) -> None:
    # role-corp uses first.last; José García -> jose.garcia.
    assert index.apply("José García", "role-corp.com").email == "jose.garcia@role-corp.com"


def test_role_override_applies_for_executive_title(index: CompanyPatternIndex) -> None:
    base = index.apply("Jane Smith", "role-corp.com")
    assert base.email == "jane.smith@role-corp.com"
    assert base.pattern_id == "P04"
    assert base.role_used is None

    exec_ = index.apply("Jane Smith", "role-corp.com", title="Chief Executive Officer")
    assert exec_.email == "j.smith@role-corp.com"
    assert exec_.pattern_id == "P06"
    assert exec_.role_used == "executive"


def test_role_override_falls_back_to_seniority(index: CompanyPatternIndex) -> None:
    exec_ = index.apply("Jane Smith", "role-corp.com", seniority="c_suite")
    assert exec_.pattern_id == "P06"
    assert exec_.role_used == "executive"


def test_non_matching_role_uses_domain_default(index: CompanyPatternIndex) -> None:
    # An engineering title has no override on this domain -> base pattern.
    r = index.apply("Jane Smith", "role-corp.com", title="Senior Software Engineer")
    assert r.pattern_id == "P04"
    assert r.role_used is None


def test_apply_missing_domain_returns_none(index: CompanyPatternIndex) -> None:
    assert index.apply("Jane Smith", "not-indexed.example") is None
    assert index.apply("Jane Smith", "") is None


def test_single_token_name_returns_none_for_distinct_pattern(index: CompanyPatternIndex) -> None:
    # role-corp uses P04 (needs distinct first != last) -> single token -> None.
    assert index.apply("Cher", "role-corp.com") is None


def test_single_token_name_ok_for_single_part_pattern(index: CompanyPatternIndex) -> None:
    # blibli uses P02 (last only) -> a single token is meaningful.
    r = index.apply("Cher", "blibli.com")
    assert r is not None
    assert r.email == "cher@blibli.com"


def test_mx_is_surfaced(index: CompanyPatternIndex) -> None:
    assert index.apply("Alex Sim", "blibli.com").mx == "other"
    assert index.apply("Jane Smith", "role-corp.com").mx == "m365"
    assert index.apply("Jane Smith", "thincorp.com").mx == "google"


def test_provenance_string_shape(index: CompanyPatternIndex) -> None:
    # This fixture is legacy (no considered_n) → the provenance names the legacy
    # denominator fallback and still carries the versioned confidence basis (Brief C).
    r = index.apply("Alex Sim", "blibli.com")
    assert r.provenance == (
        "company email pattern (P02, 5/5(legacy) samples, conf 0.6; "
        "support_n/considered_n; norm/1; legacy-denominator=support_n; "
        "artifact-normalization=unversioned SQL)"
    )
    assert r.considered_n is None  # legacy record carries no true denominator


# --------------------------------------------------------------------------- #
# Output-trust metadata (D3).
# --------------------------------------------------------------------------- #
def test_result_is_always_unverified(index: CompanyPatternIndex) -> None:
    for dom in ("blibli.com", "role-corp.com", "bigcorp.com"):
        assert index.apply("Jane Smith", dom).verification == "unverified"


def test_result_carries_full_metadata(index: CompanyPatternIndex) -> None:
    r = index.apply("Jane Smith", "role-corp.com", title="CEO")
    assert r.pattern_id == "P06"
    assert r.support_n == 4
    assert r.confidence == 0.75
    assert 0.0 <= r.applied_confidence <= r.confidence
    assert r.mx == "m365"
    assert r.role_used == "executive"


# --------------------------------------------------------------------------- #
# applied_confidence / Wilson lower bound (D2).
# --------------------------------------------------------------------------- #
def test_wilson_lb_bounds() -> None:
    assert _wilson_lb(0.6, 0) == 0.0
    assert 0.0 <= _wilson_lb(0.6, 5) <= 0.6
    # Below the point estimate (it is a LOWER bound), non-negative.
    assert _wilson_lb(1.0, 900) < 1.0


def test_applied_confidence_monotonic_in_support(index: CompanyPatternIndex) -> None:
    thin = index.apply("Jane Smith", "thincorp.com")  # conf 1.0, support 3
    thick = index.apply("Jane Smith", "bigcorp.com")  # conf 1.0, support 900
    assert thin.confidence == thick.confidence == 1.0
    assert thin.applied_confidence < thick.applied_confidence


# --------------------------------------------------------------------------- #
# Canonical-scorer integration + honesty cap (D2).
# --------------------------------------------------------------------------- #
def test_source_type_registered_in_canonical_tables() -> None:
    assert SOURCE_TYPE in SOURCE_WEIGHTS
    assert SOURCE_TYPE in SOURCE_CLASS
    # Subset invariant preserved.
    assert set(SOURCE_WEIGHTS) <= set(SOURCE_CLASS)


def test_confidence_label_tracks_applied_confidence(index: CompanyPatternIndex) -> None:
    thin = confidence_label(index.apply("Jane Smith", "thincorp.com"))
    thick = confidence_label(index.apply("Jane Smith", "bigcorp.com"))
    assert thin.score < thick.score


def test_confidence_label_not_freshness_penalised(index: CompanyPatternIndex) -> None:
    # A pattern inference has no observation age -> freshness must be 1.0, so the
    # score equals applied_confidence (single source, no verification).
    r = index.apply("Jane Smith", "thincorp.com")
    label = confidence_label(r)
    assert label.breakdown["freshness"] == 1.0
    assert label.score == pytest.approx(r.applied_confidence)


def test_confidence_label_capped_below_confirmed(index: CompanyPatternIndex) -> None:
    # bigcorp: applied_confidence >= 0.85, but an unverified guess must NEVER
    # surface as CONFIRMED — it is downgraded to LIKELY.
    big = index.apply("Jane Smith", "bigcorp.com")
    assert big.applied_confidence >= CONFIRMED_THRESHOLD
    label = confidence_label(big)
    assert label.label == "LIKELY"
    assert label.breakdown.get("capped_from_confirmed") is True


def test_source_confidence_override_is_backward_compatible() -> None:
    # Without the override the legacy score is unchanged; with it, the base
    # contribution follows the per-candidate value.
    plain_score, _ = compute_confidence(1, [SOURCE_TYPE])
    boosted_score, _ = compute_confidence(1, [SOURCE_TYPE], source_confidence={SOURCE_TYPE: 0.82})
    assert plain_score == pytest.approx(SOURCE_WEIGHTS[SOURCE_TYPE])
    assert boosted_score == pytest.approx(0.82)


# --------------------------------------------------------------------------- #
# Loader robustness + purity.
# --------------------------------------------------------------------------- #
def test_missing_index_file_is_soft_noop(tmp_path: Path) -> None:
    idx = CompanyPatternIndex(tmp_path / "does_not_exist.json.gz")
    assert idx.available is False
    assert idx.apply("Jane Smith", "blibli.com") is None  # no crash


def test_schema_mismatch_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json.gz"
    with gzip.open(bad, "wt", encoding="utf-8") as fh:
        json.dump({"_meta": {"schema": "company-patterns/99"}, "x.com": {}}, fh)
    with pytest.raises(AssertionError):
        CompanyPatternIndex(bad)


def test_apply_is_pure_and_idempotent(index: CompanyPatternIndex) -> None:
    a = index.apply("Jane Smith", "role-corp.com", title="CEO")
    b = index.apply("Jane Smith", "role-corp.com", title="CEO")
    assert a == b


def test_module_level_apply_uses_cached_singleton(
    monkeypatch: pytest.MonkeyPatch, index: CompanyPatternIndex
) -> None:
    monkeypatch.setattr(cpi, "_SINGLETON", index)
    assert cpi.get_index() is index
    assert cpi.apply("Alex Sim", "blibli.com").email == "sim@blibli.com"


# --------------------------------------------------------------------------- #
# Maintainer regression gate — symmetry enforcer (needs the private sample).
# --------------------------------------------------------------------------- #
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SAMPLE = _REPO_ROOT / "data" / "validation_sample.csv"
_REAL_INDEX = _REPO_ROOT / "data" / "company_patterns.json.gz"


@pytest.mark.skipif(
    not (_SAMPLE.exists() and _REAL_INDEX.exists()),
    reason="private validation_sample.csv / company_patterns.json.gz not present (maintainer-only)",
)
def test_roundtrip_symmetry_gate() -> None:
    metrics = cpi.roundtrip_gate(_SAMPLE, _REAL_INDEX)
    assert metrics["capture"] >= 0.95, metrics
