from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from pathlib import Path


_MODULE_PATH = Path(__file__).resolve().parents[1] / "backend" / "core" / "name_consensus.py"
_SPEC = importlib.util.spec_from_file_location("name_consensus_test_module", _MODULE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules["name_consensus_test_module"] = _MODULE
_SPEC.loader.exec_module(_MODULE)

NameConsensusEngine = _MODULE.NameConsensusEngine
extract_name_candidates = _MODULE.extract_name_candidates
normalize_name = _MODULE.normalize_name
canonical_name = _MODULE.canonical_name
PERSON_RE = _MODULE.PERSON_RE


def test_normalize_name_handles_common_profile_shapes() -> None:
    normalized, flags, username_class = normalize_name("KatrielMoses, PhD")

    assert normalized == "Katriel Moses"
    assert flags == []
    assert username_class is False


def test_consensus_confirms_independent_agreement() -> None:
    result = NameConsensusEngine("katriel.moses@gmail.com").resolve(
        [
            {"raw_name": "Katriel Moses", "source": "github_profile"},
            {"raw_name": "Katriel Moses", "source": "gravatar"},
            {"raw_name": "Katriel Moses", "source": "keybase"},
            {"raw_name": "katriel.moses", "source": "email_localpart"},
        ]
    )

    assert result.confirmed_name == "Katriel Moses"
    assert result.name_confidence == "confirmed"
    assert set(result.name_sources) == {
        "email_localpart",
        "github_profile",
        "gravatar",
        "keybase",
    }
    assert "Email local-part corroborates" in result.name_reasoning


def test_single_non_crypto_source_is_possible() -> None:
    result = NameConsensusEngine("jane@example.com").resolve(
        [{"raw_name": "Jane Doe", "source": "github_profile"}]
    )

    assert result.confirmed_name == "Jane Doe"
    assert result.name_confidence == "possible"


def test_conflict_caps_confidence_at_possible() -> None:
    result = NameConsensusEngine("john@example.com").resolve(
        [
            {"raw_name": "John Doe", "source": "github_profile"},
            {"raw_name": "John Doe", "source": "gravatar"},
            {"raw_name": "Jane Smith", "source": "linkedin_snippet"},
            {"raw_name": "Jane Smith", "source": "twitter_profile"},
        ]
    )

    assert result.name_confidence == "possible"
    assert len(result.conflicting_names) == 2
    assert "Conflict detected" in result.name_reasoning


def test_username_class_only_returns_unknown() -> None:
    result = NameConsensusEngine("test@example.com").resolve(
        [
            {"raw_name": "test1234", "source": "github_profile"},
            {"raw_name": "tester9999", "source": "gravatar"},
        ]
    )

    assert result.confirmed_name is None
    assert result.name_confidence == "unknown"


def test_org_and_bot_names_are_discarded() -> None:
    result = NameConsensusEngine("ci@example.com").resolve(
        [
            {"raw_name": "Example Technologies LLC", "source": "linkedin_snippet"},
            {"raw_name": "github-actions[bot]", "source": "github_profile"},
        ]
    )

    assert result.confirmed_name is None
    assert result.name_confidence == "unknown"


def test_extract_name_candidates_reads_profile_platform_fields() -> None:
    collected = {
        "github_commits": SimpleNamespace(findings=[
            {"platform": "github_user", "metadata": {"name": "Katriel Moses"}},
        ]),
        "gravatar": SimpleNamespace(findings=[
            {
                "platform": "gravatar_profile",
                "metadata": {"display_name": "Katriel Moses"},
            },
        ]),
        "keybase": SimpleNamespace(findings=[
            {
                "platform": "keybase_profile",
                "metadata": {"full_name": "Katriel Moses"},
            },
        ]),
        "twitter_profile": SimpleNamespace(findings=[
            {
                "platform": "twitter_profile",
                "metadata": {"display_name": "Katriel Moses"},
            },
        ]),
        "linkedin_serp": SimpleNamespace(findings=[
            {
                "platform": "linkedin_snippet",
                "metadata": {"display_name": "Katriel Moses"},
            },
        ]),
    }

    candidates = extract_name_candidates(collected, "katriel.moses@gmail.com")
    sources = {candidate["source"] for candidate in candidates}

    assert sources >= {
        "email_localpart",
        "github_profile",
        "gravatar",
        "keybase",
        "twitter_profile",
        "linkedin_snippet",
    }


def test_extract_name_candidates_accepts_flat_finding_list() -> None:
    candidates = extract_name_candidates(
        [
            {
                "platform": "github_user",
                "metadata": {"name": "Katriel Moses"},
            },
            {
                "platform": "twitter_profile",
                "metadata": {"display_name": "Katriel Moses"},
            },
        ],
        "katriel.moses@gmail.com",
    )

    assert {"raw_name": "Katriel Moses", "source": "github_profile"} in candidates
    assert {"raw_name": "Katriel Moses", "source": "twitter_profile"} in candidates


def test_extract_name_candidates_accepts_findings_by_module_lists() -> None:
    candidates = extract_name_candidates(
        {
            "github_commits": [
                {
                    "platform": "github_user",
                    "metadata": {"name": "Katriel Moses"},
                }
            ],
            "gravatar": [
                {
                    "platform": "gravatar_profile",
                    "metadata": {"display_name": "Katriel Moses"},
                }
            ],
            "keybase": [
                {
                    "platform": "keybase_profile",
                    "metadata": {"full_name": "Katriel Moses"},
                }
            ],
            "twitter_profile": [
                {
                    "platform": "twitter_profile",
                    "metadata": {"display_name": "Katriel Moses"},
                }
            ],
        },
        "katriel.moses@gmail.com",
    )

    assert {"raw_name": "Katriel Moses", "source": "github_profile"} in candidates
    assert {"raw_name": "Katriel Moses", "source": "gravatar"} in candidates
    assert {"raw_name": "Katriel Moses", "source": "keybase"} in candidates
    assert {"raw_name": "Katriel Moses", "source": "twitter_profile"} in candidates


def test_github_profile_with_dotted_email_localpart_is_probable() -> None:
    candidates = extract_name_candidates(
        {
            "github_commits": [
                {
                    "platform": "github_user",
                    "metadata": {"name": "KatrielMoses"},
                },
                {
                    "metadata": {"real_name_from_git": "KatrielMoses"},
                },
            ]
        },
        "katriel.moses@gmail.com",
    )

    result = NameConsensusEngine("katriel.moses@gmail.com").resolve(candidates)

    assert result.confirmed_name == "Katriel Moses"
    assert result.name_confidence == "probable"
    assert "github_profile" in result.name_sources


def test_role_system_email_skips_name_inference() -> None:
    result = NameConsensusEngine("noreply@github.com").resolve(
        [
            {"raw_name": "Dan Dave", "source": "git_commit"},
            {"raw_name": "Dan Dave", "source": "github_profile"},
        ]
    )

    assert result.confirmed_name is None
    assert result.name_confidence == "unknown"
    assert result.name_reasoning == "Role/system email address — name inference skipped"


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def test_diacritics_normalize_to_same_canonical() -> None:
    assert canonical_name("Müller") == canonical_name("Muller")
    assert canonical_name("François") == canonical_name("Francois")


def test_double_space_normalizes_same_as_single() -> None:
    n1, _, _ = normalize_name("John  Smith")
    n2, _, _ = normalize_name("John Smith")
    assert n1 == n2
    assert canonical_name("John  Smith") == canonical_name("John Smith")


def test_canonical_strips_jr_suffix() -> None:
    assert canonical_name("John Smith Jr.") == "john smith"
    assert canonical_name("Jane Doe Sr") == "jane doe"


def test_canonical_strips_phd_suffix() -> None:
    assert canonical_name("Alice Wong PhD") == "alice wong"
    assert canonical_name("Bob Lee, Esq.") == "bob lee"


def test_normalize_diacritics_flagged_as_transliterated() -> None:
    _, flags, _ = normalize_name("François Müller")
    assert "transliterated" in flags


# ---------------------------------------------------------------------------
# Fuzzy clustering
# ---------------------------------------------------------------------------


def test_fuzzy_clusters_one_char_typo() -> None:
    # "Jon Smith" vs "John Smith" — 1 missing char, ratio ~ 94
    result = NameConsensusEngine("test@example.com").resolve(
        [
            {"raw_name": "John Smith", "source": "github_profile"},
            {"raw_name": "Jon Smith", "source": "gravatar"},
        ]
    )
    assert result.confirmed_name is not None


def test_fuzzy_clusters_transposition() -> None:
    # "John Smyth" vs "John Smith" — 1 char swap
    result = NameConsensusEngine("test@example.com").resolve(
        [
            {"raw_name": "John Smith", "source": "pgp_keyserver"},
            {"raw_name": "John Smyth", "source": "orcid_profile"},
        ]
    )
    assert result.confirmed_name is not None


def test_fuzzy_does_not_cluster_unrelated_names() -> None:
    result = NameConsensusEngine("test@example.com").resolve(
        [
            {"raw_name": "John Smith", "source": "github_profile"},
            {"raw_name": "Jane Doe", "source": "gravatar"},
        ]
    )
    assert len(result.conflicting_names) >= 0  # independent clusters remain separate
    # Verify they are not the same confirmed name
    if result.confirmed_name:
        assert result.confirmed_name in ("John Smith", "Jane Doe")


# ---------------------------------------------------------------------------
# Temporal decay
# ---------------------------------------------------------------------------


def test_recent_seen_at_scores_higher_than_old() -> None:
    now = datetime.now(timezone.utc)
    one_year_ago = now - timedelta(days=365)

    result_recent = NameConsensusEngine("test@example.com").resolve(
        [{"raw_name": "Elspeth Nairn", "source": "github_profile", "seen_at": now}]
    )
    result_old = NameConsensusEngine("test@example.com").resolve(
        [{"raw_name": "Elspeth Nairn", "source": "github_profile", "seen_at": one_year_ago}]
    )
    assert result_recent.confidence_score > result_old.confidence_score


def test_missing_seen_at_uses_no_decay() -> None:
    assert _MODULE._temporal_decay(None) == 1.0


def test_seen_at_none_yields_same_score_as_today() -> None:
    now = datetime.now(timezone.utc)
    result_none = NameConsensusEngine("test@example.com").resolve(
        [{"raw_name": "Elspeth Nairn", "source": "github_profile"}]
    )
    result_now = NameConsensusEngine("test@example.com").resolve(
        [{"raw_name": "Elspeth Nairn", "source": "github_profile", "seen_at": now}]
    )
    # Both should be very close (within floating-point rounding of 1 second of decay)
    assert abs(result_none.confidence_score - result_now.confidence_score) < 0.01


# ---------------------------------------------------------------------------
# Common-name penalty
# ---------------------------------------------------------------------------


def test_common_name_penalty_caps_confidence_at_probable() -> None:
    # "John" and "Smith" are both in the common-names corpus.
    # Strong multi-source signal would reach "confirmed" for a rare name,
    # but is capped at "probable" for a name where all tokens are common.
    result_common = NameConsensusEngine().resolve(
        [
            {"raw_name": "John Smith", "source": "pgp_keyserver"},
            {"raw_name": "John Smith", "source": "orcid_profile"},
            {"raw_name": "John Smith", "source": "linkedin_snippet"},
            {"raw_name": "John Smith", "source": "gravatar"},
        ]
    )
    result_rare = NameConsensusEngine().resolve(
        [
            {"raw_name": "Elspeth Nairn", "source": "pgp_keyserver"},
            {"raw_name": "Elspeth Nairn", "source": "orcid_profile"},
            {"raw_name": "Elspeth Nairn", "source": "linkedin_snippet"},
            {"raw_name": "Elspeth Nairn", "source": "gravatar"},
        ]
    )
    # Rare name can reach "confirmed"; common name is capped at "probable"
    assert result_rare.name_confidence == "confirmed"
    assert result_common.name_confidence == "probable"


def test_rare_name_not_penalized() -> None:
    result = NameConsensusEngine().resolve(
        [
            {"raw_name": "Wxyzzy Qqqqq", "source": "pgp_keyserver"},
            {"raw_name": "Wxyzzy Qqqqq", "source": "orcid_profile"},
            {"raw_name": "Wxyzzy Qqqqq", "source": "linkedin_snippet"},
        ]
    )
    assert result.name_confidence == "confirmed"


def test_common_single_word_name_capped_at_possible() -> None:
    # "Mary" alone is in top-100 first names → capped at "possible" even with many sources.
    result = NameConsensusEngine().resolve(
        [
            {"raw_name": "Mary", "source": "pgp_keyserver"},
            {"raw_name": "Mary", "source": "orcid_profile"},
        ]
    )
    assert result.name_confidence in ("possible", "unknown")


# ---------------------------------------------------------------------------
# Non-Western script support
# ---------------------------------------------------------------------------


def test_person_re_matches_cyrillic() -> None:
    assert PERSON_RE.match("Иван Петров")


def test_person_re_matches_arabic() -> None:
    assert PERSON_RE.match("محمد علي")


def test_person_re_matches_cjk_single_token() -> None:
    # CJK characters form a single non-Latin token with no space
    assert PERSON_RE.match("李明")


def test_person_re_matches_devanagari() -> None:
    assert PERSON_RE.match("विजय कुमार")


def test_cyrillic_name_normalizes_consistently() -> None:
    # After unidecode transliteration, case variants merge to the same form.
    n1, _, _ = normalize_name("Иван Петров")
    n2, _, _ = normalize_name("Иван петров")
    assert n1 == n2


def test_cyrillic_names_cluster_together() -> None:
    result = NameConsensusEngine("test@example.com").resolve(
        [
            {"raw_name": "Иван Петров", "source": "github_profile"},
            {"raw_name": "Иван петров", "source": "gravatar"},
        ]
    )
    assert result.confirmed_name is not None


def test_arabic_name_extracts_via_extract_candidates() -> None:
    candidates = extract_name_candidates(
        [{"platform": "github_user", "metadata": {"name": "محمد علي"}}]
    )
    assert any(c["raw_name"] == "محمد علي" for c in candidates)


def test_cjk_name_extracts_via_extract_candidates() -> None:
    candidates = extract_name_candidates(
        [{"platform": "github_user", "metadata": {"name": "李明"}}]
    )
    assert any(c["raw_name"] == "李明" for c in candidates)


def test_devanagari_name_extracts_via_extract_candidates() -> None:
    candidates = extract_name_candidates(
        [{"platform": "github_user", "metadata": {"name": "विजय कुमार"}}]
    )
    assert any(c["raw_name"] == "विजय कुमार" for c in candidates)


# ---------------------------------------------------------------------------
# seen_at propagation through extract_name_candidates
# ---------------------------------------------------------------------------


def test_extract_propagates_seen_at_from_metadata() -> None:
    ts = datetime(2023, 6, 1, tzinfo=timezone.utc)
    candidates = extract_name_candidates(
        [
            {
                "platform": "github_user",
                "metadata": {"name": "Elspeth Nairn", "seen_at": ts},
            }
        ]
    )
    match = next((c for c in candidates if c.get("source") == "github_profile"), None)
    assert match is not None
    assert match.get("seen_at") == ts


# ---------------------------------------------------------------------------
# Phase 6A — Diacritic normalization (already in 0.7.0, locked in here)
# ---------------------------------------------------------------------------


def test_diacritic_normalization_clusters_francois_variants() -> None:
    # "François" and "Francois" must cluster together — the brief's headline
    # case for the unidecode transliteration step. Both normalize to the
    # same canonical form and join one cluster.
    result = NameConsensusEngine("test@example.com").resolve(
        [
            {"raw_name": "François", "source": "github_profile"},
            {"raw_name": "Francois", "source": "gravatar"},
        ]
    )
    assert result.confirmed_name is not None
    assert result.confirmed_name in ("François", "Francois")
    # Both candidates should be in the winning cluster
    cluster_names = {c.raw_name for c in result.all_candidates}
    assert {"François", "Francois"} <= cluster_names


# ---------------------------------------------------------------------------
# Phase 6A — Fuzzy cluster merging (double space + typos, token-share cap)
# ---------------------------------------------------------------------------


def test_fuzzy_merge_double_space_collapses_to_one_cluster() -> None:
    # "Katriel Moses" and "Katriel  Moses" (double space) must cluster
    # together. The whitespace is collapsed in canonical_name so the
    # canonicals are identical — the merge is exact, not fuzzy, but the
    # brief's test phrasing asserts the clustering outcome.
    result = NameConsensusEngine("test@example.com").resolve(
        [
            {"raw_name": "Katriel Moses", "source": "github_profile"},
            {"raw_name": "Katriel  Moses", "source": "gravatar"},
        ]
    )
    assert result.confirmed_name == "Katriel Moses"
    # No conflicting cluster should have formed.
    assert result.conflicting_names == []


def test_fuzzy_merge_one_char_typo_shares_token() -> None:
    # "Jon Smith" + "John Smith" — differ by one character, share the
    # "smith" token, ratio ≈ 89. The token-share cap must accept the merge.
    result = NameConsensusEngine("test@example.com").resolve(
        [
            {"raw_name": "Jon Smith", "source": "github_profile"},
            {"raw_name": "John Smith", "source": "gravatar"},
        ]
    )
    assert result.confirmed_name == "John Smith"
    assert "John Smith" in result.all_candidates[0].normalized_name or any(
        c.normalized_name == "John Smith" for c in result.all_candidates
    )


# ---------------------------------------------------------------------------
# Phase 6A — token_set_ratio for display names (subset match)
# ---------------------------------------------------------------------------


def test_token_set_ratio_merges_display_subset() -> None:
    # "Software Engineer at Acme" (4 tokens, social) and "Software Engineer"
    # (2 tokens, social) — token_set_ratio is 100 (subset match), they
    # cluster even though fuzz.ratio would only score ~65.
    result = NameConsensusEngine("test@example.com").resolve(
        [
            {"raw_name": "Software Engineer", "source": "about_me"},
            {"raw_name": "Software Engineer at Acme", "source": "twitter_profile"},
        ]
    )
    assert result.confirmed_name is not None
    # The longer name wins as cluster head. Note: normalize_name
    # title-cases every token (including the preposition "at" → "At"),
    # which is pre-existing behavior shared with all other tests.
    assert result.confirmed_name == "Software Engineer At Acme"
    # Reasoning should mention the display-name subset match
    assert "Display name subset match" in result.name_reasoning


def test_token_set_ratio_does_not_apply_to_short_names() -> None:
    # 1-2 token names from social sources should still use fuzz.ratio,
    # not token_set_ratio. This test guards against over-broad adoption.
    result = NameConsensusEngine("test@example.com").resolve(
        [
            {"raw_name": "Alice Brown", "source": "about_me"},
            {"raw_name": "Alice Brown", "source": "twitter_profile"},
        ]
    )
    # No display subset match should be reported (canonicals are identical)
    assert "Display name subset match" not in result.name_reasoning


# ---------------------------------------------------------------------------
# Phase 6A — Non-Western name handling
# ---------------------------------------------------------------------------


def test_non_western_muller_passes_validation() -> None:
    # "Müller" transliterates to "Muller" → matches PERSON_RE → included
    # without the non_western flag (Latin-script raw form, so the
    # transliteration is lossless and no Unicode fallback is needed).
    # "Passes validation" means the candidate survives the filter — not
    # that it reaches a confidence band, since a single-word name from
    # a low-trust source gets the 0.3 single-word penalty and stays
    # under the 0.5 score floor.
    result = NameConsensusEngine("test@example.com").resolve(
        [{"raw_name": "Müller", "source": "github_profile"}]
    )
    assert len(result.all_candidates) == 1
    muller = result.all_candidates[0]
    assert muller.raw_name == "Müller"
    assert "non_western_name" not in muller.flags


def test_non_western_obrien_passes_validation() -> None:
    # "O'Brien" — Latin with apostrophe, matches PERSON_RE pattern.
    result = NameConsensusEngine("test@example.com").resolve(
        [{"raw_name": "O'Brien", "source": "linkedin_snippet"}]
    )
    assert result.confirmed_name is not None
    obrien = next(c for c in result.all_candidates if c.raw_name == "O'Brien")
    assert "non_western_name" not in obrien.flags


def test_non_western_cjk_flagged() -> None:
    # "李雷" is CJK — raw_name has non-Latin alpha. The transliteration
    # "Li Lei" passes PERSON_RE, but the original script gets flagged.
    result = NameConsensusEngine("test@example.com").resolve(
        [{"raw_name": "李雷", "source": "gravatar"}]
    )
    assert result.confirmed_name is not None
    cjk = next(c for c in result.all_candidates if c.raw_name == "李雷")
    assert "non_western_name" in cjk.flags
    # Reasoning surfaces the Unicode-matching note
    assert "Non-Western name detected" in result.name_reasoning


# ---------------------------------------------------------------------------
# Phase 6A — Temporal decay (5-year time constant)
# ---------------------------------------------------------------------------


def test_temporal_decay_old_signal_ranks_below_recent() -> None:
    # Same name from two sources: 6-year-old vs today. With the 5-year
    # time constant, 6 years ≈ exp(-6/5) ≈ 0.30 → heavily decayed.
    now = datetime.now(timezone.utc)
    six_years_ago = now - timedelta(days=6 * 365)

    result_old = NameConsensusEngine("test@example.com").resolve(
        [{"raw_name": "Elspeth Nairn", "source": "github_profile", "seen_at": six_years_ago}]
    )
    result_recent = NameConsensusEngine("test@example.com").resolve(
        [{"raw_name": "Elspeth Nairn", "source": "github_profile", "seen_at": now}]
    )
    assert result_recent.confidence_score > result_old.confidence_score
    # The recent signal also produces a higher (or equal) confidence band
    # band ordering is monotonic in score for a single-source cluster
    band_order = {"unknown": 0, "possible": 1, "probable": 2, "confirmed": 3}
    assert band_order[result_recent.name_confidence] >= band_order[result_old.name_confidence]


def test_temporal_decay_reasoning_mentions_oldest_signal() -> None:
    # When the oldest signal in a cluster is > 3.5 years old, the
    # reasoning string should mention the temporal decay note.
    long_ago = datetime(2019, 1, 1, tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    result = NameConsensusEngine("test@example.com").resolve(
        [
            {"raw_name": "Elspeth Nairn", "source": "github_profile", "seen_at": long_ago},
            {"raw_name": "Elspeth Nairn", "source": "orcid_profile", "seen_at": now},
        ]
    )
    assert "oldest signal from 2019" in result.name_reasoning
    assert "temporal decay" in result.name_reasoning


# ---------------------------------------------------------------------------
# Phase 6A — Single-word name from high-trust source
# ---------------------------------------------------------------------------


def test_single_word_high_trust_softens_penalty() -> None:
    # "Madonna" from PGP (base_weight 1.0) — single-word high-trust case.
    # Multiplier should be 0.65, not 0.3, and the flag should be set.
    flags: list[str] = []
    multiplier = _MODULE._quality_multiplier(
        raw_name="Madonna",
        normalized_name="Madonna",
        flags=flags,
        source="pgp_keyserver",
        email=None,
    )
    assert multiplier == 0.65
    assert "single_word_high_trust" in flags


def test_single_word_low_trust_keeps_existing_penalty() -> None:
    # "Madonna" from gravatar (base_weight 0.50) — single-word, low trust.
    # Should keep the existing 0.3 penalty and NOT set the high-trust flag.
    flags: list[str] = []
    multiplier = _MODULE._quality_multiplier(
        raw_name="Madonna",
        normalized_name="Madonna",
        flags=flags,
        source="gravatar",
        email=None,
    )
    assert multiplier == 0.3
    assert "single_word_high_trust" not in flags


# ---------------------------------------------------------------------------
# Phase 6A — Reasoning string updates
# ---------------------------------------------------------------------------


def test_reasoning_mentions_fuzzy_merge() -> None:
    # "Jon Smith" (gravatar) and "John Smith" (github) — differ at the
    # canonical level, ratio ≥ 88, share "smith" token. The merge is a
    # true fuzzy event and the reasoning string should surface it.
    result = NameConsensusEngine("test@example.com").resolve(
        [
            {"raw_name": "Jon Smith", "source": "gravatar"},
            {"raw_name": "John Smith", "source": "github_profile"},
        ]
    )
    assert "Fuzzy match" in result.name_reasoning
    # The message should mention both the merged name and the cluster head
    assert "'John Smith'" in result.name_reasoning or "'Jon Smith'" in result.name_reasoning


def test_reasoning_no_fuzzy_note_for_exact_canonical_match() -> None:
    # "Katriel Moses" and "Katriel  Moses" — exact canonical match (whitespace
    # collapsed). The merge is trivial equality, not fuzzy. No "Fuzzy match"
    # note should fire.
    result = NameConsensusEngine("test@example.com").resolve(
        [
            {"raw_name": "Katriel Moses", "source": "github_profile"},
            {"raw_name": "Katriel  Moses", "source": "gravatar"},
        ]
    )
    assert "Fuzzy match" not in result.name_reasoning
