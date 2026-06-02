from __future__ import annotations

import importlib.util
import sys
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
