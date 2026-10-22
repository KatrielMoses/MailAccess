from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.core.person_card import build_card
from backend.core.person_card_schema import EXAMPLE, SCHEMA_VERSION, validate_person_card


def test_example_validates():
    assert validate_person_card(EXAMPLE) == []
    assert EXAMPLE["schema_version"] == SCHEMA_VERSION


def test_null_card_allowed():
    assert validate_person_card(None) == []


def test_built_cards_validate():
    # Several synthetic report shapes must all produce schema-valid cards.
    reports = [
        {"original_email": "sampleperson@example.com", "name_consensus": {"confirmed_name": "Sample Person"},
         "findings_by_module": {"username_platforms": [
             {"platform": "GitHub", "username": "sampleperson", "confidence": "medium",
              "profile_url": "https://github.com/sampleperson",
              "metadata": {"core": True, "display_name": "Sample Person",
                           "location_normalized": {"city": "Testcity", "country_code": "IN"},
                           "avatar_url": "https://a/1.png", "joined_at": "2020-01-01T00:00:00Z"}}]}},
        {"subject_username": "sampleperson", "name_consensus": {},
         "findings_by_module": {"username_platforms": [
             {"platform": "GitHub", "username": "sampleperson", "confidence": "low",
              "metadata": {"core": True}}]}},
        {"original_email": "nobody@example.com", "name_consensus": {},
         "findings_by_module": {}},  # empty: card still present and valid
    ]
    for data in reports:
        assert validate_person_card(build_card(data)) == []


@pytest.mark.parametrize("bad,needle", [
    ({**EXAMPLE, "schema_version": 2}, "schema_version"),
    ({**EXAMPLE, "subject": {"type": "phone", "value": "x"}}, "subject.type"),
    ({**EXAMPLE, "counts": {**EXAMPLE["counts"], "photos": "1"}}, "counts.photos"),
])
def test_schema_rejects_malformed(bad, needle):
    errors = validate_person_card(bad)
    assert any(needle in e for e in errors), errors


def test_every_scoreboard_report_card_validates():
    """Gate 8: every person_card in dev/uc/runs validates (skipped if no runs present)."""
    runs = Path(__file__).resolve().parents[1] / "dev" / "uc" / "runs"
    reports = list(runs.glob("*/raw/*.json")) if runs.exists() else []
    checked = 0
    for path in reports:
        try:
            raw = json.loads(path.read_text())
        except ValueError:
            continue
        report = raw.get("report") if isinstance(raw, dict) else None
        card = (report or {}).get("person_card") if isinstance(report, dict) else None
        if card is None:
            continue
        errors = validate_person_card(card)
        assert errors == [], f"{path.name}: {errors}"
        checked += 1
    if not reports:
        pytest.skip("no scoreboard runs present")
