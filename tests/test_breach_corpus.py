from __future__ import annotations

import json
import os
import time
from dataclasses import asdict
from pathlib import Path

import pytest

from backend.core.breach_corpus import (
    _CACHE_TTL_SECONDS,
    BreachCorpus,
    BreachSite,
    _severity_label,
    _severity_score,
    _site_from_hibp,
)


def _raw(
    domain: str = "example.com",
    name: str = "Example",
    pwn_count: int = 100,
    data_classes: list[str] | None = None,
) -> dict:
    return {
        "Domain": domain,
        "Name": name,
        "BreachDate": "2024-01-02",
        "PwnCount": pwn_count,
        "DataClasses": data_classes or ["Email addresses"],
    }


def test_severity_score_passwords_multiplier() -> None:
    assert _severity_score(100, ["passwords"]) == 300


def test_severity_score_combined_multipliers() -> None:
    assert _severity_score(100, ["passwords", "credit cards"]) == 600


def test_severity_score_all_multipliers_stacked() -> None:
    classes = ["passwords", "credit cards", "financial data", "phone numbers"]
    assert _severity_score(100, classes) == 1_800


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (300_000_000, "critical"),
        (400_000_000, "critical"),
        (10_000_000, "high"),
        (299_999_999, "high"),
        (9_999_999, "medium"),
        (0, "medium"),
    ],
)
def test_severity_label_thresholds_parametrized(score: float, expected: str) -> None:
    assert _severity_label(score) == expected


def test_site_from_hibp_normal_fields() -> None:
    site = _site_from_hibp(
        _raw(
            domain="EXAMPLE.COM",
            name="Example Breach",
            pwn_count=100,
            data_classes=["Passwords", "Credit cards"],
        )
    )

    assert site == BreachSite(
        domain="example.com",
        breach_name="Example Breach",
        breach_date="2024-01-02",
        pwn_count=100,
        data_classes=["Passwords", "Credit cards"],
        severity_score=600,
        severity_label="medium",
    )


def test_site_from_hibp_skips_when_no_domain_no_name() -> None:
    assert _site_from_hibp({"Domain": "", "Name": ""}) is None


def test_site_from_hibp_invalid_pwn_count() -> None:
    site = _site_from_hibp(_raw(pwn_count="not-a-number"))  # type: ignore[arg-type]

    assert site is not None
    assert site.pwn_count == 0


def test_breach_corpus_load_sorts_by_severity_desc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus = BreachCorpus(tmp_path / "cache.json")
    payload = [
        _raw("low.example", "Low", 10),
        _raw("high.example", "High", 100, ["Passwords"]),
        _raw("middle.example", "Middle", 200),
    ]
    monkeypatch.setattr(corpus, "_fetch", lambda: payload)

    sites = corpus.load()

    assert [site.breach_name for site in sites] == ["High", "Middle", "Low"]


def test_breach_corpus_by_domain_case_insensitive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus = BreachCorpus(tmp_path / "cache.json")
    monkeypatch.setattr(corpus, "_fetch", lambda: [_raw()])

    assert corpus.by_domain("EXAMPLE.com") is not None


def test_breach_corpus_cache_round_trip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache_path = tmp_path / "cache.json"
    first = BreachCorpus(cache_path)
    monkeypatch.setattr(first, "_fetch", lambda: [_raw()])
    expected = first.load()
    second = BreachCorpus(cache_path)
    monkeypatch.setattr(
        second,
        "_fetch",
        lambda: pytest.fail("fresh cache should not fetch"),
    )

    assert second.load() == expected


def test_breach_corpus_cache_expired_refetches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache_path = tmp_path / "cache.json"
    cache_path.write_text(json.dumps([_raw(name="Stale")]), encoding="utf-8")
    expired = time.time() - _CACHE_TTL_SECONDS - 1
    os.utime(cache_path, (expired, expired))
    corpus = BreachCorpus(cache_path)
    monkeypatch.setattr(corpus, "_fetch", lambda: [_raw(name="Fresh")])

    assert corpus.load()[0].breach_name == "Fresh"


def test_breach_corpus_cache_corrupt_json_refetches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache_path = tmp_path / "cache.json"
    cache_path.write_text("{not-json", encoding="utf-8")
    corpus = BreachCorpus(cache_path)
    monkeypatch.setattr(corpus, "_fetch", lambda: [_raw(name="Fresh")])

    assert corpus.load()[0].breach_name == "Fresh"


def test_breach_corpus_get_top_filters_empty_domains(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus = BreachCorpus(tmp_path / "cache.json")
    monkeypatch.setattr(
        corpus,
        "_fetch",
        lambda: [_raw("", "No Domain", 1_000), _raw("example.com", "Example", 10)],
    )

    assert [site.domain for site in corpus.get_top()] == ["example.com"]


def test_breach_corpus_as_jsonable_returns_dicts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus = BreachCorpus(tmp_path / "cache.json")
    monkeypatch.setattr(corpus, "_fetch", lambda: [_raw()])
    expected = asdict(corpus.load()[0])

    assert corpus.as_jsonable() == [expected]
    assert set(expected) == {
        "domain",
        "breach_name",
        "breach_date",
        "pwn_count",
        "data_classes",
        "severity_score",
        "severity_label",
    }


def test_breach_corpus_load_caches_in_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus = BreachCorpus(tmp_path / "cache.json")
    calls = 0

    def fetch() -> list[dict]:
        nonlocal calls
        calls += 1
        return [_raw()]

    monkeypatch.setattr(corpus, "_fetch", fetch)
    first = corpus.load()
    second = corpus.load()

    assert first == second
    assert first is not second
    assert calls == 1
