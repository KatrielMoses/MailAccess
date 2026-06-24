from __future__ import annotations

import json

import pytest

from backend.core import disposable_domains
from backend.modules.maigret_platforms import _finding


@pytest.fixture(autouse=True)
def reset_disposable_domains_cache(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    corpus_path = tmp_path / "disposable_domains.json"
    corpus_path.write_text(
        json.dumps(["guerrillamail.com", "mailinator.com"]),
        encoding="utf-8",
    )
    monkeypatch.setattr(disposable_domains, "_CORPUS_PATH", corpus_path)
    monkeypatch.setattr(disposable_domains, "_disposable_domains", None)


def test_disposable_domain_matches_corpus_case_insensitively() -> None:
    assert disposable_domains.is_disposable_domain("mailinator.com") is True
    assert disposable_domains.is_disposable_domain("MAILINATOR.COM") is True
    assert disposable_domains.is_disposable_domain("gmail.com") is False


@pytest.mark.parametrize(
    ("email", "expected"),
    [
        ("user@mailinator.com", True),
        ("  User@MAILINATOR.COM  ", True),
        ("user@gmail.com", False),
        ("", False),
    ],
)
def test_disposable_email(email: str, expected: bool) -> None:
    assert disposable_domains.is_disposable_email(email) is expected


@pytest.mark.parametrize(
    ("email", "expected"),
    [
        ("user@example.com", "example.com"),
        ("User@EXAMPLE.COM", "example.com"),
        ("  user@example.com  ", "example.com"),
        ("not-an-email", ""),
        ("@example.com", ""),
        ("user@", ""),
        ("user@@example.com", ""),
    ],
)
def test_extract_domain(email: str, expected: str) -> None:
    assert disposable_domains.extract_domain(email) == expected


def test_missing_corpus_fails_open(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setattr(disposable_domains, "_CORPUS_PATH", tmp_path / "missing.json")

    assert disposable_domains.is_disposable_domain("mailinator.com") is False


def test_malformed_corpus_fails_open() -> None:
    disposable_domains._CORPUS_PATH.write_text("{not valid json", encoding="utf-8")

    assert disposable_domains.is_disposable_domain("mailinator.com") is False


def test_corpus_is_loaded_only_once(monkeypatch: pytest.MonkeyPatch) -> None:
    read_calls = 0
    path_type = type(disposable_domains._CORPUS_PATH)
    original_read_text = path_type.read_text

    def counted_read_text(path, *args, **kwargs):
        nonlocal read_calls
        read_calls += 1
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(path_type, "read_text", counted_read_text)

    assert disposable_domains.is_disposable_domain("mailinator.com") is True
    assert disposable_domains.is_disposable_email("user@guerrillamail.com") is True
    assert read_calls == 1


def test_maigret_finding_downgrades_disposable_email() -> None:
    finding = _finding(
        "Example",
        {"checkType": "message", "presenseStrs": ["profile"]},
        "user@mailinator.com",
        "https://example.test/user",
        1,
    )

    assert finding["confidence"] == "low"
    assert finding["metadata"]["fp_warnings"] == ["disposable_email_domain"]


def test_maigret_finding_preserves_both_fp_warnings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("backend.core.common_names.is_common_username", lambda _value: True)
    finding = _finding(
        "Example",
        {"checkType": "message", "presenseStrs": ["profile"]},
        "john",
        "https://example.test/john",
        1,
        email="john@mailinator.com",
    )

    assert finding["metadata"]["fp_warnings"] == [
        "common_username_no_corroboration",
        "disposable_email_domain",
    ]
