from __future__ import annotations

import pytest

from backend.core.bio_similarity import bio_similarity, normalize_bio


def test_identical_strings_return_100() -> None:
    assert bio_similarity("Dad of 3 | Software Engineer", "Dad of 3 | Software Engineer") == 100.0


def test_word_reordered_bio_scores_high() -> None:
    a = "Software Engineer | Coffee enthusiast | Dad of 3"
    b = "Dad of 3 | Software Engineer | Coffee enthusiast"
    assert bio_similarity(a, b) >= 85.0


def test_unrelated_bios_score_low() -> None:
    a = "Software Engineer at Acme | Python lover | Open source contributor"
    b = "Artist and musician | Traveling the world | Foodie and chef"
    assert bio_similarity(a, b) < 70.0


@pytest.mark.parametrize(
    "a, b",
    [
        ("", "some bio text here"),
        ("some bio text here", ""),
        ("", ""),
        ("   ", "some bio text here"),
        ("\t\n", "\t\n"),
    ],
)
def test_empty_or_whitespace_returns_zero(a: str, b: str) -> None:
    assert bio_similarity(a, b) == 0.0


@pytest.mark.parametrize("short", ["hi", "abc", "ok!", "no", "x"])
def test_very_short_input_returns_zero(short: str) -> None:
    assert bio_similarity(short, "some longer bio text here") == 0.0
    assert bio_similarity("some longer bio text here", short) == 0.0


def test_url_stripping_same_words_score_high() -> None:
    a = "Software Engineer | https://github.com/user1 | Coffee enthusiast"
    b = "Software Engineer | https://twitter.com/user2 | Coffee enthusiast"
    # After stripping URLs both reduce to identical text
    assert bio_similarity(a, b) >= 85.0


def test_different_urls_with_different_words_still_compared_correctly() -> None:
    a = "Python dev | https://github.com/user1"
    b = "Java developer enthusiast | https://twitter.com/user2"
    # After stripping URLs: "python dev" vs "java developer enthusiast" — low similarity
    score = bio_similarity(a, b)
    assert score < 85.0


# ---------------------------------------------------------------------------
# normalize_bio
# ---------------------------------------------------------------------------


def test_normalize_bio_lowercases() -> None:
    assert normalize_bio("Hello World") == "hello world"


def test_normalize_bio_collapses_whitespace() -> None:
    assert normalize_bio("Hello   World\t  ") == "hello world"


def test_normalize_bio_strips_urls() -> None:
    result = normalize_bio("Check out https://example.com my profile")
    assert "https://" not in result
    assert "example.com" not in result
    assert "check out" in result
    assert "my profile" in result


def test_normalize_bio_strips_http_url() -> None:
    result = normalize_bio("Visit http://old-site.net for more")
    assert "http://" not in result
    assert "old-site.net" not in result


def test_normalize_bio_empty_returns_empty() -> None:
    assert normalize_bio("") == ""
    assert normalize_bio("   ") == ""


def test_normalize_bio_url_only_returns_empty_or_whitespace() -> None:
    result = normalize_bio("https://example.com/path?q=1")
    assert result.strip() == ""
