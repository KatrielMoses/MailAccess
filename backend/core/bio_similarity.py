"""Fuzzy bio-text similarity via token-set ratio matching."""

from __future__ import annotations

import re

_URL_RE = re.compile(r"https?://\S+")
_MIN_NON_WS = 5


def normalize_bio(text: str) -> str:
    """Strip URLs, collapse whitespace, and lowercase."""
    text = _URL_RE.sub("", text)
    return " ".join(text.split()).lower()


def bio_similarity(text_a: str, text_b: str) -> float:
    """Return token_set_ratio score (0.0–100.0) for two bio strings.

    Returns 0.0 for empty, whitespace-only, or very short inputs (< 5
    non-whitespace characters after URL stripping and normalization).
    """
    from rapidfuzz import fuzz

    a = normalize_bio(text_a)
    b = normalize_bio(text_b)

    if not a or not b:
        return 0.0
    if len(a.replace(" ", "")) < _MIN_NON_WS or len(b.replace(" ", "")) < _MIN_NON_WS:
        return 0.0

    return float(fuzz.token_set_ratio(a, b))
