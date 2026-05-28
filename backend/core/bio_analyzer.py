from __future__ import annotations

import re
from dataclasses import dataclass, field

# Matches international and North American phone numbers (9–15 digits with separators)
_PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(\+\d{1,3}[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{1,4}[\s.\-]?\d{1,9}"
    r"|\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4})"
    r"(?!\d)"
)

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")

_AGGREGATOR_DOMAINS = frozenset(
    {
        "linktr.ee",
        "about.me",
        "beacons.ai",
        "bio.link",
        "linkin.bio",
        "campsite.bio",
        "allmylinks.com",
    }
)


@dataclass
class BioAnalysis:
    phones: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    aggregator_urls: list[str] = field(default_factory=list)


def analyze_bio(text: str, exclude_domain: str | None = None) -> BioAnalysis:
    """Extract phones, emails, URLs, and aggregator links from free-form bio text."""
    if not text:
        return BioAnalysis()

    phones: list[str] = []
    for m in _PHONE_RE.finditer(text):
        raw = m.group(1).strip()
        # Require at least 7 digits to avoid false positives on version numbers etc.
        digits = re.sub(r"\D", "", raw)
        if len(digits) >= 7:
            phones.append(raw)

    emails = _EMAIL_RE.findall(text)
    if exclude_domain:
        emails = [e for e in emails if exclude_domain.lower() not in e.lower()]

    urls = _URL_RE.findall(text)
    aggregator_urls = [u for u in urls if _is_aggregator(u)]

    return BioAnalysis(
        phones=_dedup(phones),
        emails=_dedup(emails),
        urls=_dedup(urls),
        aggregator_urls=_dedup(aggregator_urls),
    )


def is_aggregator_url(url: str) -> bool:
    return _is_aggregator(url)


def _is_aggregator(url: str) -> bool:
    return any(d in url for d in _AGGREGATOR_DOMAINS)


def _dedup(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
