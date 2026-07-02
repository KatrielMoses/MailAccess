"""Dork query construction for domain email harvesting.

Five ordered query templates — most effective first per research.  The
list is intentionally short: every extra dork is one more request that
gets us closer to a CAPTCHA wall.  ``build_dork_queries`` is pure
logic, fully testable, and includes a *lite* mode (patterns 1-2 only)
for fast harvests where exhaustive coverage is not required.

Why these patterns, in this order:

1. ``"@{domain}"`` — highest recall, picks up everything indexed for
   the literal ``@domain.com`` token.
2. ``"@{domain}" -site:{domain}`` — drops the target's own pages
   (those are covered better by Common Crawl WARC fetches) and keeps
   third-party mentions: LinkedIn bios, forum posts, press releases.
3. ``site:{domain} "@{domain}"`` — backstop for self-hosted pages the
   CC index may have missed.
4. ``site:linkedin.com/in/ "@{domain}"`` — employee profile hits
   that don't surface under pattern #1 because the email lives in a
   profile field rather than visible page text.
5. ``"@{domain}" filetype:pdf`` — press kits, leaked contact lists,
   signature blocks.  Often the highest-quality hits when present.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DorkQuery:
    query: str
    pattern_id: int
    description: str


# Index 0 maps to ``pattern_id`` 1 in the docstring — public IDs are
# 1-based to match documentation and log output.
_DORK_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        '"@{domain}"',
        "Bare quoted @domain token — highest recall, broad net.",
    ),
    (
        '"@{domain}" -site:{domain}',
        "Bare quoted token excluding the target site — external mentions only.",
    ),
    (
        'site:{domain} "@{domain}"',
        "Self-hosted pages mentioning the literal email — backstop for CC gaps.",
    ),
    (
        'site:linkedin.com/in/ "@{domain}"',
        "LinkedIn profile bios that mention the email address.",
    ),
    (
        '"@{domain}" filetype:pdf',
        "PDF documents (press kits, contact sheets, resumes) with the email.",
    ),
)


def build_dork_queries(domain: str, lite_mode: bool = False) -> list[DorkQuery]:
    """Return the list of dork queries for *domain*.

    Parameters
    ----------
    domain:
        Target domain (e.g. ``example.com``).  Treated case-insensitively.
    lite_mode:
        When ``True``, only patterns 1 and 2 (the broadest / cheapest
        two) are returned — used for fast harvests or rate-limited
        environments where every query counts.
    """

    cleaned = (domain or "").strip().lower()
    if not is_valid_domain(cleaned):
        return []

    pattern_limit = 2 if lite_mode else len(_DORK_PATTERNS)
    queries: list[DorkQuery] = []
    for index, (template, description) in enumerate(_DORK_PATTERNS[:pattern_limit]):
        rendered = template.replace("{domain}", cleaned)
        queries.append(
            DorkQuery(
                query=rendered,
                pattern_id=index + 1,  # 1-based public IDs
                description=description,
            )
        )
    return queries


def is_valid_domain(value: str) -> bool:
    """Cheap domain-shape check used by callers and tests."""
    if not isinstance(value, str):
        return False
    cleaned = value.strip().lower()
    if not cleaned or "." not in cleaned:
        return False
    if cleaned.startswith(".") or cleaned.endswith("."):
        return False
    return True
