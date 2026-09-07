"""Phase 3B — deterministic title → seniority band + department classifier.

Seniority filtering ("VPs and above") is a primary paid-tool lead filter. This
maps a free-text ``job_title`` onto a small, ordered set of seniority bands and a
coarse department, **deterministically and explainably** — every classification
records *why* a title mapped to a band (the matched term). It reuses the
lexicon-pattern approach already used for ``industry_vocabulary.json`` /
``role_prefixes.json`` rather than any ML (Phase 4 may calibrate later).

Design principles (brief's constraints):

* **Ambiguous or unrecognised → ``unknown``, never a forced band.** A bare
  "Principal" (Principal Engineer? Principal / Partner?) or a non-English title
  we don't recognise returns ``unknown`` rather than guessing. This keeps 3A's
  evidence-or-null contract: an unproven seniority is *unknown*, not a
  plausible-sounding default.
* **Highest band wins.** Titles like "VP of Engineering" carry both a band token
  ("VP") and a department token ("Engineering"); the band is taken from the
  most-senior token present, the department from the strongest department token.
* **Deterministic.** Ordered rules, first match by precedence — same input always
  yields the same output.

No collection, no I/O — a pure function over a string.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Seniority bands, most-senior first. ``unknown`` is terminal (not a band, the
# absence of one).
BAND_C_LEVEL = "c-level"
BAND_VP = "vp"
BAND_DIRECTOR = "director"
BAND_MANAGER = "manager"
BAND_IC = "ic"
BAND_UNKNOWN = "unknown"

# Precedence order used when several band tokens co-occur in one title.
_BAND_ORDER = (BAND_C_LEVEL, BAND_VP, BAND_DIRECTOR, BAND_MANAGER, BAND_IC)


@dataclass(frozen=True)
class SeniorityClassification:
    """The explainable result of classifying a single title."""

    band: str  # one of BAND_* (BAND_UNKNOWN when nothing matched)
    department: str | None  # coarse department, or None
    matched_term: str | None  # the token that decided the band
    reason: str  # human-readable rationale
    is_ambiguous: bool  # True when the title is recognisably conflicting


# ---------------------------------------------------------------------------
# Band lexicon. Each entry is (band, compiled regex). Patterns use word
# boundaries so "director" doesn't match "directory" and "vp" doesn't match a
# random substring. Order within a band does not matter; band precedence does.
# ---------------------------------------------------------------------------

def _rx(*words: str) -> re.Pattern[str]:
    # Escape, allow interior whitespace runs, anchor on word-ish boundaries.
    parts = [re.escape(w).replace(r"\ ", r"\s+") for w in words]
    return re.compile(r"(?<![a-z])(?:" + "|".join(parts) + r")(?![a-z])", re.IGNORECASE)


_BAND_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        BAND_C_LEVEL,
        _rx(
            "ceo", "cto", "cfo", "coo", "cio", "ciso", "cmo", "cpo", "cro", "cco",
            "cdo", "chief", "founder", "co-founder", "cofounder", "owner",
            "proprietor",
        ),
    ),
    (
        # "President" is C-level, but NOT when it's part of "vice president" /
        # "SVP/EVP/AVP" (those are the VP band). Exclude that case explicitly so
        # "Vice President, Sales" resolves to VP, not C-level.
        BAND_C_LEVEL,
        re.compile(r"(?<![a-z])(?<!vice )(?<!vice-)president(?![a-z])", re.IGNORECASE),
    ),
    (
        BAND_VP,
        _rx(
            "vp", "svp", "evp", "avp", "vice president", "vice-president",
            "senior vice president", "executive vice president",
        ),
    ),
    (
        BAND_DIRECTOR,
        _rx(
            "director", "head of", "managing director", "partner",
        ),
    ),
    (
        BAND_MANAGER,
        _rx(
            "manager", "mgr", "supervisor", "team lead", "team leader",
            "foreman", "principal engineer", "principal scientist",
            "principal architect", "staff engineer",
        ),
    ),
    (
        BAND_IC,
        _rx(
            "engineer", "developer", "programmer", "analyst", "specialist",
            "associate", "consultant", "designer", "scientist", "coordinator",
            "representative", "accountant", "administrator", "technician",
            "intern", "assistant", "clerk", "agent", "writer", "editor",
            "researcher", "recruiter", "architect", "strategist", "advisor",
            "producer", "buyer", "planner", "operator", "nurse", "teacher",
            "professor", "attorney", "counsel", "paralegal", "bookkeeper",
        ),
    ),
]

# Bare tokens that are genuinely ambiguous on their own — recognisable but not
# resolvable to a band without more context. Return unknown + is_ambiguous.
_AMBIGUOUS_RX = _rx("principal", "lead", "executive", "officer", "fellow", "staff")

# ---------------------------------------------------------------------------
# Department lexicon: (department, regex). First match by list order wins.
# ---------------------------------------------------------------------------
_DEPARTMENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("engineering", _rx(
        "engineer", "engineering", "developer", "development", "devops", "sre",
        "software", "backend", "frontend", "full stack", "full-stack", "platform",
        "infrastructure", "qa", "quality assurance",
    )),
    ("data", _rx(
        "data", "analytics", "analyst", "machine learning", "ml", "ai",
        "data science", "data scientist", "bi", "business intelligence",
    )),
    ("product", _rx("product", "product manager", "product owner", "cpo")),
    ("design", _rx("design", "designer", "ux", "ui", "user experience", "creative")),
    ("sales", _rx(
        "sales", "account executive", "account manager", "business development",
        "bdr", "sdr", "revenue", "cro",
    )),
    ("marketing", _rx(
        "marketing", "growth", "seo", "sem", "content", "brand", "communications",
        "comms", "pr", "public relations", "demand generation", "cmo",
    )),
    ("finance", _rx(
        "finance", "financial", "accounting", "accountant", "controller",
        "treasurer", "cfo", "audit", "fp&a", "bookkeeper",
    )),
    ("people", _rx(
        "hr", "human resources", "people", "recruit", "recruiter", "talent",
        "chro", "people ops",
    )),
    ("legal", _rx(
        "legal", "counsel", "attorney", "compliance", "paralegal", "general counsel",
    )),
    ("operations", _rx("operations", "operational", "ops", "coo", "logistics", "supply chain")),
    ("it", _rx(
        "it ", "information technology", "sysadmin", "system administrator",
        "network", "helpdesk", "help desk", "cio", "ciso", "security",
    )),
    ("support", _rx(
        "support", "customer success", "customer service", "success", "care",
    )),
    ("executive", _rx(
        "ceo", "founder", "co-founder", "cofounder", "president", "owner",
        "managing director", "chief executive",
    )),
]


def _detect_department(title: str) -> str | None:
    for dept, pattern in _DEPARTMENT_PATTERNS:
        if pattern.search(title):
            return dept
    return None


def classify_title(title: str | None) -> SeniorityClassification:
    """Classify a free-text job title into a seniority band + department.

    Returns ``BAND_UNKNOWN`` (with ``is_ambiguous`` set when the title *is*
    recognisable but conflicting/underspecified) rather than forcing a band.
    """
    raw = " ".join(str(title or "").split())
    if not raw:
        return SeniorityClassification(
            BAND_UNKNOWN, None, None, "empty title", is_ambiguous=False
        )

    normalized = raw.lower()
    department = _detect_department(normalized)

    # Find every band whose lexicon matches; take the most-senior by precedence.
    matches: dict[str, str] = {}
    for band, pattern in _BAND_PATTERNS:
        m = pattern.search(normalized)
        if m and band not in matches:
            matches[band] = m.group(0)

    if matches:
        for band in _BAND_ORDER:
            if band in matches:
                term = matches[band]
                return SeniorityClassification(
                    band,
                    department,
                    term,
                    f"title {raw!r} → {band} (matched {term!r})",
                    is_ambiguous=False,
                )

    # No band token, but a recognisable-yet-ambiguous token → unknown, flagged.
    amb = _AMBIGUOUS_RX.search(normalized)
    if amb:
        return SeniorityClassification(
            BAND_UNKNOWN,
            department,
            amb.group(0),
            f"title {raw!r} is ambiguous (token {amb.group(0)!r} needs context)",
            is_ambiguous=True,
        )

    return SeniorityClassification(
        BAND_UNKNOWN,
        department,
        None,
        f"title {raw!r} matched no known seniority band",
        is_ambiguous=False,
    )
