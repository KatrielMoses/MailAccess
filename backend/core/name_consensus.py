from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from math import exp
from typing import Any


@dataclass
class NameCandidate:
    raw_name: str
    normalized_name: str
    source: str
    source_class: str
    base_weight: float
    quality_multiplier: float
    final_score: float
    is_username_class: bool
    flags: list[str] = field(default_factory=list)
    seen_at: datetime | None = None


@dataclass
class NameConsensusResult:
    confirmed_name: str | None
    name_confidence: str
    confidence_score: float
    name_sources: list[str]
    name_source_classes: list[str]
    name_reasoning: str
    conflicting_names: list[str]
    all_candidates: list[NameCandidate]


SOURCE_WEIGHTS: dict[str, tuple[float, str]] = {
    "pgp_keyserver": (1.00, "cryptographic"),
    "orcid_profile": (0.95, "institutional"),
    "linkedin_snippet": (0.85, "professional"),
    "keybase": (0.80, "cryptographic"),
    "academic_paper": (0.80, "academic"),
    "git_commit": (0.65, "developer"),
    "github_profile": (0.60, "developer"),
    "pypi_discovery": (0.55, "developer"),
    "npm_discovery": (0.55, "developer"),
    "gravatar": (0.50, "social"),
    "email_localpart": (0.50, "inferred"),
    "about_me": (0.45, "social"),
    "twitter_profile": (0.35, "social"),
    "hackernews": (0.35, "social"),
    "mastodon": (0.35, "social"),
    "etsy_shop": (0.30, "commerce"),
    "reddit": (0.15, "social"),
    "ebay_profile": (0.10, "commerce"),
}

ORG_TERMS = re.compile(
    r"\b(inc|llc|ltd|corp|corporation|foundation|group|technologies)\b",
    re.IGNORECASE,
)
BOT_TERMS = re.compile(r"(\[bot\]|github-actions|dependabot|renovate)", re.IGNORECASE)
EMAIL_RE = re.compile(r"<?[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}>?")
CREDENTIAL_RE = re.compile(
    r"(?:,\s*|\s+)(?:phd|md|mba|cissp|cpa|esq|jr|sr|iii|ii)\.?\s*$",
    re.IGNORECASE,
)

# Unicode-aware person name pattern: Latin (uppercase-first), Cyrillic, Arabic, CJK, Devanagari.
_LATIN_TOKEN = r"[A-Z][a-zA-Z''-]+"
_NONLATIN_TOKEN = r"[Ѐ-ӿ؀-ۿ一-鿿ऀ-ॿ]+"
_ANY_TOKEN = rf"(?:{_LATIN_TOKEN}|{_NONLATIN_TOKEN})"
_INITIAL = r"[A-Z]\."
PERSON_RE = re.compile(
    rf"^{_ANY_TOKEN}(?:\s+(?:{_INITIAL}|{_ANY_TOKEN})){{0,3}}$",
    re.UNICODE,
)

ROLE_LOCALPART_RE = re.compile(
    r"^(?:"
    r"noreply|no-reply|donotreply|do-not-reply|"
    r"support|help|info|contact|hello|hi|"
    r"admin|administrator|root|postmaster|hostmaster|"
    r"webmaster|abuse|security|privacy|legal|"
    r"notifications|alerts|updates|newsletter|"
    r"bot|daemon|mailer|automailer|system|"
    r"jobs|careers|hr|recruiting|hiring"
    r")$",
    re.IGNORECASE,
)
GENERIC_LOCALPARTS = {
    "about",
    "account",
    "accounts",
    "billing",
    "business",
    "community",
    "customerservice",
    "dev",
    "developer",
    "developers",
    "feedback",
    "mail",
    "marketing",
    "media",
    "news",
    "office",
    "press",
    "sales",
    "service",
    "team",
}
KNOWN_FREE_OR_ROLE_DOMAINS = {
    "aol.com",
    "fastmail.com",
    "fastmail.fm",
    "github.com",
    "gmx.com",
    "gmx.net",
    "gmail.com",
    "googlemail.com",
    "hotmail.co.uk",
    "hotmail.com",
    "icloud.com",
    "live.com",
    "mail.com",
    "mailinator.com",
    "mac.com",
    "me.com",
    "outlook.com",
    "pm.me",
    "proton.me",
    "protonmail.com",
    "tuta.io",
    "tutanota.com",
    "users.noreply.github.com",
    "yahoo.co.uk",
    "yahoo.com",
    "yandex.com",
    "yandex.ru",
    "zoho.com",
}
ROLE_SKIP_REASON = "Role/system email address — name inference skipped"

# Fuzzy-match threshold for rapidfuzz.fuzz.ratio (0–100 scale).
FUZZY_THRESHOLD = 88
# Token-set ratio threshold for display-name matching (slightly lower — subset
# matching is reliable when one string contains the tokens of the other).
TOKEN_SET_THRESHOLD = 85
# Minimum source base_weight to soften the single-word penalty (PGP, ORCID,
# LinkedIn, Keybase, academic). Below this, single-word names get the full 0.3
# crush; at or above, they only drop to 0.65 with a flag for analyst review.
HIGH_TRUST_BASE_WEIGHT = 0.80
# Source classes eligible for token_set_ratio (display-name subset matching).
# Lower-trust sources often carry longer free-text displays ("Software Engineer
# at Acme") that benefit from word-order-independent comparison.
_TOKEN_SET_SOURCE_CLASSES = frozenset({"social", "commerce", "inferred"})

# Stripped from canonical_name output to improve comparison accuracy.
_HONORIFIC_RE = re.compile(
    r"\b(?:jr|sr|ii|iii|iv|phd|md|esq)\.?\b",
    re.IGNORECASE,
)

# Metadata keys tried in order when extracting finding timestamps.
_SEEN_AT_KEYS = ("seen_at", "observed_at", "scraped_at", "last_seen", "collected_at", "timestamp")

# Top-100 most common English first names — single-word matches receive a stronger penalty.
_COMMON_FIRST_NAMES_TOP100 = frozenset({
    "james", "john", "robert", "michael", "william", "david", "richard",
    "joseph", "thomas", "charles", "christopher", "daniel", "matthew",
    "anthony", "mark", "donald", "steven", "paul", "andrew", "joshua",
    "kenneth", "kevin", "brian", "george", "timothy", "ronald", "edward",
    "jason", "jeffrey", "ryan", "jacob", "gary", "nicholas", "eric",
    "jonathan", "stephen", "larry", "justin", "scott", "brandon", "benjamin",
    "samuel", "raymond", "gregory", "frank", "alexander", "patrick", "jack",
    "dennis", "jerry", "mary", "patricia", "jennifer", "linda", "barbara",
    "elizabeth", "susan", "jessica", "sarah", "karen", "lisa", "nancy",
    "betty", "margaret", "sandra", "ashley", "dorothy", "kimberly", "emily",
    "donna", "michelle", "carol", "amanda", "melissa", "deborah", "stephanie",
    "rebecca", "sharon", "laura", "cynthia", "kathleen", "amy", "angela",
    "shirley", "anna", "brenda", "pamela", "emma", "nicole", "helen",
    "samantha", "katherine", "christine", "debra", "rachel", "carolyn",
    "janet", "catherine", "maria", "jane",
})


def _strip_symbol_chars(value: str) -> tuple[str, bool]:
    chars: list[str] = []
    stripped = False
    for char in value:
        if unicodedata.category(char) in {"So", "Sm", "Sk", "Sc"}:
            stripped = True
            continue
        chars.append(char)
    return "".join(chars), stripped


def _title_word(word: str) -> str:
    if len(word) == 1:
        return word.upper()
    return word[:1].upper() + word[1:].lower()


def _is_non_latin_name(value: str) -> bool:
    """
    Return True if the raw name is written in a non-Latin alphabetic script.

    Used to flag candidates whose original script (CJK, Cyrillic, Arabic,
    Devanagari, etc.) was transliterated to ASCII for clustering. The flag is
    informational; the candidate is still eligible for the normal multiplier
    when unidecode produces a valid Latin form, and only drops to 0.8 when
    transliteration fails the ASCII pattern check.
    """
    has_latin = False
    has_non_latin_alpha = False
    for char in value:
        if char.isspace() or char in "'-":
            continue
        if "A" <= char <= "Z" or "a" <= char <= "z":
            has_latin = True
        elif char.isalpha():
            # Any other alphabetic category (Lo, Lu, Ll in non-Latin blocks)
            has_non_latin_alpha = True
        # Digits, punctuation, and symbol categories are ignored for the
        # script classification — they don't shift the verdict.
    return has_non_latin_alpha and not has_latin


def normalize_name(raw_name: str) -> tuple[str, list[str], bool]:
    """
    Normalize a raw name string into a display-ready title-cased form.

    Pipeline: NFKC → unidecode (diacritic strip) → email/credential strip →
    CamelCase split → symbol strip → whitespace collapse → title-case.
    """
    flags: list[str] = []
    value = unicodedata.normalize("NFKC", str(raw_name).strip())

    from unidecode import unidecode as _unidecode  # lazy import for fast startup
    transliterated = _unidecode(value)
    if transliterated != value:
        flags.append("transliterated")
    value = transliterated

    value = EMAIL_RE.sub("", value)
    while True:
        updated = CREDENTIAL_RE.sub("", value).strip()
        if updated == value:
            break
        value = updated

    value = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", value)
    value = re.sub(r"(?<=\w)[_.-](?=\w)", " ", value)
    value, had_symbol = _strip_symbol_chars(value)
    if had_symbol:
        flags.append("emoji_stripped")

    value = re.sub(r"\s+", " ", value).strip()
    value = " ".join(_title_word(part) for part in value.split())

    is_username_class = bool(re.search(r"\d{2,}", value))
    if is_username_class:
        flags.append("username_class")
    return value, flags, is_username_class


def canonical_name(value: str) -> str:
    """
    Produce a lowercase comparison key suitable for fuzzy clustering.

    Steps (applied in order):
    1. NFKC normalize + unidecode transliteration (handles raw diacritic input)
    2. Lowercase
    3. Strip honorific suffixes: jr, sr, ii, iii, iv, phd, md, esq
    4. Strip punctuation (. , ') while preserving internal spaces
    5. Collapse whitespace
    """
    from unidecode import unidecode as _unidecode  # lazy import
    v = _unidecode(unicodedata.normalize("NFKC", value))
    v = v.lower()
    v = _HONORIFIC_RE.sub("", v)
    v = re.sub(r"[.,']", "", v)
    return " ".join(v.split())


def _tokens(value: str) -> set[str]:
    return {token.lower().strip(".") for token in value.split() if token.strip(".")}


def _email_localpart(email: str | None) -> str:
    if not email or "@" not in email:
        return ""
    return email.split("@", 1)[0].strip()


def _email_domain(email: str | None) -> str:
    if not email or "@" not in email:
        return ""
    return email.rsplit("@", 1)[1].strip().lower()


def _looks_like_person_localpart(localpart: str) -> bool:
    normalized, _flags, is_username_class = normalize_name(localpart)
    return bool(PERSON_RE.match(normalized)) and not is_username_class


def is_role_or_system_email(email: str | None) -> bool:
    localpart = _email_localpart(email).lower()
    if not localpart:
        return False
    if ROLE_LOCALPART_RE.match(localpart):
        return True

    domain = _email_domain(email)
    collapsed = re.sub(r"[^a-z]", "", localpart)
    if (
        domain in KNOWN_FREE_OR_ROLE_DOMAINS
        and collapsed in GENERIC_LOCALPARTS
        and not _looks_like_person_localpart(localpart)
    ):
        return True
    return False


def _quality_multiplier(
    raw_name: str,
    normalized_name: str,
    flags: list[str],
    source: str,
    email: str | None,
) -> float:
    base_weight, _ = SOURCE_WEIGHTS.get(source, (0.25, "other"))

    # Non-Western name detection — flag when the raw name uses a non-Latin
    # script (CJK, Cyrillic, Arabic, Devanagari, etc.). The flag is purely
    # informational when transliteration produced a valid ASCII form (1.0
    # multiplier). The existing 0.8 fallback below already covers the
    # transliteration-failure case from the brief's Step 5.
    if _is_non_latin_name(raw_name) and "non_western_name" not in flags:
        flags.append("non_western_name")

    multiplier = 1.0 if PERSON_RE.match(normalized_name) else 0.8
    if " " not in normalized_name:
        # Single-word name. High-trust sources (PGP, ORCID, LinkedIn, Keybase,
        # academic) carry a softer penalty so mononym profiles like "Madonna"
        # or mononym researchers can still contribute meaningfully to the
        # consensus instead of being crushed to 0.3.
        if base_weight >= HIGH_TRUST_BASE_WEIGHT:
            multiplier = min(multiplier, 0.65)
            if "single_word_high_trust" not in flags:
                flags.append("single_word_high_trust")
        else:
            multiplier = min(multiplier, 0.3)
    if any(char.isdigit() for char in normalized_name):
        multiplier = min(multiplier, 0.2)
    if "emoji_stripped" in flags:
        multiplier = min(multiplier, 0.1)

    localpart = _email_localpart(email)
    if localpart and raw_name.strip().lower() == localpart.lower():
        multiplier = min(multiplier, 0.2)

    if source == "email_localpart" and PERSON_RE.match(normalized_name):
        multiplier = max(multiplier, 1.1)
    return multiplier


def _temporal_decay(seen_at: datetime | None) -> float:
    """
    Exponential decay with a 5-year time constant: exp(-days / (365 × 5)).

    Reference values:
        0 years -> 1.00   (full weight)
        1 year  -> 0.82
        2 years -> 0.67
        5 years -> 0.37
       10 years -> 0.14

    Returns 1.0 when seen_at is None — modules that fail to attach a
    timestamp do not get penalised. This matches the long-standing
    `test_missing_seen_at_uses_no_decay` contract; modules that want the
    conservative 12-month default should populate `seen_at` themselves
    before calling `extract_name_candidates`.
    """
    if seen_at is None:
        return 1.0
    if seen_at.tzinfo is None:
        seen_at = seen_at.replace(tzinfo=timezone.utc)
    days = max(0.0, (datetime.now(timezone.utc) - seen_at).total_seconds() / 86400)
    return exp(-days / (365 * 5))


def _parse_seen_at(metadata: dict[str, Any]) -> datetime | None:
    for key in _SEEN_AT_KEYS:
        val = metadata.get(key)
        if val is None:
            continue
        if isinstance(val, datetime):
            return val
        if isinstance(val, str):
            try:
                return datetime.fromisoformat(val.replace("Z", "+00:00"))
            except ValueError:
                pass
    return None


def _empty_result(
    reason: str, candidates: list[NameCandidate] | None = None
) -> NameConsensusResult:
    return NameConsensusResult(
        confirmed_name=None,
        name_confidence="unknown",
        confidence_score=0.0,
        name_sources=[],
        name_source_classes=[],
        name_reasoning=reason,
        conflicting_names=[],
        all_candidates=candidates or [],
    )


class NameConsensusEngine:
    def __init__(self, target_email: str | None = None) -> None:
        self.target_email = target_email

    def resolve(self, raw_candidates: list[dict[str, Any] | NameCandidate]) -> NameConsensusResult:
        if is_role_or_system_email(self.target_email):
            return _empty_result(ROLE_SKIP_REASON)

        candidates = self._prepare_candidates(raw_candidates)
        if not candidates:
            return _empty_result("No usable name signals found.")
        if all(candidate.is_username_class for candidate in candidates):
            return _empty_result("Only username-class name signals were found.", candidates)

        clusters = self._cluster(candidates)
        if not clusters:
            return _empty_result("No usable name clusters found.", candidates)

        top = clusters[0]
        second = clusters[1] if len(clusters) > 1 else None
        conflict = bool(second and top["score"] < 1.5 * second["score"])

        confidence = self._confidence_for_cluster(top)
        if conflict and confidence in {"confirmed", "probable"}:
            confidence = "possible"

        names = [str(top["name"])]
        if conflict and second:
            names.append(str(second["name"]))

        source_classes = sorted({c.source_class for c in top["candidates"]})
        sources = sorted({c.source for c in top["candidates"]})
        reasoning = self._reasoning(top, second, confidence, conflict)
        return NameConsensusResult(
            confirmed_name=str(top["name"]) if confidence != "unknown" else None,
            name_confidence=confidence,
            confidence_score=round(float(top["score"]), 3),
            name_sources=sources,
            name_source_classes=source_classes,
            name_reasoning=reasoning,
            conflicting_names=names if conflict else [],
            all_candidates=candidates,
        )

    def _prepare_candidates(
        self, raw_candidates: list[dict[str, Any] | NameCandidate]
    ) -> list[NameCandidate]:
        prepared: list[NameCandidate] = []
        for item in raw_candidates:
            if isinstance(item, NameCandidate):
                prepared.append(item)
                continue

            raw_name = str(item.get("raw_name") or item.get("name") or "").strip()
            source = str(item.get("source") or "").strip()
            if not raw_name or not source:
                continue
            if BOT_TERMS.search(raw_name) or ORG_TERMS.search(raw_name):
                continue
            if self.target_email and raw_name.strip().lower() == self.target_email.strip().lower():
                continue

            normalized, flags, is_username_class = normalize_name(raw_name)
            if not normalized or len(normalized) > 40:
                continue
            if ORG_TERMS.search(normalized) or BOT_TERMS.search(normalized):
                continue
            if self.target_email and normalized.lower() == self.target_email.strip().lower():
                continue

            seen_at_raw = item.get("seen_at")
            seen_at: datetime | None = seen_at_raw if isinstance(seen_at_raw, datetime) else None

            base_weight, source_class = SOURCE_WEIGHTS.get(source, (0.25, "other"))
            multiplier = _quality_multiplier(
                raw_name, normalized, flags, source, self.target_email
            )
            if multiplier <= 0:
                continue

            decay = _temporal_decay(seen_at)
            prepared.append(
                NameCandidate(
                    raw_name=raw_name,
                    normalized_name=normalized,
                    source=source,
                    source_class=source_class,
                    base_weight=base_weight,
                    quality_multiplier=multiplier,
                    final_score=base_weight * multiplier * decay,
                    is_username_class=is_username_class,
                    flags=flags,
                    seen_at=seen_at,
                )
            )

        by_name: dict[str, list[NameCandidate]] = {}
        for candidate in prepared:
            by_name.setdefault(canonical_name(candidate.normalized_name), []).append(candidate)

        for same_name in by_name.values():
            if len({candidate.source for candidate in same_name}) < 2:
                continue
            for candidate in same_name:
                bonus = 1.3
                localpart_match = any(
                    other.source == "email_localpart" and other is not candidate
                    for other in same_name
                )
                if localpart_match and candidate.source != "email_localpart":
                    bonus *= 1.1
                candidate.quality_multiplier = min(candidate.quality_multiplier * bonus, 2.0)
                decay = _temporal_decay(candidate.seen_at)
                candidate.final_score = candidate.base_weight * candidate.quality_multiplier * decay

        return prepared

    def _cluster(self, candidates: list[NameCandidate]) -> list[dict[str, Any]]:
        from rapidfuzz import fuzz as _fuzz  # lazy import

        clusters: list[dict[str, Any]] = []
        for candidate in candidates:
            placed = False
            candidate_canonical = canonical_name(candidate.normalized_name)
            candidate_tokens = _tokens(candidate.normalized_name)
            for cluster in clusters:
                cluster_canonical = canonical_name(str(cluster["name"]))
                cluster_tokens = _tokens(str(cluster["name"]))

                # Pick the comparison metric. token_set_ratio is preferred
                # for display-style strings from lower-trust source classes
                # (3+ tokens) because it handles word-order-independent
                # subset matches ("Software Engineer at Acme" vs "Software
                # Engineer"). fuzz.ratio is used for 1–2 token names where
                # a stricter character-level comparison is appropriate.
                use_token_set = (
                    len(candidate_tokens) >= 3
                    and candidate.source_class in _TOKEN_SET_SOURCE_CLASSES
                )
                if use_token_set:
                    score = _fuzz.token_set_ratio(candidate_canonical, cluster_canonical)
                    threshold = TOKEN_SET_THRESHOLD
                    # token_set_ratio inherently encodes token overlap, so
                    # no extra token-share cap is needed.
                    token_cap_satisfied = True
                else:
                    score = _fuzz.ratio(candidate_canonical, cluster_canonical)
                    threshold = FUZZY_THRESHOLD
                    # Token-share cap: prevents "John Smith" from merging
                    # with "Jane Stone" at ~80% ratio when the two share
                    # no real-world identity. Two clusters must share at
                    # least one token before a fuzzy ratio match is accepted.
                    token_cap_satisfied = bool(candidate_tokens & cluster_tokens)

                subset = (
                    candidate_tokens < cluster_tokens
                    or cluster_tokens < candidate_tokens
                )

                # Decide which path produced the merge. token_set_ratio is
                # preferred for display names, then the ratio path with
                # token-share cap, then plain strict-token subset as a
                # fallback. Tracking *which* path won matters for reasoning:
                # a token_set_ratio merge is a display-name event, a ratio
                # merge is a typo/nickname event, a pure-subset merge is
                # trivial and not worth surfacing.
                merge = False
                used_token_set_for_merge = False
                if use_token_set and score >= threshold:
                    merge = True
                    used_token_set_for_merge = True
                elif score >= threshold and token_cap_satisfied:
                    merge = True
                elif subset:
                    merge = True

                if merge:
                    # Record the merge only when canonicals actually differ.
                    # Exact-canonical matches are trivial equalities, not
                    # "fuzzy" events.
                    if candidate_canonical != cluster_canonical:
                        if used_token_set_for_merge:
                            cluster["display_matches"].append(
                                (
                                    candidate.normalized_name,
                                    candidate.source,
                                    str(cluster["name"]),
                                )
                            )
                        elif not subset:
                            # Only record as a fuzzy merge when the path was
                            # actually the ratio path, not the trivial
                            # subset fallback.
                            cluster["fuzzy_merges"].append(
                                (
                                    candidate.normalized_name,
                                    candidate.source,
                                    str(cluster["name"]),
                                )
                            )
                    cluster["candidates"].append(candidate)
                    if len(candidate.normalized_name) > len(str(cluster["name"])):
                        cluster["name"] = candidate.normalized_name
                    placed = True
                    break
            if not placed:
                clusters.append({
                    "name": candidate.normalized_name,
                    "candidates": [candidate],
                    "fuzzy_merges": [],
                    "display_matches": [],
                })

        for cluster in clusters:
            members = cluster["candidates"]
            score = sum(candidate.final_score for candidate in members)
            class_weights: dict[str, float] = {}
            for candidate in members:
                current = class_weights.get(candidate.source_class, 0.0)
                class_weights[candidate.source_class] = max(current, candidate.base_weight)
            if len(class_weights) > 1:
                additional = sorted(class_weights.values(), reverse=True)[1:]
                score += sum(weight * 0.3 for weight in additional)
            cluster["score"] = score

        clusters.sort(key=lambda cluster: float(cluster["score"]), reverse=True)
        return clusters

    def _confidence_for_cluster(self, cluster: dict[str, Any]) -> str:
        score = float(cluster["score"])
        members: list[NameCandidate] = cluster["candidates"]
        source_classes = {candidate.source_class for candidate in members}
        has_crypto = any(candidate.source_class == "cryptographic" for candidate in members)
        source_count = len({candidate.source for candidate in members})

        single_word = all(" " not in candidate.normalized_name for candidate in members)
        if single_word and not has_crypto:
            return "possible" if score >= 0.5 else "unknown"

        if score >= 2.5 and (len(source_classes) >= 3 or (has_crypto and source_count >= 2)):
            confidence = "confirmed"
        elif score >= 1.5 and len(source_classes) >= 2:
            confidence = "probable"
        elif score >= 0.5 and source_classes:
            confidence = "possible"
        else:
            confidence = "unknown"

        # Common-name penalty: prevent over-confidence when all name tokens are common.
        # Single-word top-100 first name → cap at "possible".
        # Compound where every token is in the common-names corpus → cap at "probable".
        from backend.core.common_names import is_common_name as _is_common_name  # lazy import
        tokens = [t.strip(".,'-") for t in str(cluster["name"]).lower().split() if t.strip(".,'-")]
        if tokens and all(_is_common_name(t) for t in tokens):
            if len(tokens) == 1 and tokens[0] in _COMMON_FIRST_NAMES_TOP100:
                if confidence in ("confirmed", "probable"):
                    confidence = "possible"
            elif confidence == "confirmed":
                confidence = "probable"

        return confidence

    def _reasoning(
        self,
        top: dict[str, Any],
        second: dict[str, Any] | None,
        confidence: str,
        conflict: bool,
    ) -> str:
        members: list[NameCandidate] = top["candidates"]
        sources = sorted({candidate.source.replace("_", " ").title() for candidate in members})
        classes = sorted({candidate.source_class for candidate in members})
        reason = (
            f"{', '.join(sources)} support this name across "
            f"{len(classes)} independent source class{'es' if len(classes) != 1 else ''}."
        )
        if any(candidate.source == "email_localpart" for candidate in members):
            reason += " Email local-part corroborates."

        # Fuzzy merge — surfaced when two distinct canonical forms collapsed
        # into one cluster via fuzz.ratio (≥ 88, shared token). One event
        # shown to keep the reasoning tight.
        for from_name, from_source, to_name in top.get("fuzzy_merges", []):
            reason += (
                f" Fuzzy match: '{from_name}' ({from_source.replace('_', ' ').title()}) "
                f"≈ '{to_name}' merged."
            )
            break

        # Display-name subset match — token_set_ratio collapsed a longer
        # display string into a shorter one (LinkedIn bio "Software Engineer
        # at Acme" → GitHub bio "Software Engineer").
        for from_name, from_source, to_name in top.get("display_matches", []):
            reason += (
                f" Display name subset match: '{to_name}' confirmed as subset "
                f"of {from_source.replace('_', ' ').title()} display."
            )
            break

        # Non-Western name — flagged when any member originated in a
        # non-Latin script (CJK, Cyrillic, Arabic, Devanagari, etc.).
        if any("non_western_name" in candidate.flags for candidate in members):
            reason += " Non-Western name detected — Unicode matching applied."

        # Temporal decay — surfaced when the oldest signal in the cluster
        # has decayed below 0.5 (≈ 3.5 years with the 5-year time constant).
        # Tells the analyst the consensus is being carried by fresher signals.
        seen_ats = [candidate.seen_at for candidate in members if candidate.seen_at is not None]
        if seen_ats:
            oldest = min(seen_ats)
            if _temporal_decay(oldest) < 0.5:
                reason += (
                    f" Note: oldest signal from {oldest.year} "
                    f"(weight reduced by temporal decay)."
                )

        if conflict and second:
            reason += (
                f" Conflict detected: {top['name']} and {second['name']} have similar scores; "
                f"confidence capped at {confidence}."
            )
        return reason


def extract_name_candidates(
    collected: dict[str, Any] | list[Any],
    canonical_email: str | None = None,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    def add(raw_name: Any, source: str, seen_at: datetime | None = None) -> None:
        text = str(raw_name or "").strip()
        if text:
            entry: dict[str, Any] = {"raw_name": text, "source": source}
            if seen_at is not None:
                entry["seen_at"] = seen_at
            candidates.append(entry)

    localpart = _email_localpart(canonical_email)
    if localpart:
        add(localpart, "email_localpart")

    def iter_module_findings() -> list[tuple[str, list[Any]]]:
        if isinstance(collected, list):
            return [("", collected)]

        rows: list[tuple[str, list[Any]]] = []
        for module_name, result in collected.items():
            if isinstance(result, list):
                raw_findings = result
            elif isinstance(result, dict):
                raw_findings = result.get("findings", [])
            else:
                raw_findings = getattr(result, "findings", [])
            findings = raw_findings if isinstance(raw_findings, list) else []
            rows.append((str(module_name), findings))
        return rows

    for module_name, findings in iter_module_findings():
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
            ts = _parse_seen_at(metadata)
            platform = str(finding.get("platform") or "")
            if platform == "github_user":
                add(metadata.get("name"), "github_profile", ts)
            elif platform == "gravatar_profile":
                add(metadata.get("display_name") or metadata.get("name"), "gravatar", ts)
            elif platform == "keybase_profile":
                add(metadata.get("full_name") or metadata.get("name"), "keybase", ts)
            elif platform == "twitter_profile":
                add(metadata.get("display_name"), "twitter_profile", ts)
            elif platform == "linkedin_snippet":
                add(metadata.get("display_name"), "linkedin_snippet", ts)
            elif platform == "pgp_keyserver":
                add(metadata.get("uid_name"), "pgp_keyserver", ts)
            elif platform == "orcid_profile":
                add(metadata.get("full_name") or metadata.get("credit_name"), "orcid_profile", ts)
            elif platform == "hackernews_profile":
                add(metadata.get("extracted_name"), "hackernews", ts)
            elif module_name == "pypi_discovery":
                add(metadata.get("author"), "pypi_discovery", ts)
            elif module_name == "npm_discovery":
                add(metadata.get("author_name"), "npm_discovery", ts)
            elif module_name == "github_commits":
                name = metadata.get("author_name") or metadata.get("real_name_from_git")
                add(name, "git_commit", ts)

    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for candidate in candidates:
        key = (candidate["raw_name"].lower(), candidate["source"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique
