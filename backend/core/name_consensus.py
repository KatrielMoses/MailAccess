from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
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
PERSON_RE = re.compile(r"^[A-Z][a-z]+(?:\s+[A-Z]\.)?\s+[A-Z][a-z]+$")
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


def _ascii_transliterate(value: str) -> tuple[str, bool]:
    normalized = unicodedata.normalize("NFC", value)
    ascii_value = normalized.encode("ascii", "ignore").decode("ascii")
    return ascii_value, ascii_value != normalized


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


def normalize_name(raw_name: str) -> tuple[str, list[str], bool]:
    flags: list[str] = []
    value, transliterated = _ascii_transliterate(str(raw_name).strip())
    if transliterated:
        flags.append("transliterated")

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
    return re.sub(r"[\s-]+", "", value.lower())


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
    multiplier = 1.0 if PERSON_RE.match(normalized_name) else 0.8
    if " " not in normalized_name:
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


def _empty_result(reason: str, candidates: list[NameCandidate] | None = None) -> NameConsensusResult:
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

            base_weight, source_class = SOURCE_WEIGHTS.get(source, (0.25, "other"))
            multiplier = _quality_multiplier(
                raw_name, normalized, flags, source, self.target_email
            )
            if multiplier <= 0:
                continue
            prepared.append(
                NameCandidate(
                    raw_name=raw_name,
                    normalized_name=normalized,
                    source=source,
                    source_class=source_class,
                    base_weight=base_weight,
                    quality_multiplier=multiplier,
                    final_score=base_weight * multiplier,
                    is_username_class=is_username_class,
                    flags=flags,
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
                candidate.final_score = candidate.base_weight * candidate.quality_multiplier

        return prepared

    def _cluster(self, candidates: list[NameCandidate]) -> list[dict[str, Any]]:
        clusters: list[dict[str, Any]] = []
        for candidate in candidates:
            placed = False
            candidate_tokens = _tokens(candidate.normalized_name)
            for cluster in clusters:
                cluster_tokens = _tokens(str(cluster["name"]))
                same = canonical_name(candidate.normalized_name) == canonical_name(str(cluster["name"]))
                subset = candidate_tokens < cluster_tokens or cluster_tokens < candidate_tokens
                if same or subset:
                    cluster["candidates"].append(candidate)
                    if len(candidate.normalized_name) > len(str(cluster["name"])):
                        cluster["name"] = candidate.normalized_name
                    placed = True
                    break
            if not placed:
                clusters.append({"name": candidate.normalized_name, "candidates": [candidate]})

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
            return "confirmed"
        if score >= 1.5 and len(source_classes) >= 2:
            return "probable"
        if score >= 0.5 and source_classes:
            return "possible"
        return "unknown"

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
        if conflict and second:
            reason += (
                f" Conflict detected: {top['name']} and {second['name']} have similar scores; "
                f"confidence capped at {confidence}."
            )
        return reason


def extract_name_candidates(
    collected: dict[str, Any] | list[Any],
    canonical_email: str | None = None,
) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []

    def add(raw_name: Any, source: str) -> None:
        text = str(raw_name or "").strip()
        if text:
            candidates.append({"raw_name": text, "source": source})

    localpart = _email_localpart(canonical_email)
    if localpart:
        add(localpart, "email_localpart")

    module_source = {
        "github_commits": "git_commit",
        "pypi_discovery": "pypi_discovery",
        "npm_discovery": "npm_discovery",
        "twitter_profile": "twitter_profile",
        "linkedin_serp": "linkedin_snippet",
        "keybase": "keybase",
        "gravatar": "gravatar",
        "marketplace_profile": "etsy_shop",
    }

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
            platform = str(finding.get("platform") or "")
            if platform == "github_user":
                add(metadata.get("name"), "github_profile")
            elif platform == "gravatar_profile":
                add(metadata.get("display_name") or metadata.get("name"), "gravatar")
            elif platform == "keybase_profile":
                add(metadata.get("full_name") or metadata.get("name"), "keybase")
            elif platform == "twitter_profile":
                add(metadata.get("display_name"), "twitter_profile")
            elif platform == "linkedin_snippet":
                add(metadata.get("display_name"), "linkedin_snippet")
            elif platform == "pgp_keyserver":
                add(metadata.get("uid_name"), "pgp_keyserver")
            elif platform == "orcid_profile":
                add(metadata.get("full_name") or metadata.get("credit_name"), "orcid_profile")
            elif platform == "hackernews_profile":
                add(metadata.get("extracted_name"), "hackernews")
            elif module_name == "pypi_discovery":
                add(metadata.get("author"), "pypi_discovery")
            elif module_name == "npm_discovery":
                add(metadata.get("author_name"), "npm_discovery")
            elif module_name == "github_commits":
                add(metadata.get("author_name") or metadata.get("real_name_from_git"), "git_commit")

    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, str]] = []
    for candidate in candidates:
        key = (candidate["raw_name"].lower(), candidate["source"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique
