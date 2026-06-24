"""Detect shadow profiles — same display name, different recovery email.

The V1 detector (``find_shadow_pairs``) groups findings by display name and
emits pairs whose emails differ.  It does not consider whether the two
identities share platforms.

The V2 detector (``find_shadow_v2_pairs``) extends V1 with the constraints
from Phase 6B.2:
    * The primary investigation's name_consensus must have produced a
      non-null ``confirmed_name``.
    * The alternate email must be associated with at least one finding
      whose display name matches the confirmed name.
    * The alternate email must share at least ``min_shared_platforms``
      platforms with the primary investigation (default 2).

V2 is additive — V1 keeps running unchanged for analysts who want the
looser signal.
"""

from __future__ import annotations

import re
from typing import Any

# name_consensus.normalize_name returns (str, list[str], bool) — the full
# pipeline (unidecode, camel-case split, title-case) is heavier than needed
# here.  We reimplement a lighter version: lowercase + strip punctuation +
# collapse whitespace.
_PUNCT_RE = re.compile(r"[^\w\s]")

_USERNAME_KEYS = ("username", "login", "user", "handle", "matched_username")
_DISPLAY_KEYS = ("display_name", "name", "full_name", "real_name")
_EMAIL_KEYS = ("email", "primary_email", "recovery_email", "alternate_email",
               "discovered_email", "backup_email", "secondary_email")


def normalize_display_name(name: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace.

    Returns empty string for non-string or empty inputs.
    """
    if not isinstance(name, str) or not name:
        return ""
    cleaned = _PUNCT_RE.sub(" ", name)
    return " ".join(cleaned.lower().split())


def _extract_fields(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    """Return (platform, email, username, display_name) from a finding dict."""
    payload: dict[str, Any] = finding.get("data") if "data" in finding else finding  # type: ignore[assignment]
    if not isinstance(payload, dict):
        payload = {}
    meta: dict[str, Any] = payload.get("metadata") or {}
    if not isinstance(meta, dict):
        meta = {}

    platform = str(
        payload.get("platform") or finding.get("module_name") or "unknown"
    )

    email = ""
    for key in _EMAIL_KEYS:
        for src in (payload, meta):
            val = src.get(key)
            if isinstance(val, str) and val.strip():
                email = val.strip().lower()
                break
        if email:
            break

    username = ""
    for key in _USERNAME_KEYS:
        for src in (payload, meta):
            val = src.get(key)
            if isinstance(val, str) and val.strip():
                username = val.strip().lower()
                break
        if username:
            break

    display_name = ""
    for key in _DISPLAY_KEYS:
        for src in (payload, meta):
            val = src.get(key)
            if isinstance(val, str) and val.strip():
                display_name = val.strip()
                break
        if display_name:
            break

    return platform, email, username, display_name


class ShadowProfileDetector:
    """Find accounts where the same person operates under a different email.

    Groups findings by normalized display name (requiring at least
    ``min_name_token_count`` tokens to avoid single-word false positives),
    then pairs findings that have different primary email addresses.

    Three findings sharing a name yield C(3,2) = 3 shadow pairs.
    """

    def __init__(self, min_name_token_count: int = 2) -> None:
        self.min_name_token_count = min_name_token_count

    def find_shadow_pairs(
        self,
        findings: list[dict[str, Any]],
        anchor_email: str = "",
    ) -> list[dict[str, Any]]:
        """Return shadow-profile pairs from a list of finding dicts.

        A pair qualifies when two findings share a normalized display name
        (the OR condition from the spec — shared display name is always true
        within a group) and have different primary email addresses.

        Confidence is "high" when username also matches, "medium" when only
        the display name matches.

        ``anchor_email`` (the investigation target) is excluded: any pair
        where either email equals the anchor is skipped, since the anchor is
        the starting point, not a shadow account.
        """
        anchor = anchor_email.strip().lower() if anchor_email else ""

        # Index by normalized display name
        name_groups: dict[str, list[tuple[str, str, str, str]]] = {}
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            platform, email, username, display_name = _extract_fields(finding)
            if not display_name:
                continue
            norm = normalize_display_name(display_name)
            if not norm or len(norm.split()) < self.min_name_token_count:
                continue
            name_groups.setdefault(norm, []).append(
                (platform, email, username, display_name)
            )

        pairs: list[dict[str, Any]] = []
        for norm_name, group in name_groups.items():
            if len(group) < 2:
                continue
            for i, (plat_a, email_a, uname_a, dname_a) in enumerate(group):
                for plat_b, email_b, uname_b, dname_b in group[i + 1 :]:
                    if not email_a or not email_b:
                        continue
                    if email_a == email_b:
                        continue
                    if anchor and (email_a == anchor or email_b == anchor):
                        continue

                    shared_username = ""
                    if uname_a and uname_b and uname_a == uname_b:
                        shared_username = uname_a

                    confidence = "high" if shared_username else "medium"

                    pairs.append({
                        "primary_email": email_a,
                        "primary_platform": plat_a,
                        "shadow_email": email_b,
                        "shadow_platform": plat_b,
                        "display_name": dname_a,
                        "shared_username": shared_username,
                        "confidence": confidence,
                    })

        return pairs

    # ------------------------------------------------------------------
    # V2 detector — Phase 6B.2
    # ------------------------------------------------------------------

    def find_shadow_v2_pairs(
        self,
        findings: list[dict[str, Any]],
        name_consensus: dict[str, Any] | None = None,
        alternate_emails: list[str] | None = None,
        primary_email: str = "",
        min_shared_platforms: int = 2,
    ) -> list[dict[str, Any]]:
        """Return V2 shadow-profile findings.

        A V2 finding is emitted when ALL of the following hold:

        1. ``name_consensus`` resolved to a non-null ``confirmed_name``.
        2. The alternate email appears in ``alternate_emails`` (or is
           recoverable from an ``alternate_email`` finding).
        3. The alternate email has at least one finding whose display
           name normalises to the same value as the confirmed name.
        4. The alternate email shares at least ``min_shared_platforms``
           platforms with the primary investigation (default 2).

        Output schema (one dict per qualifying alternate email):
            {
                "primary_email": str,
                "shadow_email": str,
                "shared_name": str,
                "name_confidence": str,
                "shared_platforms": list[str],
                "platform_overlap_count": int,
            }

        Returns an empty list when the consensus did not produce a name
        or no alternate emails satisfy the overlap constraint — this
        keeps the V2 detector a no-op for investigations where the
        primary consensus is still "unknown".
        """
        confirmed_name = (
            (name_consensus or {}).get("confirmed_name") if name_consensus else None
        )
        if not confirmed_name:
            return []
        name_confidence = (
            (name_consensus or {}).get("name_confidence")
            if name_consensus
            else "unknown"
        ) or "unknown"
        normalised_name = normalize_display_name(confirmed_name)
        if not normalised_name:
            return []

        primary = (primary_email or "").strip().lower()

        # Build the set of "alternate" emails.  Accept either an explicit
        # list or extract them from any findings whose module is
        # "alternate_email" — the alternate_email module's own findings
        # already encode the discovered_email.  We also sweep the wider
        # finding set for any ``alternate_email`` / ``discovered_email``
        # / ``recovery_email`` field so the detector works when the
        # caller passes the full finding list instead of a curated
        # alternate-email subset.
        candidate_emails: set[str] = set()
        if alternate_emails:
            for value in alternate_emails:
                if isinstance(value, str) and value.strip():
                    candidate_emails.add(value.strip().lower())
        if not candidate_emails:
            for finding in findings or []:
                if not isinstance(finding, dict):
                    continue
                payload = finding.get("data") if "data" in finding else finding
                if not isinstance(payload, dict):
                    continue
                meta = payload.get("metadata") or {}
                if not isinstance(meta, dict):
                    meta = {}
                for key in (
                    "discovered_email",
                    "alternate_email",
                    "recovery_email",
                    "backup_email",
                    "secondary_email",
                ):
                    value = payload.get(key) or meta.get(key)
                    if isinstance(value, str) and value.strip():
                        email = value.strip().lower()
                        if email and email != primary:
                            candidate_emails.add(email)

        if not candidate_emails:
            return []

        # Index primary platforms: every platform where the primary
        # email has a confirmed presence.  We exclude post-primary
        # module outputs (alternate_email, infra_cluster, shadow_profile)
        # and any finding whose email field is not the anchor — this
        # keeps the alt_email's platforms out of the primary bucket
        # when both are passed in the same finding list.
        primary_platforms: set[str] = set()
        for finding in findings or []:
            if not isinstance(finding, dict):
                continue
            module = str(finding.get("module_name") or "").lower()
            if module in {"alternate_email", "infra_cluster", "shadow_profile"}:
                continue
            payload = finding.get("data") if "data" in finding else finding
            if not isinstance(payload, dict):
                continue
            meta = payload.get("metadata") or {}
            if not isinstance(meta, dict):
                meta = {}
            # Skip findings tied to a non-anchor email — those belong to
            # the alternate identity, not the primary.
            finding_email = ""
            for key in _EMAIL_KEYS:
                value = payload.get(key) if key in payload else meta.get(key)
                if isinstance(value, str) and value.strip():
                    finding_email = value.strip().lower()
                    break
            if finding_email and finding_email != primary:
                continue
            platform = str(
                payload.get("platform") or module or "unknown"
            ).strip().lower()
            if platform:
                primary_platforms.add(platform)

        results: list[dict[str, Any]] = []
        for alt_email in sorted(candidate_emails):
            if alt_email == primary:
                continue
            alt_platforms, alt_names = self._index_alternate(
                findings or [], alt_email
            )
            # Constraint 3: alternate email must carry the confirmed name
            # in at least one of its display-name fields.
            if not any(
                normalize_display_name(name) == normalised_name
                for name in alt_names
                if isinstance(name, str)
            ):
                continue
            # Constraint 4: shared platforms.
            shared = sorted(primary_platforms & alt_platforms)
            if len(shared) < min_shared_platforms:
                continue
            results.append({
                "primary_email": primary,
                "shadow_email": alt_email,
                "shared_name": confirmed_name,
                "name_confidence": name_confidence,
                "shared_platforms": shared,
                "platform_overlap_count": len(shared),
            })

        # Stable order: most overlapping pair first.
        results.sort(key=lambda r: r["platform_overlap_count"], reverse=True)
        return results

    @staticmethod
    def _index_alternate(
        findings: list[dict[str, Any]], alt_email: str
    ) -> tuple[set[str], list[str]]:
        """Return (platforms, display_names) for a given alternate email.

        Walks every finding looking for the alt_email in the documented
        email-related fields, and collects the platform + display name
        of the matching findings.  This is intentionally permissive: a
        breach record that mentions the alt email is enough to count a
        platform, since breach data ties the alt email to a service.
        """
        platforms: set[str] = set()
        names: list[str] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            payload = finding.get("data") if "data" in finding else finding
            if not isinstance(payload, dict):
                continue
            meta = payload.get("metadata") or {}
            if not isinstance(meta, dict):
                meta = {}
            for key in _EMAIL_KEYS:
                value = payload.get(key) if key in payload else meta.get(key)
                if isinstance(value, str) and value.strip().lower() == alt_email:
                    platform = str(
                        payload.get("platform")
                        or finding.get("module_name")
                        or "unknown"
                    ).strip().lower()
                    if platform:
                        platforms.add(platform)
                    for name_key in _DISPLAY_KEYS:
                        name_val = payload.get(name_key) or meta.get(name_key)
                        if isinstance(name_val, str) and name_val.strip():
                            names.append(name_val)
                    # Don't double-count the same email's appearances on
                    # a single finding.
                    break
        return platforms, names
