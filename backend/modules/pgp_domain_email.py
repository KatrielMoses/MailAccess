"""PGP Keyserver email discovery (domain harvest mode) — W5 of 0.10.0.

This module queries public PGP keyserver endpoints for keys whose
UIDs (User IDs — the name + email attached to a key) match the
target domain.  It slots into Phase 1 of the domain harvest
orchestrator (the parallel fast / cheap-sources phase) and runs
concurrently with ``commoncrawl_email`` and ``code_and_cert_email``
via ``asyncio.gather``.

Why a separate module from the existing ``pgp_keyserver``:
    The existing ``pgp_keyserver`` module is a SINGLE-EMAIL-mode
    investigator — given a known email, fetch the key that
    attests to it and extract the real name(s) from the UIDs.
    This new ``pgp_domain_email`` module is DOMAIN-mode — given
    a target domain, find ALL keys whose UIDs contain the domain
    string and harvest the matching emails.

    The existing ``pgp_keyserver`` is NOT modified; consolidation
    between the two execution paths is left as a future cleanup
    (the audit calls out to note overlap in code comments).

Yield reality check (from the audit):
    Since ``sks-keyservers.net`` shut down in 2021 and
    ``keys.openpgp.org`` now requires personal email verification
    for keys to be publicly searchable, ~99% of historical keys
    are filtered out.  Realistic yield is 1-5% for tech-heavy
    domains.  We ship this module anyway because the hits that
    DO surface are extremely high-confidence (a PGP UID is a
    deliberate, user-verified assertion of identity).

Why a strict domain filter still matters here:
    Keyservers can return UID strings that mention a domain in
    unrelated contexts (e.g. ``random_user <bob@gmail.com>`` might
    show up in a search for ``example.com`` if some signature
    block contains the string).  We pull every email out of every
    UID and apply the same strict "domain must equal the target"
    filter used by the npm and PyPI modules.

API choice:
    Two public keyservers are queried:

    * ``https://keys.openpgp.org/search?q={domain}`` — modern JSON
      endpoint, requires no key, but limited historical coverage.
    * ``https://keyserver.ubuntu.com/pks/lookup?op=vindex&search={domain}``
      — older HKP protocol, returns an HTML index page, broader
      historical coverage.

    Both return enough information to extract UIDs without needing
    a full key fetch (saving bandwidth + parsing time).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config import settings
from ..core.email_confidence import compute_confidence_breakdown, label_for_score
from ..core.email_extraction import extract_emails
from ..core.http_client import build_client
from ..core.role_classifier import classify_email
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

# Public keyserver endpoints — no authentication required.
_OPENPGP_SEARCH_URL = "https://keys.openpgp.org/search"
_UBUNTU_HKP_URL = "https://keyserver.ubuntu.com/pks/lookup"

_REQUEST_TIMEOUT = 10.0
_RATE_LIMIT_SECONDS = 2.0
_MAX_KEYS_PER_SOURCE = 20

# Source-weight identifier (mirrors SOURCE_WEIGHTS key in email_confidence).
# PGP UIDs are deliberate, user-verified assertions of identity —
# equivalent to ``ca_attested`` for the confidence model.
_TYPE = "pgp_uid"


@dataclass
class _SubSourceOutcome:
    source_id: str  # "openpgp_search" | "ubuntu_hkp"
    ok: bool = False
    error: str | None = None
    count: int = 0
    keys_checked: int = 0
    emails: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


def _email_domain_matches(email: str, target_domain: str) -> bool:
    """Strict equality filter on the email's domain half."""
    if not email or "@" not in email:
        return False
    _, _, dom = email.strip().lower().rpartition("@")
    return bool(dom) and dom == target_domain.lower()


class PgpDomainEmailModule(BaseModule):
    """DOMAIN-mode: discover PGP UIDs matching the target domain."""

    name = "pgp_domain_email"
    description = (
        "Email discovery via PGP keyserver domain search — "
        "extracts UID-bearing public keys from keys.openpgp.org "
        "and the Ubuntu HKP keyserver."
    )
    requires_key = False
    default_enabled = False  # domain harvest mode only

    async def run(self, target: str) -> ModuleResult:  # type: ignore[override]
        if not settings.enable_pgp_domain_email:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "pgp_domain_email disabled — "
                    "set ENABLE_PGP_DOMAIN_EMAIL=true to enable"
                ],
            )

        domain = (target or "").strip().lower()
        if not domain or "." not in domain:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["pgp_domain_email: invalid domain"],
                metadata={"skip_reason": "invalid_domain", "domain": domain},
            )

        outcomes: dict[str, _SubSourceOutcome] = {
            "openpgp_search": _SubSourceOutcome(source_id="openpgp_search"),
            "ubuntu_hkp": _SubSourceOutcome(source_id="ubuntu_hkp"),
        }

        aggregated: dict[str, dict[str, Any]] = {}

        try:
            async with build_client(timeout=_REQUEST_TIMEOUT) as client:
                openpgp_task = asyncio.create_task(
                    self._openpgp_search(client, domain)
                )
                ubuntu_task = asyncio.create_task(
                    self._ubuntu_hkp(client, domain)
                )
                openpgp_outcome = await openpgp_task
                ubuntu_outcome = await ubuntu_task
                outcomes["openpgp_search"] = openpgp_outcome
                outcomes["ubuntu_hkp"] = ubuntu_outcome
                for outcome in (openpgp_outcome, ubuntu_outcome):
                    for email, evidence in outcome.emails.items():
                        bucket = aggregated.setdefault(
                            email, {"types": set(), "evidence": []}
                        )
                        bucket["types"].add(_TYPE)
                        bucket["evidence"].extend(evidence)
        except Exception as exc:
            _LOG.error("pgp_domain_email: catastrophic error: %s", exc)
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"pgp_domain_email: {exc}"],
                metadata={"domain": domain},
            )

        # ------------------------------------------------------------------
        # Build findings
        # ------------------------------------------------------------------
        findings: list[dict[str, Any]] = []
        role_count = 0
        personal_count = 0
        on_domain_count = 0

        for email in sorted(aggregated):
            data = aggregated[email]
            confidence_info = compute_confidence_breakdown(
                source_types=[_TYPE],
                is_smtp_verified=False,
                is_ca_attested=False,
                oldest_timestamp=None,
            )
            classification = classify_email(email)
            local_part = email.split("@", 1)[0]
            _, _, dom = email.partition("@")
            on_domain = bool(dom and dom == domain)
            if on_domain:
                on_domain_count += 1

            findings.append(
                {
                    "platform": "pgp_domain_email",
                    "profile_url": (
                        f"https://keys.openpgp.org/search?q={email}"
                    ),
                    "username": local_part,
                    "confidence": label_for_score(confidence_info.score).lower(),
                    "metadata": {
                        "email": email,
                        "on_domain": on_domain,
                        "source_type": _TYPE,
                        "all_sources": sorted(data["types"]),
                        "evidence": data["evidence"][:8],
                        "is_role": classification.is_role,
                        "role_match_type": classification.match_type,
                        "role_confidence": classification.confidence,
                        "role_matched_prefix": classification.matched_prefix,
                        "confidence_score": round(confidence_info.score, 4),
                        "confidence_breakdown": confidence_info.breakdown,
                    },
                }
            )
            if classification.is_role:
                role_count += 1
            else:
                personal_count += 1

        ok_count = sum(
            1
            for o in outcomes.values()
            if o.ok or o.keys_checked or o.emails
        )
        if ok_count == 0:
            status = ModuleStatus.FAILED
        elif ok_count == 1:
            status = ModuleStatus.PARTIAL
        else:
            status = ModuleStatus.SUCCESS

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "domain": domain,
                "openpgp_keys_checked": outcomes["openpgp_search"].keys_checked,
                "openpgp_emails_found": outcomes["openpgp_search"].count,
                "ubuntu_keys_checked": outcomes["ubuntu_hkp"].keys_checked,
                "ubuntu_emails_found": outcomes["ubuntu_hkp"].count,
                "total_unique_emails": len(aggregated),
                "on_domain_emails": on_domain_count,
                "role_accounts": role_count,
                "personal_emails": personal_count,
                "sub_source_outcomes": {
                    sid: {"ok": o.ok, "error": o.error, "count": o.count}
                    for sid, o in outcomes.items()
                },
            },
        )

    # ----------------------------------------------------------------------
    # Sub-source fetchers
    # ----------------------------------------------------------------------
    async def _throttle(self) -> None:
        await asyncio.sleep(_RATE_LIMIT_SECONDS)

    async def _openpgp_search(
        self, client: httpx.AsyncClient, domain: str
    ) -> _SubSourceOutcome:
        """Query ``keys.openpgp.org/search?q={domain}``.

        Returns a JSON list of key objects with embedded UID strings
        in the ``uids`` field.  We only need the UID text — no key
        material — to extract candidate emails.
        """
        outcome = _SubSourceOutcome(source_id="openpgp_search")
        try:
            await self._throttle()
            response = await client.get(
                _OPENPGP_SEARCH_URL,
                params={"q": domain},
                headers={"Accept": "application/json"},
                timeout=_REQUEST_TIMEOUT,
            )
        except httpx.TimeoutException:
            outcome.error = "openpgp_timeout"
            return outcome
        except Exception as exc:
            outcome.error = f"openpgp_request:{exc}"
            return outcome

        if response.status_code == 429:
            outcome.error = "openpgp_rate_limited"
            return outcome
        if response.status_code != 200:
            outcome.error = f"openpgp_http_{response.status_code}"
            return outcome

        try:
            data = response.json()
        except Exception as exc:
            outcome.error = f"openpgp_invalid_json:{exc}"
            return outcome

        keys = data if isinstance(data, list) else []
        outcome.keys_checked = min(len(keys), _MAX_KEYS_PER_SOURCE)
        outcome.ok = True

        for key_obj in keys[:_MAX_KEYS_PER_SOURCE]:
            if not isinstance(key_obj, dict):
                continue
            uids = key_obj.get("uids")
            if not isinstance(uids, list):
                continue
            for uid in uids:
                if not isinstance(uid, str):
                    continue
                self._extract_uids(outcome, uid, domain, "openpgp_search")

        return outcome

    async def _ubuntu_hkp(
        self, client: httpx.AsyncClient, domain: str
    ) -> _SubSourceOutcome:
        """Query the Ubuntu keyserver HKP ``vindex`` endpoint.

        Returns an HTML index page listing keys matching the search
        term.  Each row contains the UID string for the key, which
        is all we need to harvest emails.
        """
        outcome = _SubSourceOutcome(source_id="ubuntu_hkp")
        try:
            await self._throttle()
            response = await client.get(
                _UBUNTU_HKP_URL,
                params={
                    "op": "vindex",
                    "search": domain,
                    "fingerprint": "on",
                },
                headers={"Accept": "text/html"},
                timeout=_REQUEST_TIMEOUT,
            )
        except httpx.TimeoutException:
            outcome.error = "ubuntu_timeout"
            return outcome
        except Exception as exc:
            outcome.error = f"ubuntu_request:{exc}"
            return outcome

        if response.status_code == 429:
            outcome.error = "ubuntu_rate_limited"
            return outcome
        if response.status_code != 200:
            outcome.error = f"ubuntu_http_{response.status_code}"
            return outcome

        # The vindex HTML uses ``<pre>`` blocks with one UID per line.
        # We run the response through extract_emails as a safety net
        # — it covers every email-shaped token in the page, including
        # ones outside the obvious UID lines.  Then we re-filter on
        # the strict domain match.
        outcome.keys_checked = response.text.count("<br>") or len(
            response.text.splitlines()
        )
        outcome.ok = True

        for extracted in extract_emails(response.text, target_domain=domain):
            if not _email_domain_matches(extracted.email, domain):
                continue
            outcome.emails.setdefault(extracted.email, []).append(
                {
                    "source": "ubuntu_hkp",
                    "snippet": extracted.source_text_snippet[:120],
                }
            )
            outcome.count += 1

        return outcome

    def _extract_uids(
        self,
        outcome: _SubSourceOutcome,
        uid_text: str,
        domain: str,
        source_label: str,
    ) -> None:
        """Extract emails from an OpenPGP UID string.

        UID strings look like::

            Jane Doe <jane@example.com>

        or sometimes with comments::

            Jane Doe (work) <jane@example.com>

        We use the shared ``extract_emails`` helper for the
        email-detection step (it handles deobfuscation + placeholder
        filtering for free), then apply the strict domain filter.
        """
        if not uid_text:
            return
        for extracted in extract_emails(uid_text, target_domain=domain):
            if not _email_domain_matches(extracted.email, domain):
                continue
            outcome.emails.setdefault(extracted.email, []).append(
                {
                    "source": source_label,
                    "uid": uid_text[:200],
                }
            )
            outcome.count += 1