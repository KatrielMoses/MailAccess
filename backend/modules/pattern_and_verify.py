"""Pattern + verify module — Phase C2 of the 0.10.0 rebuild.

Reads Phase C1's :class:`EmployeeNameResult` list and turns each
employee into one or more candidate email addresses.  When SMTP
verification is enabled in settings, candidates are probed through
the safety-bounded :mod:`backend.core.smtp_verifier`.  When SMTP
verification is disabled (the SAFE default), the module returns
"unverified" patterns only — no network probes of any kind.

This module does NOT itself invoke the Phase C1 employee-name
discovery.  Phase C3's orchestrator wires the two together; this
module keeps its single responsibility.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from ..config import settings
from ..core.email_confidence import (
    compute_confidence_breakdown,
    label_for_score,
)
from ..core.email_pattern_generator import (
    GeneratedEmail,
    confirmed_pattern_priority,
    generate_patterns,
)
from ..core.mx_resolver import MXRecord, resolve_mx
from ..core.role_classifier import classify_email
from ..core.smtp_verifier import (
    DEFAULT_PROBE_DELAY,
    DEFAULT_SENDER,
    MAX_PROBES_HARD_CAP,
    SMTPVerifier,
)
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

# Source-type identifiers — mirror SOURCE_WEIGHTS keys from
# email_confidence.py so callers can compute confidence via the
# standard pipeline.
_SOURCE_TYPE_VERIFIED = "permutation_verified"
_SOURCE_TYPE_CATCHALL = "permutation_catchall"
_SOURCE_TYPE_UNVERIFIED = "permutation_unverified"
_TOP_THREE_TEMPLATES = [
    "{first}.{last}@{domain}",
    "{first}@{domain}",
    "{f}{last}@{domain}",
]


@dataclass
class EmployeeNameResult:
    """Shape-compatible view of Phase C1's class.

    We re-declare the fields here (rather than importing) so this
    module stays standalone-testable without a C1 dependency.
    """

    name: str
    sources: list[str] = field(default_factory=list)
    source_count: int = 0
    title_or_role: str | None = None
    confidence: float = 0.5
    source_urls: list[str] = field(default_factory=list)


@dataclass
class GeneratedPatternResult:
    email: str
    pattern_template: str
    source_name: str
    verification_status: str  # verified / catchall / unverified / inconclusive / not_attempted
    confidence_score: float = 0.0
    confidence_label: str = "low"
    is_role: bool = False
    role_match_type: str | None = None
    source_type: str = _SOURCE_TYPE_UNVERIFIED


class PatternAndVerifyModule(BaseModule):
    name = "pattern_and_verify"
    description = (
        "Generates email patterns from discovered employee names and "
        "optionally verifies via SMTP probing."
    )
    requires_key = False
    default_enabled = False

    async def run(
        self,
        domain: str,
        employee_names: list[EmployeeNameResult] | None = None,
        *,
        enable_smtp: bool | None = None,
    ) -> ModuleResult:  # type: ignore[override]
        """Generate email patterns and optionally verify via SMTP.

        Parameters
        ----------
        domain:
            Target domain (e.g. ``"example.com"``).
        employee_names:
            Optional list of names from upstream discovery. Empty list
            is fine — the module returns SUCCESS with no findings.
        enable_smtp:
            Explicit SMTP opt-in. MUST-FIX M3: when the orchestrator
            calls this method it MUST pass ``enable_smtp`` explicitly,
            which is the only value consulted. The function falls back
            to ``settings.enable_smtp_verification`` ONLY when called
            standalone (e.g. from a test) and ``enable_smtp`` is None.
            This eliminates the previous race where the orchestrator
            mutated ``settings.enable_smtp_verification`` globally and
            any concurrent reader saw the wrong value.
        """
        if not settings.enable_email_pattern_and_verify:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "pattern_and_verify disabled — "
                    "set ENABLE_EMAIL_PATTERN_AND_VERIFY=true to enable"
                ],
            )

        cleaned_domain = (domain or "").strip().lower()
        if not cleaned_domain or "." not in cleaned_domain:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["pattern_and_verify: invalid domain"],
                metadata={"skip_reason": "invalid_domain", "domain": cleaned_domain},
            )

        if not employee_names:
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                findings=[],
                metadata={
                    "note": "no employee names provided; nothing to generate",
                    "domain": cleaned_domain,
                },
            )

        candidates: list[GeneratedPatternResult] = []
        confirmed_pattern: str | None = None
        names_processed_high = 0
        names_processed_medium = 0
        names_skipped_low = 0
        patterns_generated_high = 0
        patterns_generated_medium = 0
        patterns_skipped = 0
        skipped_low_confidence_names: list[dict[str, Any]] = []
        pattern_generation_by_name: list[dict[str, Any]] = []

        high_threshold = float(settings.pattern_high_confidence_threshold)
        medium_threshold = float(settings.pattern_medium_confidence_threshold)

        # ------------------------------------------------------------------
        # 1. SMTP opt-in.  MUST-FIX M3: explicit parameter wins; only
        #    fall back to settings when called outside an orchestrator.
        # ------------------------------------------------------------------
        smtp_enabled = (
            bool(enable_smtp)
            if enable_smtp is not None
            else bool(settings.enable_smtp_verification)
        )

        batch_meta: dict[str, Any] = {}
        probes_used_total = 0

        def _base_tier(confidence: float) -> str:
            if confidence >= high_threshold:
                return "high"
            if confidence >= medium_threshold:
                return "medium"
            return "low"

        def _tier_templates(
            tier: str,
            *,
            confirmed_template: str | None = None,
            downgrade_high: bool = False,
        ) -> list[str] | None:
            if tier == "high" and not downgrade_high:
                if confirmed_template:
                    return confirmed_pattern_priority(confirmed_template)
                return None
            templates = list(_TOP_THREE_TEMPLATES)
            if confirmed_template:
                templates = [
                    confirmed_template,
                    *[t for t in templates if t != confirmed_template],
                ][:3]
            return templates

        def _minimum_templates_for_tier(tier: str) -> int:
            return 11 if tier == "high" else 3

        def _record_skip(
            emp: EmployeeNameResult,
            *,
            tier: str,
            reason: str,
        ) -> None:
            nonlocal names_skipped_low, patterns_skipped
            if tier == "low":
                names_skipped_low += 1
                skipped_low_confidence_names.append(
                    {
                        "name": emp.name,
                        "confidence": float(emp.confidence),
                        "sources": list(emp.sources or []),
                        "title_or_role": emp.title_or_role,
                        "reason": reason,
                    }
                )
            patterns_skipped += _minimum_templates_for_tier(tier)
            pattern_generation_by_name.append(
                {
                    "name": emp.name,
                    "confidence": float(emp.confidence),
                    "tier": tier,
                    "templates_generated": 0,
                    "patterns_generated": 0,
                    "skipped": True,
                    "skip_reason": reason,
                }
            )

        def _append_generated(
            emp: EmployeeNameResult,
            patterns: list[GeneratedEmail],
            *,
            tier: str,
            generation_tier: str,
            downgraded: bool = False,
        ) -> None:
            nonlocal names_processed_high, names_processed_medium
            nonlocal patterns_generated_high, patterns_generated_medium
            if tier == "high":
                names_processed_high += 1
                patterns_generated_high += len(patterns)
            else:
                names_processed_medium += 1
                patterns_generated_medium += len(patterns)
            for pattern in patterns:
                candidates.append(_to_result(pattern, _SOURCE_TYPE_UNVERIFIED))
            pattern_generation_by_name.append(
                {
                    "name": emp.name,
                    "confidence": float(emp.confidence),
                    "tier": tier,
                    "generation_tier": generation_tier,
                    "templates_generated": len(patterns),
                    "patterns_generated": len(patterns),
                    "skipped": False,
                    "downgraded_for_budget": downgraded,
                }
            )

        def _generate_for_employee(
            emp: EmployeeNameResult,
            *,
            confirmed_template: str | None = None,
            remaining_probe_budget: int | None = None,
        ) -> list[GeneratedEmail]:
            tier = _base_tier(float(emp.confidence))
            if tier == "low":
                _record_skip(emp, tier=tier, reason="low_confidence")
                return []
            downgraded = False
            generation_tier = tier
            if remaining_probe_budget is not None:
                if remaining_probe_budget < 3:
                    _record_skip(emp, tier=tier, reason="smtp_probe_budget_exhausted")
                    return []
                if tier == "high" and remaining_probe_budget < 11:
                    downgraded = True
                    generation_tier = "medium"
            try:
                patterns = generate_patterns(
                    emp.name,
                    cleaned_domain,
                    patterns=_tier_templates(
                        tier,
                        confirmed_template=confirmed_template,
                        downgrade_high=downgraded,
                    ),
                )
            except Exception as exc:  # noqa: BLE001 - defensive
                _LOG.warning(
                    "pattern_and_verify: pattern generation failed for %r: %s",
                    emp.name,
                    exc,
                )
                return []
            _append_generated(
                emp,
                patterns,
                tier=tier,
                generation_tier=generation_tier,
                downgraded=downgraded,
            )
            return patterns

        def _generate_without_probing() -> None:
            for emp in employee_names:
                _generate_for_employee(emp)

        if not smtp_enabled:
            _generate_without_probing()

        if smtp_enabled:
            # MUST-FIX M2: open ONE SMTPVerifier for the whole batch.
            # The per-name loop previously constructed N verifiers,
            # triggering N TCP connects + N MAIL FROM handshakes against
            # the same MX — a textbook anti-abuse trigger pattern.
            mx_records: list[MXRecord] = []
            try:
                mx_records = await resolve_mx(cleaned_domain)
            except Exception as exc:  # noqa: BLE001
                _LOG.warning(
                    "pattern_and_verify: MX resolution failed: %s", exc
                )

            if not mx_records:
                batch_meta["stop_reason"] = "no_mx_records"
                _generate_without_probing()
            else:
                async with SMTPVerifier(
                    mx_records=mx_records,
                    sender_address=(
                        settings.smtp_sender_address or DEFAULT_SENDER
                    ),
                    probe_delay_seconds=float(
                        settings.smtp_probe_delay_seconds
                    )
                    or DEFAULT_PROBE_DELAY,
                ) as verifier:
                    # MUST-FIX M1: catch-all detection runs FIRST and
                    # ALWAYS. The previous implementation skipped this
                    # entirely and called ``verify_single`` in a loop,
                    # which on every catch-all domain (most large corps,
                    # all cloud-mail providers) returned ``exists=True``
                    # for every probe — flooding the user with
                    # confidently-wrong verified emails.
                    is_catchall = await verifier.check_catchall(cleaned_domain)
                    batch_meta["is_catchall"] = is_catchall

                    if is_catchall is True:
                        # Catch-all detected — we KNOW every pattern
                        # would verify, so SMTP probing is meaningless
                        # and would only add noise. Mark all candidates
                        # not_attempted (the retag below turns them
                        # into ``permutation_catchall``).
                        _generate_without_probing()
                    elif is_catchall is None:
                        # Catch-all check itself failed (timeout, block
                        # signal, ambiguous response). Per the design
                        # notes in smtp_verifier.py we MUST NOT probe
                        # individuals in this case — refuse to proceed.
                        batch_meta["stop_reason"] = "catchall_check_failed"
                        _generate_without_probing()
                    else:
                        # Not catch-all — run the batched probe loop.
                        # We probe per-name to preserve the propagation
                        # optimization (once a template confirms,
                        # subsequent names' same-template candidate is
                        # skipped instead of re-probed). Each name's
                        # first hit still consumes one SMTP probe.
                        cap = min(
                            int(settings.smtp_max_probes_per_domain),
                            MAX_PROBES_HARD_CAP,
                        )
                        # MUST-FIX S3: track the candidate index with
                        # an integer counter instead of calling
                        # ``patterns.index(pattern)`` on every iteration
                        # (O(n) lookup → O(n²) overall). The previous
                        # implementation used ``.index(pattern)`` to find
                        # the corresponding candidate, which on a typical
                        # 11-pattern × 50-name batch cost 275 index()
                        # calls. The counter makes every lookup O(1).
                        cand_index = 0
                        stop_for_block = False
                        for emp_index, emp in enumerate(employee_names):
                            remaining_budget = cap - probes_used_total
                            if remaining_budget < 3:
                                remaining_names = employee_names[emp_index:]
                                for skipped_emp in remaining_names:
                                    _record_skip(
                                        skipped_emp,
                                        tier=_base_tier(float(skipped_emp.confidence)),
                                        reason="smtp_probe_budget_exhausted",
                                    )
                                batch_meta["stop_reason"] = (
                                    batch_meta.get("stop_reason")
                                    or "budget_exhausted"
                                )
                                _LOG.warning(
                                    "SMTP probe budget exhausted - %s names skipped",
                                    len(remaining_names),
                                )
                                break
                            pats = _generate_for_employee(
                                emp,
                                confirmed_template=confirmed_pattern,
                                remaining_probe_budget=remaining_budget,
                            )
                            if not pats:
                                continue
                            for pattern_offset, pattern in enumerate(pats):
                                if probes_used_total >= cap:
                                    batch_meta["stop_reason"] = (
                                        batch_meta.get("stop_reason")
                                        or "budget_exhausted"
                                    )
                                    # remaining candidates already
                                    # marked unverified by initial
                                    # generation
                                    cand_index += 1
                                    continue
                                try:
                                    res = await verifier.verify_single(
                                        pattern.email
                                    )
                                except Exception as exc:  # noqa: BLE001
                                    _LOG.warning(
                                        "pattern_and_verify: SMTP probe "
                                        "error for %s: %s",
                                        pattern.email,
                                        exc,
                                    )
                                    res = type(
                                        "R",
                                        (),
                                        {
                                            "exists": None,
                                            "blocked_signal": False,
                                            "verification_status": "inconclusive",
                                        },
                                    )()
                                probes_used_total += 1

                                if getattr(res, "blocked_signal", False):
                                    # Mid-batch block — STOP, mark
                                    # remaining not_attempted.
                                    batch_meta["stop_reason"] = (
                                        "blocked_mid_batch"
                                    )
                                    stop_for_block = True
                                    break
                                if getattr(res, "exists", None) is True:
                                    # MUST-FIX S3: ``cand_index`` is an
                                    # integer counter (O(1) per iter).
                                    # The pre-fix code used
                                    # ``candidates.index(pattern)`` which
                                    # is O(n) per iter → O(n²) overall.
                                    if cand_index < len(candidates):
                                        cand = candidates[cand_index]
                                        cand.source_type = (
                                            _SOURCE_TYPE_VERIFIED
                                        )
                                        cand.verification_status = (
                                            "verified"
                                        )
                                        cand.confidence_score = (
                                            0.5 * 1.4
                                        )
                                    if confirmed_pattern is None:
                                        confirmed_pattern = (
                                            pattern.pattern_template
                                        )
                                    # Stop probing patterns for this
                                    # name — we found a working one.
                                    cand_index += len(pats) - pattern_offset
                                    break
                                cand_index += 1
                            if stop_for_block:
                                break

        # ------------------------------------------------------------------
        # 3. If catch-all was detected and we never probed individuals,
        #    retag the bulk candidates as permutation_catchall.
        # ------------------------------------------------------------------
        if batch_meta.get("is_catchall") is True:
            for cand in candidates:
                if cand.verification_status == "unverified":
                    cand.source_type = _SOURCE_TYPE_CATCHALL
                    cand.confidence_score = 0.2 * 0.7  # conservative

        # ------------------------------------------------------------------
        # 4. Filter role-account matches (we don't want to surface
        #    "info.smith@…" as a person hit).
        # ------------------------------------------------------------------
        findings: list[dict[str, Any]] = []
        verified_count = 0
        for cand in candidates:
            classification = classify_email(cand.email)
            if classification.is_role:
                # Skip — these are noise matches, not a person.
                continue

            breakdown = compute_confidence_breakdown(
                source_types=[cand.source_type],
                is_smtp_verified=(cand.source_type == _SOURCE_TYPE_VERIFIED),
                is_ca_attested=False,
                oldest_timestamp=None,
            )
            final_score = max(
                cand.confidence_score, float(breakdown.score)
            )
            label = label_for_score(final_score)
            findings.append(
                {
                    "platform": "pattern_and_verify",
                    "profile_url": cand.email,
                    "confidence": label,
                    "metadata": {
                        "email": cand.email,
                        "source_name": cand.source_name,
                        "pattern_template": cand.pattern_template,
                        "verification_status": cand.verification_status,
                        "confidence_score": round(final_score, 4),
                        "confidence_breakdown": breakdown.breakdown,
                        "is_role": classification.is_role,
                        "role_match_type": classification.match_type,
                        "source_type": cand.source_type,
                    },
                }
            )
            if cand.source_type == _SOURCE_TYPE_VERIFIED:
                verified_count += 1

        # ------------------------------------------------------------------
        # 5. Module status — should almost always be SUCCESS; pure-logic
        #    generation cannot fail, and SMTP verification is optional.
        # ------------------------------------------------------------------
        status = ModuleStatus.SUCCESS

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "domain": cleaned_domain,
                "employee_names_processed": len(employee_names),
                "total_patterns_generated": len(candidates),
                "smtp_verification_enabled": smtp_enabled,
                "smtp_probes_used": probes_used_total,
                "is_catchall": batch_meta.get("is_catchall"),
                "confirmed_pattern": confirmed_pattern,
                "verified_count": verified_count,
                "stopped_early": batch_meta.get("stop_reason") is not None,
                "stop_reason": batch_meta.get("stop_reason"),
                "names_processed_high": names_processed_high,
                "names_processed_medium": names_processed_medium,
                "names_skipped_low": names_skipped_low,
                "patterns_generated_high": patterns_generated_high,
                "patterns_generated_medium": patterns_generated_medium,
                "patterns_skipped": patterns_skipped,
                "skipped_low_confidence_names": skipped_low_confidence_names,
                "pattern_generation_by_name": pattern_generation_by_name,
                "pattern_high_confidence_threshold": high_threshold,
                "pattern_medium_confidence_threshold": medium_threshold,
            },
        )


def _to_result(
    pattern: GeneratedEmail,
    source_type: str,
    confidence: float | None = None,
    verification_status: str | None = None,
) -> GeneratedPatternResult:
    cls = classify_email(pattern.email)
    if cls.is_role:
        # Mark role; we don't short-circuit here — the orchestrator
        # filters these out at Finding time.  Keeping them in the
        # full list preserves auditable provenance.
        pass

    return GeneratedPatternResult(
        email=pattern.email,
        pattern_template=pattern.pattern_template,
        source_name=pattern.source_name,
        verification_status=(
            verification_status
            if verification_status is not None
            else ("verified" if source_type == _SOURCE_TYPE_VERIFIED else "unverified")
        ),
        confidence_score=confidence if confidence is not None else 0.05,
        confidence_label="low",
        is_role=cls.is_role,
        role_match_type=cls.match_type,
        source_type=source_type,
    )


def employee_name_result_from_dict(payload: dict[str, Any]) -> EmployeeNameResult:
    """Adapter for callers that load Phase C1's findings from JSON."""
    return EmployeeNameResult(
        name=str(payload.get("name") or ""),
        sources=list(payload.get("sources") or []),
        source_count=int(payload.get("source_count") or 0),
        title_or_role=payload.get("title_or_role"),
        confidence=float(payload.get("confidence") or 0.5),
        source_urls=list(payload.get("source_urls") or []),
    )


def employee_name_results_to_dicts(
    results: Iterable[EmployeeNameResult],
) -> list[dict[str, Any]]:
    return [asdict(r) for r in results]
