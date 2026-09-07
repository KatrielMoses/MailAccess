"""Phase 3C — non-SMTP probabilistic deliverability score.

Phase 0 established that SMTP is unmeasurable on the eval host (port 25 blocked),
yet a lead is worthless without a deliverability signal. This module grades every
email **without touching port 25**, from signals the tool already resolves:

* MX presence (``mx_resolver``) — no MX ⇒ no mail infrastructure;
* SPF / DMARC posture (the harvest DNS pass) — a configured, strict domain is a
  maintained one;
* mail provider (``mail_provider``) — a reputable managed provider vs unknown;
* disposable (``disposable_domains``) and role (``role_classifier``) flags;
* corpus verification history (``corpus_store.read_verification_history``) — has
  this address/domain verified (or bounced) before, and how recently.

The model is a small, **interpretable additive log-odds** function squashed
through a logistic — deliberately simple so it is auditable now and so Phase 4
can *replace the weights* with a model trained on real outcomes without changing
the feature interface. Every score carries its per-feature contributions
(reasons) and the raw feature vector (evidence), and each scored email is logged
against any known outcome — the Phase-4 (F1) ground-truth capture, started here.

Never depends on SMTP; works in every product mode.
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Weight schema version — bump when the weights/features change so logged samples
# stay attributable to the model that produced them (Phase 4 reads this).
MODEL_VERSION = "3c-loglinear-v1"

# Log-odds intercept + per-feature weights. Interpretable and hand-set for now;
# Phase 4 replaces these with trained coefficients over the logged outcomes.
_INTERCEPT = 0.4
_W = {
    "mx_present": 1.4,
    "mx_absent": -3.2,
    "spf_present": 0.4,
    "dmarc_strict": 0.3,
    "provider_reputable": 0.6,
    "provider_unknown": -0.6,
    "disposable": -3.5,
    "role": 0.15,  # role mailboxes (info@, sales@) usually deliver — slight +
    "history_verified_recent": 2.0,
    "history_verified_stale": 0.8,
    "history_negative": -2.5,
}

_REPUTABLE_PROVIDERS = frozenset({"google", "m365", "proton", "zoho", "fastmail", "yahoo"})
# Provider values that carry no reputational signal either way.
_NEUTRAL_PROVIDERS = frozenset({"self_hosted", "shared_hosting"})

# A prior verification counts as "recent" within this many days (B2B contact data
# decays ~25-30%/yr — beyond a year a past success is only weak evidence).
_RECENT_DAYS = 365
_NEGATIVE_STATUSES = frozenset({"not_found", "bounced", "invalid", "no_mx"})
_POSITIVE_STATUSES = frozenset({"verified"})


@dataclass
class DeliverabilityScore:
    score: float  # calibrated-ready probability in [0, 1]
    reasons: list[dict[str, Any]] = field(default_factory=list)
    features: dict[str, Any] = field(default_factory=dict)
    model_version: str = MODEL_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "reasons": self.reasons,
            "features": self.features,
            "model_version": self.model_version,
        }


def _sigmoid(x: float) -> float:
    if x < -60:
        return 0.0
    if x > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-x))


def _history_signal(history: list[dict[str, Any]] | None) -> tuple[str | None, dict[str, Any]]:
    """Reduce verification history to a single signal + evidence.

    A recent positive dominates; otherwise a negative; otherwise a stale
    positive; otherwise no signal."""
    if not history:
        return None, {}
    now = datetime.now(timezone.utc)
    recent_positive = stale_positive = negative = None
    for row in history:
        status = str(row.get("status") or "").lower()
        ts = row.get("verified_at")
        parsed: datetime | None = None
        if isinstance(ts, str) and ts.strip():
            try:
                parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                parsed = None
        elif isinstance(ts, datetime):
            parsed = ts
        if parsed is not None and parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        age_days = (now - parsed).days if parsed else None
        evidence = {"status": status, "verified_at": row.get("verified_at"), "age_days": age_days}
        if status in _POSITIVE_STATUSES:
            if age_days is not None and age_days <= _RECENT_DAYS:
                recent_positive = recent_positive or evidence
            else:
                stale_positive = stale_positive or evidence
        elif status in _NEGATIVE_STATUSES:
            negative = negative or evidence
    if recent_positive:
        return "history_verified_recent", recent_positive
    if negative:
        return "history_negative", negative
    if stale_positive:
        return "history_verified_stale", stale_positive
    return None, {}


def compute_deliverability_score(
    *,
    mx_present: bool,
    spf_present: bool = False,
    dmarc_strict: bool = False,
    provider: str | None = None,
    is_role: bool = False,
    is_disposable: bool = False,
    history: list[dict[str, Any]] | None = None,
) -> DeliverabilityScore:
    """Compute a non-SMTP deliverability probability with explainable reasons."""
    logit = _INTERCEPT
    reasons: list[dict[str, Any]] = []
    features: dict[str, Any] = {
        "mx_present": bool(mx_present),
        "spf_present": bool(spf_present),
        "dmarc_strict": bool(dmarc_strict),
        "provider": provider,
        "is_role": bool(is_role),
        "is_disposable": bool(is_disposable),
    }

    def add(feature: str, detail: str) -> None:
        nonlocal logit
        w = _W[feature]
        logit += w
        reasons.append({"feature": feature, "contribution": round(w, 3), "detail": detail})

    if is_disposable:
        add("disposable", "disposable/throwaway domain — not deliverable for outreach")
    if mx_present:
        add("mx_present", "domain publishes MX records")
    else:
        add("mx_absent", "no MX (or A fallback) — domain accepts no mail")
    if spf_present:
        add("spf_present", "SPF policy published")
    if dmarc_strict:
        add("dmarc_strict", "DMARC p=reject (maintained mail domain)")

    prov = str(provider or "").lower()
    if prov in _REPUTABLE_PROVIDERS:
        add("provider_reputable", f"managed provider ({prov})")
        features["provider_class"] = "reputable"
    elif prov and prov not in _NEUTRAL_PROVIDERS and prov not in {"unknown", ""}:
        features["provider_class"] = "other"
    elif prov in _NEUTRAL_PROVIDERS:
        features["provider_class"] = "neutral"
    else:
        add("provider_unknown", "no provider identified from MX")
        features["provider_class"] = "unknown"

    if is_role:
        add("role", "role mailbox — typically deliverable")

    hist_feature, hist_evidence = _history_signal(history)
    if hist_feature:
        add(hist_feature, f"corpus verification history: {hist_evidence.get('status')}")
        features["history"] = hist_evidence

    features["logit"] = round(logit, 4)
    return DeliverabilityScore(score=_sigmoid(logit), reasons=reasons, features=features)


def _log_path() -> Path:
    from ..config import settings

    default = Path.home() / ".mailaccess" / "deliverability_outcomes.jsonl"
    return Path(getattr(settings, "deliverability_outcome_log", default))


def log_score_sample(
    email: str,
    domain: str,
    score: DeliverabilityScore,
    *,
    known_outcome: str | None = None,
) -> None:
    """Append a score→outcome sample for Phase-4 (F1) calibration/training.

    One JSONL line per scored email: the feature vector, the score, the model
    version, and any known deliverability outcome (from corpus history or, later,
    an SMTP/provider confirmation). Fully guarded — logging never breaks a
    harvest."""
    try:
        path = _log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "email": email,
            "domain": domain,
            "score": round(score.score, 4),
            "model_version": score.model_version,
            "features": score.features,
            "known_outcome": known_outcome,
        }
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except Exception:
        logger.debug("deliverability sample log skipped", exc_info=True)
