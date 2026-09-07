"""Phase 6C — corpus-derived Bayesian email-pattern priors.

The corpus is the one place that owns *verification outcomes*: which email
template actually worked for a given domain, tagged with that domain's mail
provider and (when known) industry. Aggregated, that yields a calibrated prior
no vendor publishes (Doc-2 A5): "verified Google-Workspace companies use
``{first}.{last}`` 63% of the time, ``{first}`` 24% …". This module computes
those per-provider / per-industry pattern *distributions* from the corpus and
feeds them as explainable priors into pattern inference.

Privacy. A prior is an **aggregate distribution over templates plus a support
count** — never a raw contact. It is exactly a 6B ``*_PATTERN_PRIOR`` artifact:
shareable. :meth:`PatternPriors.to_safe_artifacts` emits one artifact per
provider/industry so the distribution machinery (6D) can classify it.

Model. Each observed (provider, template) pair is a count. Per group we fit a
Dirichlet-smoothed categorical (add-``alpha``) so an unseen template keeps a
small non-zero mass and a thinly-observed group is not over-confident. Groups
are combined **hierarchically**: a provider/industry distribution is shrunk
toward the global distribution with strength ``shrinkage`` and observation
weight ``support``, so a well-observed provider dominates while a sparse one
backs off to the population base rate. The combination is a weighted average of
the component posteriors — fully explainable via :meth:`PatternPriors.explain`.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Canonical template vocabulary — mirrors
# ``email_pattern_generator._PATTERN_TEMPLATES`` (a sync test asserts they stay
# in step, the same discipline calibration.FEATURE_NAMES uses for the scorer).
PATTERN_TEMPLATES: tuple[str, ...] = (
    "{first}.{last}@{domain}",
    "{first}@{domain}",
    "{f}{last}@{domain}",
    "{first}{last}@{domain}",
    "{first}{l}@{domain}",
    "{last}.{first}@{domain}",
    "{last}@{domain}",
    "{first}_{last}@{domain}",
    "{first}-{last}@{domain}",
    "{f}.{last}@{domain}",
    "{last}{f}@{domain}",
)
# Catch-all for a confirmed pattern outside the known vocabulary.
OTHER_TEMPLATE = "{other}@{domain}"

_VOCAB: tuple[str, ...] = (*PATTERN_TEMPLATES, OTHER_TEMPLATE)

DEFAULT_ALPHA = 0.5
DEFAULT_SHRINKAGE = 8.0


def normalize_template(raw: str | None) -> str:
    """Map a stored/confirmed pattern onto the canonical vocabulary.

    Confirmed patterns are stored local-part-only (e.g. ``{first}`` or
    ``{first}.{last}``); the generator vocabulary carries the ``@{domain}``
    suffix. This appends the suffix and matches; anything unrecognised maps to
    :data:`OTHER_TEMPLATE` (kept, never dropped — an unknown pattern is signal).
    """
    if not raw or not str(raw).strip():
        return OTHER_TEMPLATE
    text = str(raw).strip()
    if text in _VOCAB:
        return text
    candidate = text if "@" in text else f"{text}@{{domain}}"
    if candidate in _VOCAB:
        return candidate
    # Tolerate a bare "{domain}"-less form typed differently.
    local = candidate.split("@", 1)[0]
    for template in PATTERN_TEMPLATES:
        if template.split("@", 1)[0] == local:
            return template
    return OTHER_TEMPLATE


@dataclass(frozen=True)
class PatternObservation:
    """One corpus datum: a domain's confirmed template, its provider/industry."""

    template: str  # raw or canonical; normalized on ingest
    provider: str | None = None
    industry: str | None = None
    weight: float = 1.0


@dataclass(frozen=True)
class PatternDistribution:
    """A Dirichlet-smoothed categorical over the template vocabulary."""

    probs: dict[str, float]
    support: float  # total observation weight (pre-smoothing)
    alpha: float

    def prob(self, template: str) -> float:
        return self.probs.get(normalize_template(template), 0.0)

    def top(self, n: int = 3) -> list[tuple[str, float]]:
        return sorted(self.probs.items(), key=lambda kv: (-kv[1], kv[0]))[: max(1, n)]

    @classmethod
    def from_counts(
        cls, counts: dict[str, float], *, alpha: float = DEFAULT_ALPHA
    ) -> PatternDistribution:
        support = float(sum(max(0.0, v) for v in counts.values()))
        denom = support + alpha * len(_VOCAB)
        probs = {
            t: (float(counts.get(t, 0.0)) + alpha) / denom if denom > 0 else 1.0 / len(_VOCAB)
            for t in _VOCAB
        }
        return cls(probs=probs, support=support, alpha=alpha)


def _uniform_probs() -> dict[str, float]:
    return {t: 1.0 / len(_VOCAB) for t in _VOCAB}


@dataclass
class PatternPriors:
    """Hierarchical per-provider / per-industry pattern priors over the corpus."""

    global_dist: PatternDistribution
    by_provider: dict[str, PatternDistribution] = field(default_factory=dict)
    by_industry: dict[str, PatternDistribution] = field(default_factory=dict)
    shrinkage: float = DEFAULT_SHRINKAGE
    alpha: float = DEFAULT_ALPHA

    # -- combination -------------------------------------------------------
    def _components(
        self, provider: str | None, industry: str | None
    ) -> list[tuple[str, PatternDistribution, float]]:
        """(name, distribution, weight) triples that back a conditional prior.

        The global distribution always contributes at weight ``shrinkage`` (the
        prior strength); a provider/industry contributes at its own support, so
        a well-observed group dominates and a sparse one backs off to global.
        """
        parts: list[tuple[str, PatternDistribution, float]] = [
            ("global", self.global_dist, self.shrinkage)
        ]
        if provider:
            dist = self.by_provider.get(_norm_key(provider))
            if dist is not None:
                parts.append((f"provider:{_norm_key(provider)}", dist, dist.support))
        if industry:
            dist = self.by_industry.get(_norm_key(industry))
            if dist is not None:
                parts.append((f"industry:{_norm_key(industry)}", dist, dist.support))
        return parts

    def distribution(
        self, *, provider: str | None = None, industry: str | None = None
    ) -> dict[str, float]:
        """The blended posterior distribution for a (provider, industry) context."""
        parts = self._components(provider, industry)
        total_w = sum(w for _n, _d, w in parts)
        if total_w <= 0:
            return _uniform_probs()
        blended = {
            t: sum(dist.probs[t] * w for _n, dist, w in parts) / total_w for t in _VOCAB
        }
        return blended

    def prior(
        self, template: str, *, provider: str | None = None, industry: str | None = None
    ) -> float:
        """Prior probability of ``template`` in a (provider, industry) context."""
        return self.distribution(provider=provider, industry=industry).get(
            normalize_template(template), 0.0
        )

    def top_template(
        self, *, provider: str | None = None, industry: str | None = None
    ) -> str | None:
        """The single most-likely template for a context (excluding the catch-all)."""
        dist = self.distribution(provider=provider, industry=industry)
        ranked = sorted(
            ((t, p) for t, p in dist.items() if t != OTHER_TEMPLATE),
            key=lambda kv: (-kv[1], kv[0]),
        )
        return ranked[0][0] if ranked else None

    def explain(
        self, template: str, *, provider: str | None = None, industry: str | None = None
    ) -> dict[str, Any]:
        """Per-component breakdown of a template's prior — why it is what it is."""
        norm = normalize_template(template)
        parts = self._components(provider, industry)
        total_w = sum(w for _n, _d, w in parts) or 1.0
        components = [
            {
                "source": name,
                "prob": round(dist.probs[norm], 6),
                "weight": round(w, 4),
                "support": round(dist.support, 4),
                "contribution": round(dist.probs[norm] * w / total_w, 6),
            }
            for name, dist, w in parts
        ]
        return {
            "template": norm,
            "provider": _norm_key(provider) if provider else None,
            "industry": _norm_key(industry) if industry else None,
            "prior": round(self.prior(norm, provider=provider, industry=industry), 6),
            "components": components,
        }

    # -- seeding / distribution export ------------------------------------
    def provider_prior_map(self) -> dict[str, dict[str, float]]:
        """{provider: {template: prob}} plus a "" global entry, for pool seeding."""
        out: dict[str, dict[str, float]] = {"": self.distribution()}
        for provider in self.by_provider:
            out[provider] = self.distribution(provider=provider)
        return out

    def to_safe_artifacts(self) -> list[Any]:
        """Emit 6B-safe ``*_PATTERN_PRIOR`` artifacts (aggregate, non-contact)."""
        from .safe_artifact import Artifact, ArtifactKind

        artifacts: list[Any] = []
        for provider, dist in self.by_provider.items():
            artifacts.append(
                Artifact(
                    kind=ArtifactKind.PROVIDER_PATTERN_PRIOR,
                    key=provider,
                    payload={
                        "provider": provider,
                        "distribution": dist.probs,
                        "support": dist.support,
                        "top": dist.top(3),
                    },
                )
            )
        for industry, dist in self.by_industry.items():
            artifacts.append(
                Artifact(
                    kind=ArtifactKind.INDUSTRY_PATTERN_PRIOR,
                    key=industry,
                    payload={
                        "industry": industry,
                        "distribution": dist.probs,
                        "support": dist.support,
                        "top": dist.top(3),
                    },
                )
            )
        return artifacts

    @property
    def is_empty(self) -> bool:
        return self.global_dist.support <= 0


def _norm_key(value: str | None) -> str:
    return str(value or "").strip().lower()


def build_priors(
    observations: Iterable[PatternObservation],
    *,
    alpha: float = DEFAULT_ALPHA,
    shrinkage: float = DEFAULT_SHRINKAGE,
) -> PatternPriors:
    """Aggregate observations into hierarchical pattern priors."""
    global_counts: dict[str, float] = defaultdict(float)
    provider_counts: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    industry_counts: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))

    for obs in observations:
        template = normalize_template(obs.template)
        weight = float(obs.weight) if obs.weight and obs.weight > 0 else 1.0
        global_counts[template] += weight
        if obs.provider:
            provider_counts[_norm_key(obs.provider)][template] += weight
        if obs.industry:
            industry_counts[_norm_key(obs.industry)][template] += weight

    return PatternPriors(
        global_dist=PatternDistribution.from_counts(dict(global_counts), alpha=alpha),
        by_provider={
            p: PatternDistribution.from_counts(dict(c), alpha=alpha)
            for p, c in provider_counts.items()
        },
        by_industry={
            i: PatternDistribution.from_counts(dict(c), alpha=alpha)
            for i, c in industry_counts.items()
        },
        shrinkage=shrinkage,
        alpha=alpha,
    )


def _provider_of(result_json: dict[str, Any]) -> str | None:
    """Best-effort mail provider from a serialized harvest result (5D/verify)."""
    for key in ("mail_provider", "provider", "mail_provider_detected"):
        val = result_json.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip().lower()
    meta = result_json.get("metadata")
    if isinstance(meta, dict):
        for key in ("mail_provider", "provider", "technographics"):
            val = meta.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip().lower()
            if isinstance(val, dict):
                mail = val.get("mail") or val.get("mail_provider")
                if isinstance(mail, str) and mail.strip():
                    return mail.strip().lower()
    return None


def _industry_of(result_json: dict[str, Any]) -> str | None:
    meta = result_json.get("metadata")
    if isinstance(meta, dict):
        val = meta.get("industry")
        if isinstance(val, str) and val.strip():
            return val.strip().lower()
    return None


async def build_priors_from_corpus(
    *,
    alpha: float = DEFAULT_ALPHA,
    shrinkage: float = DEFAULT_SHRINKAGE,
    limit: int = 20000,
) -> PatternPriors:
    """Build priors from the corpus crawl snapshots. Guarded → empty priors.

    Reads one snapshot per domain via the ``domains`` projection's
    ``last_crawl_snapshot_id`` (bounded to the number of domains, not all crawl
    history), tags each confirmed pattern with the domain's mail
    provider/industry when the serialized result carries it, and weights by the
    crawl's high-confidence count (a domain we know well counts for more).
    Aggregate-only; no contact ever leaves the DB.
    """
    from .corpus_store import _corpus_enabled

    empty = build_priors([], alpha=alpha, shrinkage=shrinkage)
    if not _corpus_enabled():
        return empty
    try:
        from sqlalchemy import select

        from ..db.database import AsyncSessionLocal
        from ..db.models import CrawlSnapshot, Domain

        observations: list[PatternObservation] = []
        async with AsyncSessionLocal() as session:
            rows = (
                await session.execute(
                    select(CrawlSnapshot)
                    .join(Domain, Domain.last_crawl_snapshot_id == CrawlSnapshot.id)
                    .where(CrawlSnapshot.confirmed_pattern.isnot(None))
                    .limit(max(1, min(int(limit), 100000)))
                )
            ).scalars().all()
        for row in rows:
            result_json = dict(row.result_json or {})
            observations.append(
                PatternObservation(
                    template=str(row.confirmed_pattern),
                    provider=_provider_of(result_json),
                    industry=_industry_of(result_json),
                    weight=float(max(1, int(row.high_confidence_count or 0)) or 1),
                )
            )
        return build_priors(observations, alpha=alpha, shrinkage=shrinkage)
    except Exception:
        logger.exception("build_priors_from_corpus failed; returning empty priors")
        return empty
