"""Phase 7A/7B — shared types for enrichment connectors.

A connector (Apollo, People Data Labs, ...) normalizes its vendor response into
a single :class:`EnrichmentResult`. The waterfall (:mod:`enrichment_waterfall`)
consumes that uniform shape, converts it into evidence entries, and lets the 1E
claim resolver merge it — so no connector writes person fields directly.

Kept in its own module so connector clients and the waterfall can both import it
without a cycle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# The person-field keys a connector may populate. These names are exactly the
# 1E ``claim_resolver._FIELD_KEYS`` aliases, so an evidence entry built from
# ``fields`` resolves without any extra key registration.
ENRICHMENT_FIELDS: tuple[str, ...] = (
    "full_name",
    "first",
    "last",
    "job_title",
    "department",
    "linkedin_url",
    "phone",
    "location",
    "company",
)


@dataclass
class EnrichmentResult:
    """One connector's normalized answer for a single email.

    ``fields`` holds only the keys the connector actually resolved (empty/None
    values are dropped by the connector). ``confidence`` is the connector's
    0..1 confidence that this record matches the queried email — the waterfall
    treats a result at or above its threshold as a confident hit.
    """

    provider: str
    source_type: str
    fields: dict[str, str] = field(default_factory=dict)
    confidence: float = 0.0
    source_url: str | None = None
    raw: dict[str, Any] | None = None

    def has_fields(self) -> bool:
        return any(v for v in self.fields.values())
