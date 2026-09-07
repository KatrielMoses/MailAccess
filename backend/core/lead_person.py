"""Phase 3A — promote a ``HarvestedEmail`` into a person-centric Lead.

Paid lead-gen tools sell *a person*, not a string: ``name + title + seniority +
company + verified email (+ linkedin/phone)``. The harvest already *collects* the
person signals — Hunter (`first_name`/`last_name`/`position`/`department`/
`linkedin`), company-page structured data (`name`/`title`), LinkedIn SERP
(`title_or_role` + profile URL), and the name a verified pattern was built from
(`source_name`) — but they sit untyped inside ``HarvestedEmail.evidence`` and
never reach a first-class field. This module promotes them.

Two hard contracts from the brief:

* **Evidence-or-null, resolved through 1E.** Every person field is resolved by
  feeding *this email's own evidence entries* through the Phase-1E claim resolver
  (:func:`claim_resolver.resolve_field`) — so competing claims (VP vs Engineer)
  don't clobber, the winner is explainable, and losers are retained. A field is
  populated **only** when an evidenced claim resolves for it; otherwise it stays
  ``None``. No inference-to-fill, no guessing.
* **Mode-aware.** In ``public-business-contact`` mode, personal-leaning fields
  (phone, location) survive only when they trace to a *published business*
  source; anything else is dropped. (Profile-inference / personal-pivot modules
  don't even run in public mode — 2C — so this is defense-in-depth.)

No new collection happens here: the input is the evidence the aggregator already
assembled. Seniority is derived from the resolved title via
:mod:`seniority_classifier` (Phase 3B).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .claim_resolver import resolve_field
from .product_mode import ProductMode, normalize_mode
from .seniority_classifier import BAND_UNKNOWN, classify_title

logger = logging.getLogger(__name__)

# Person fields resolved directly off evidence, mapped to the 1E resolver field
# name that gathers them. ``full_name``/``first``/``last`` compose specially.
_DIRECT_FIELDS: dict[str, str] = {
    "full_name": "name",
    "first": "first",
    "last": "last",
    "job_title": "title",
    "department": "department",
    "linkedin_url": "linkedin_url",
    "phone": "phone",
    "location": "location",
}

# Fields whose value is personal-leaning: in public-business-contact mode they
# survive only when the winning observation traces to a published-business source.
_MODE_GATED_FIELDS = frozenset({"phone", "location"})

# Source types that count as *published business contact* provenance — the lawful
# basis for a person attribute in public-business-contact mode. Anything outside
# this set (a personal profile, a breach, an inferred pivot) is dropped for the
# gated fields in that mode.
_BUSINESS_CONTACT_SOURCES = frozenset(
    {
        "hunter", "company_page", "company_page_names", "structured_email",
        "structured_data", "json_ld", "microdata", "hcard", "dom_team_card",
        "mailto", "sec_edgar", "opencorporates", "companies_house",
        "security_txt", "whois", "whois_lookup", "press_intel",
        "pgp_uid", "ca_attested", "pattern_and_verify", "employee_name_discovery",
        "linkedin_search",
        # Phase 7B — Apollo returns published business contact data, so its
        # phone/location are a lawful basis in public-business-contact mode. PDL
        # (data-broker) is deliberately NOT here and is security-only anyway.
        "apollo",
    }
)


@dataclass
class PersonFields:
    """Resolved, evidence-backed person attribution for one contact."""

    full_name: str | None = None
    first: str | None = None
    last: str | None = None
    job_title: str | None = None
    seniority: str | None = None
    department: str | None = None
    linkedin_url: str | None = None
    phone: str | None = None
    location: str | None = None
    # field -> provenance ({value, source_type, source_url, evidence_modules,
    # reasoning, candidates}). The invariant: a populated field ALWAYS has an
    # entry here pointing to >=1 backing evidence observation.
    field_provenance: dict[str, dict[str, Any]] = field(default_factory=dict)

    def as_export_dict(self) -> dict[str, Any]:
        return {
            "full_name": self.full_name,
            "first": self.first,
            "last": self.last,
            "job_title": self.job_title,
            "seniority": self.seniority,
            "department": self.department,
            "linkedin_url": self.linkedin_url,
            "phone": self.phone,
            "location": self.location,
            "field_provenance": self.field_provenance,
        }

    def is_empty(self) -> bool:
        return not any(
            (
                self.full_name, self.first, self.last, self.job_title,
                self.seniority, self.department, self.linkedin_url,
                self.phone, self.location,
            )
        )


def _evidence_observations(entry: Any) -> list[dict[str, Any]]:
    """Turn a HarvestedEmail's evidence list into 1E resolution-ready dicts.

    Each evidence entry (``{"module", "metadata"}``) becomes one observation
    whose ``claim`` is the metadata dict, so :func:`resolve_field` can read the
    scattered person keys out of it. The synthetic ``id`` (``ev:<i>``) points
    back at the exact evidence entry — this is the provenance link the
    evidence-or-null contract asserts.
    """
    obs: list[dict[str, Any]] = []
    default_ts = getattr(entry, "last_seen_timestamp", None) or getattr(
        entry, "first_seen_timestamp", None
    )
    for i, ev in enumerate(getattr(entry, "evidence", None) or []):
        if not isinstance(ev, dict):
            continue
        meta = ev.get("metadata")
        if not isinstance(meta, dict):
            meta = {}
        module = str(ev.get("module") or "evidence")
        source_type = str(meta.get("source_type") or module)
        source_url = (
            meta.get("source_url")
            or meta.get("html_url")
            or meta.get("url")
            or _first_url(meta.get("source_urls"))
        )
        obs.append(
            {
                "id": f"ev:{i}",
                "claim": meta,
                "source_type": source_type,
                "source_url": source_url,
                "capture_time": meta.get("last_seen") or meta.get("timestamp") or default_ts,
                "extraction_method": module,
                "_module": module,
            }
        )
    return obs


def _first_url(value: Any) -> str | None:
    if isinstance(value, list):
        for u in value:
            if isinstance(u, str) and u:
                return u
    return None


def _provenance(resolution: Any, observations: list[dict[str, Any]]) -> dict[str, Any]:
    winner = resolution.winner
    obs_by_id = {o["id"]: o for o in observations}
    modules = sorted(
        {
            str(obs_by_id[oid].get("_module"))
            for oid in winner.observation_ids
            if oid in obs_by_id
        }
    )
    return {
        "value": resolution.resolved_value,
        "source_type": winner.best_source_type,
        "source_url": next(
            (
                obs_by_id[oid].get("source_url")
                for oid in winner.observation_ids
                if obs_by_id.get(oid, {}).get("source_url")
            ),
            None,
        ),
        "evidence_modules": modules,
        "evidence_ids": list(winner.observation_ids),
        "support_count": winner.support_count,
        "reasoning": resolution.reasoning,
        "candidates": [
            {"value": c.value, "score": c.score, "source_type": c.best_source_type}
            for c in resolution.candidates
        ],
    }


def resolve_person_fields(entry: Any, *, mode: str | ProductMode) -> PersonFields:
    """Resolve every person field for one contact from its own evidence.

    Fully guarded: any failure yields an empty :class:`PersonFields` (the lead
    degrades to email-only, never crashes the harvest). Populated fields always
    carry a provenance entry pointing at the backing evidence.
    """
    person = PersonFields()
    try:
        observations = _evidence_observations(entry)
        if not observations:
            return person
        m = normalize_mode(mode)

        resolved: dict[str, Any] = {}
        for target, resolver_field in _DIRECT_FIELDS.items():
            resolution = resolve_field(
                observations, resolver_field, subject=getattr(entry, "email", "")
            )
            if resolution is None or resolution.resolved_value is None:
                continue
            value = str(resolution.resolved_value).strip()
            if not value:
                continue
            prov = _provenance(resolution, observations)

            # Mode gate: personal-leaning fields need a published-business source.
            if (
                m is ProductMode.PUBLIC_BUSINESS_CONTACT
                and target in _MODE_GATED_FIELDS
                and (prov.get("source_type") or "") not in _BUSINESS_CONTACT_SOURCES
            ):
                person.field_provenance[target] = {
                    **prov,
                    "value": None,
                    "suppressed_by_mode": "public-business-contact",
                }
                continue

            resolved[target] = value
            person.field_provenance[target] = prov

        person.full_name = resolved.get("full_name")
        person.first = resolved.get("first")
        person.last = resolved.get("last")
        person.job_title = resolved.get("job_title")
        person.department = resolved.get("department")
        person.linkedin_url = resolved.get("linkedin_url")
        person.phone = resolved.get("phone")
        person.location = resolved.get("location")

        # Compose the missing halves of the name from what we have, keeping the
        # composition explainable (it inherits the source field's provenance).
        _compose_name(person)

        # Phase 3B — derive seniority + department from the resolved title. This
        # is classification of an *already-evidenced* title, not new attribution:
        # if there's no title there's no seniority.
        if person.job_title:
            cls = classify_title(person.job_title)
            if cls.band != BAND_UNKNOWN:
                person.seniority = cls.band
            if cls.department and not person.department:
                person.department = cls.department
            person.field_provenance["seniority"] = {
                "value": person.seniority,
                "band": cls.band,
                "derived_from": "job_title",
                "matched_term": cls.matched_term,
                "is_ambiguous": cls.is_ambiguous,
                "reasoning": cls.reason,
                "source_field_provenance": person.field_provenance.get("job_title"),
            }

        _assert_provenance_invariant(person)
        return person
    except Exception:
        logger.exception("person-field resolution failed for %s", getattr(entry, "email", "?"))
        return PersonFields()


def _compose_name(person: PersonFields) -> None:
    if person.full_name and (not person.first or not person.last):
        tokens = person.full_name.split()
        if len(tokens) >= 2:
            person.first = person.first or tokens[0]
            person.last = person.last or tokens[-1]
            for part in ("first", "last"):
                person.field_provenance.setdefault(
                    part,
                    {
                        **(person.field_provenance.get("full_name") or {}),
                        "derived_from": "full_name",
                    },
                )
    elif not person.full_name and person.first and person.last:
        person.full_name = f"{person.first} {person.last}"
        person.field_provenance.setdefault(
            "full_name",
            {
                **(person.field_provenance.get("first") or {}),
                "derived_from": "first+last",
            },
        )


def _assert_provenance_invariant(person: PersonFields) -> None:
    """Enforce the brief's contract: no populated field without an evidence link.

    A populated field must have a provenance entry that names >=1 backing
    evidence observation (or a documented derivation). Seniority is derived, so
    it links via ``source_field_provenance``. A violation is a bug — we log and
    scrub the offending field rather than emit an unbacked person attribute.
    """
    for fname in (
        "full_name", "first", "last", "job_title", "department",
        "linkedin_url", "phone", "location",
    ):
        value = getattr(person, fname)
        if value is None:
            continue
        prov = person.field_provenance.get(fname) or {}
        has_link = bool(prov.get("evidence_ids")) or bool(prov.get("derived_from"))
        if not has_link:
            logger.error(
                "person field %s=%r has no evidence link; scrubbing", fname, value
            )
            setattr(person, fname, None)
            person.field_provenance.pop(fname, None)
