"""JEV-1 — identity resolution tasks (investigate).

Three bounded judgments that sharpen the *inputs* to the identity picture; the
call sites and their deterministic fallbacks live in
:mod:`backend.core.jev_identity`. None of these outputs is a score:

* ``identity.same_person`` — do two public profiles belong to one person?
* ``identity.name_reconcile`` — which name candidates are the same name, which are
  not personal names, and which one is canonical? Answers are INDICES into the
  supplied list, so JEV can only select among observed strings, never author one.
* ``identity.bio_extract`` — employer / role / location / entity type from a bio.
  The call site keeps a string field only if it occurs verbatim in the bio, so the
  stored value is always a span of the source text.
"""

from __future__ import annotations

import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..contract import JevTask, register

SAME_PERSON = "identity.same_person"
NAME_RECONCILE = "identity.name_reconcile"
BIO_EXTRACT = "identity.bio_extract"

MAX_NAME_CANDIDATES = 12


def _dump(payload: BaseModel) -> str:
    return json.dumps(payload.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# identity.same_person
# ---------------------------------------------------------------------------
class Profile(BaseModel):
    platform: str = Field(max_length=80)
    username: str | None = Field(default=None, max_length=120)
    display_name: str | None = Field(default=None, max_length=120)
    bio: str | None = Field(default=None, max_length=600)
    created: str | None = Field(default=None, max_length=40)
    handles: list[str] = Field(default_factory=list, max_length=8)
    employer: str | None = Field(default=None, max_length=120)
    location: str | None = Field(default=None, max_length=120)


class SamePersonInput(BaseModel):
    a: Profile
    b: Profile
    avatar_match: bool
    heuristic_signals: list[str] = Field(default_factory=list, max_length=8)


class SamePersonOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    same_person: Literal["yes", "no", "unclear"]
    # Accepted for the model's benefit; the call site never stores it.
    reason: str = Field(default="", max_length=200)


def _same_person_prompt(inp: SamePersonInput) -> tuple[str, str]:
    system = (
        "You compare two public online profiles and decide whether they belong to the "
        "same real person. Weigh concrete overlap (identical rare usernames, matching "
        "names, the same employer/location, cross-links, matching avatars) against "
        "conflicts (different names, different locations or languages, one is an "
        "organization). A shared common name or a similar signup date alone is NOT "
        "enough. Answer 'unclear' when the evidence does not decide it."
    )
    return system, _dump(inp)


# ---------------------------------------------------------------------------
# identity.name_reconcile
# ---------------------------------------------------------------------------
class NameCandidateIn(BaseModel):
    name: str = Field(max_length=60)
    sources: list[str] = Field(max_length=12)
    weight: float = Field(ge=0.0, le=10.0)


class NameReconcileInput(BaseModel):
    email_localpart: str = Field(max_length=64)
    candidates: list[NameCandidateIn] = Field(min_length=2, max_length=MAX_NAME_CANDIDATES)


class NameReconcileOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    canonical_index: int | None = None
    equivalence_groups: list[Annotated[list[int], Field(max_length=MAX_NAME_CANDIDATES)]] = (
        Field(default_factory=list, max_length=6)
    )
    drop: list[int] = Field(default_factory=list, max_length=MAX_NAME_CANDIDATES)


def _name_prompt(inp: NameReconcileInput) -> tuple[str, str]:
    system = (
        "You reconcile candidate personal names gathered about ONE email address. "
        "Candidates are numbered from 0 in the order given. Return: "
        "`equivalence_groups` — lists of indices that are the same person's name "
        "written differently (nicknames, initials, transliterations, word order); "
        "`drop` — indices that are not a personal name at all (page text, "
        "organization or product names, usernames, job titles, junk); "
        "`canonical_index` — the index of the single best full form of the person's "
        "real name, or null if none is credible. Use only indices; never invent names."
    )
    return system, _dump(inp)


# ---------------------------------------------------------------------------
# identity.bio_extract
# ---------------------------------------------------------------------------
class BioInput(BaseModel):
    bio: str = Field(min_length=1, max_length=1000)
    exclude_domain: str | None = Field(default=None, max_length=253)


class BioOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    employer: str | None = Field(default=None, max_length=120)
    role_title: str | None = Field(default=None, max_length=120)
    location: str | None = Field(default=None, max_length=120)
    entity_type: Literal["person", "organization", "unclear"]


def _bio_prompt(inp: BioInput) -> tuple[str, str]:
    system = (
        "You extract structured facts from a short public profile bio. Copy each value "
        "EXACTLY as it appears in the bio (same words); use null when the bio does not "
        "state it. `employer`: the organization the author works for. `role_title`: "
        "their job title or role. `location`: a place they say they live or work. "
        "`entity_type`: 'person' for an individual's profile, 'organization' for a "
        "company/brand/project account, 'unclear' otherwise. Ignore the domain given "
        "as exclude_domain when it only identifies the subject's own email provider."
    )
    return system, _dump(inp)


register(JevTask(
    name=SAME_PERSON,
    input_model=SamePersonInput,
    output_model=SamePersonOutput,
    prompt_version="same-person-v1",
    build_prompt=_same_person_prompt,
    min_confidence=0.8,
    description="Same-person judgment for an ambiguous identity-graph profile pair.",
))

register(JevTask(
    name=NAME_RECONCILE,
    input_model=NameReconcileInput,
    output_model=NameReconcileOutput,
    prompt_version="name-reconcile-v1",
    build_prompt=_name_prompt,
    min_confidence=0.75,
    description="Group / drop / pick-canonical over conflicting name candidates.",
))

register(JevTask(
    name=BIO_EXTRACT,
    input_model=BioInput,
    output_model=BioOutput,
    prompt_version="bio-extract-v1",
    build_prompt=_bio_prompt,
    description="Employer / role / location / entity type from bio text.",
))
