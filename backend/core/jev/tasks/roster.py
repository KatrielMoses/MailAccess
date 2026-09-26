"""JEV-3 — harvest roster quality tasks.

Four bounded judgments that clean the harvest ROSTER (which names / people /
titles / company), never the labeling, confidence, verification, or persistence of
any address. Bias to keep: the drop (Task 1) and merge (Task 3) verdicts carry
high confidence floors, so on any doubt the seam DEFERs and today's behavior (keep
/ keep-separate) stands. Company resolution (Task 4) can only choose among the real
candidate orgs the engine already returned — its output is an index, never a name
or domain, so JEV can never fabricate one.
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..contract import JevTask, register

PERSON_FILTER = "roster.person_filter"
TITLE_NORMALIZE = "roster.title_normalize"
PERSON_DEDUPE = "roster.person_dedupe"
COMPANY_RESOLVE = "roster.company_resolve"

MAX_ORG_CANDIDATES = 20

# Buckets mirror backend.core.seniority_classifier BAND_* exactly.
SeniorityBucket = Literal["c-level", "vp", "director", "manager", "ic", "unknown"]


def _dump(payload: BaseModel) -> str:
    return json.dumps(payload.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# roster.person_filter — real person vs page noise
# ---------------------------------------------------------------------------
class PersonFilterInput(BaseModel):
    candidate: str = Field(min_length=1, max_length=120)
    context: str | None = Field(default=None, max_length=600)
    source: str | None = Field(default=None, max_length=60)


class PersonFilterOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_person_name: Literal["yes", "no", "unclear"] = Field(
        description=("Is this candidate a real individual person's name, not a team, "
                     "role, department, product, or navigation label?")
    )
    normalized_name: str | None = Field(default=None, max_length=120)


def _person_filter_prompt(inp: PersonFilterInput) -> tuple[str, str]:
    system = (
        "You decide whether a candidate string extracted from a web page or search "
        "result is a real individual person's name, as opposed to page/navigation "
        "boilerplate, a section heading, a company/product/brand name, a job title, or "
        "other non-name text. Use the surrounding context. Answer 'no' only when you "
        "are confident it is not a personal name; 'yes' for a real personal name "
        "(optionally give its clean normalized form); 'unclear' when the context does "
        "not decide it. Never drop a real person on doubt — prefer 'unclear'."
    )
    return system, _dump(inp)


# ---------------------------------------------------------------------------
# roster.title_normalize — messy/multilingual title -> seniority bucket
# ---------------------------------------------------------------------------
class TitleInput(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    company: str | None = Field(default=None, max_length=120)
    industry: str | None = Field(default=None, max_length=80)


class TitleOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seniority_bucket: SeniorityBucket = Field(
        description="Seniority band of this job title (c-level, vp, director, manager, ic)."
    )
    # Free-text; the typed core is seniority_bucket. Optional so a typed-decision
    # provider (jev/ollaya) can answer the bucket alone and still validate.
    normalized_title: str | None = Field(default=None, max_length=120)


def _title_prompt(inp: TitleInput) -> tuple[str, str]:
    system = (
        "You map a free-text job title (any language, any format) to one seniority "
        "bucket: 'c-level' (CEO/CxO/founder/owner/partner), 'vp' (vice president / "
        "SVP / head of a large org), 'director' (director / head of a function), "
        "'manager' (manages people or a team/lead), 'ic' (individual contributor with "
        "no reports), or 'unknown' when the title does not indicate seniority. Also "
        "give a short English normalized_title. Use the company/industry only as "
        "context; do not invent a seniority the title does not support."
    )
    return system, _dump(inp)


# ---------------------------------------------------------------------------
# roster.person_dedupe — same person across sources
# ---------------------------------------------------------------------------
class PersonEntry(BaseModel):
    name: str | None = Field(default=None, max_length=120)
    emails: list[str] = Field(default_factory=list, max_length=8)
    titles: list[str] = Field(default_factory=list, max_length=6)
    source: str | None = Field(default=None, max_length=60)
    profile_links: list[str] = Field(default_factory=list, max_length=8)


class DedupeInput(BaseModel):
    a: PersonEntry
    b: PersonEntry


class DedupeOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    same_person: Literal["yes", "no", "unclear"] = Field(
        description="Are entries A and B the same person (duplicate roster rows)?"
    )


def _dedupe_prompt(inp: DedupeInput) -> tuple[str, str]:
    system = (
        "You decide whether two harvested person entries are the SAME real individual "
        "at one company, written slightly differently across sources (nickname vs full "
        "name, initials, spelling, a shared email or profile link). Two different "
        "people who merely share a common name, or a first name in common, are NOT the "
        "same person. Answer 'yes' only when you are confident they are one person; "
        "otherwise 'no' or 'unclear'. Never merge two distinct people on doubt."
    )
    return system, _dump(inp)


# ---------------------------------------------------------------------------
# roster.company_resolve — company name -> the right org among real candidates
# ---------------------------------------------------------------------------
class OrgCandidate(BaseModel):
    name: str = Field(max_length=200)
    domain: str | None = Field(default=None, max_length=253)
    employees: int | None = Field(default=None, ge=0)


class CompanyResolveInput(BaseModel):
    query: str = Field(min_length=1, max_length=200)
    candidates: list[OrgCandidate] = Field(min_length=2, max_length=MAX_ORG_CANDIDATES)


class CompanyResolveOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chosen_index: int | None = None
    reason: str = Field(default="", max_length=200)  # never stored by the call site


def _company_prompt(inp: CompanyResolveInput) -> tuple[str, str]:
    system = (
        "You pick which candidate organization a company-name query refers to. "
        "Candidates are numbered from 0 in the order given. Return `chosen_index` = "
        "the index of the single best-matching real organization, or null if none is a "
        "confident match or several are equally plausible. You may only choose from the "
        "provided candidates — never invent a name or domain. Prefer the org whose "
        "name and domain match the query; use employee counts only to break ties."
    )
    return system, _dump(inp)


register(JevTask(
    name=PERSON_FILTER,
    input_model=PersonFilterInput,
    output_model=PersonFilterOutput,
    prompt_version="person-filter-v1",
    build_prompt=_person_filter_prompt,
    # High floor: a drop removes a candidate, so only a confident 'no' acts.
    min_confidence=0.85,
    description="Real person vs page noise for an ambiguous roster candidate.",
))

register(JevTask(
    name=TITLE_NORMALIZE,
    input_model=TitleInput,
    output_model=TitleOutput,
    prompt_version="title-normalize-v1",
    build_prompt=_title_prompt,
    description="Map a messy/multilingual title to a seniority bucket (metadata).",
))

register(JevTask(
    name=PERSON_DEDUPE,
    input_model=DedupeInput,
    output_model=DedupeOutput,
    prompt_version="person-dedupe-v1",
    build_prompt=_dedupe_prompt,
    # High floor: a merge collapses two rows, so only a confident 'yes' acts.
    min_confidence=0.85,
    description="Same-person judgment for an ambiguous near-duplicate pair.",
))

register(JevTask(
    name=COMPANY_RESOLVE,
    input_model=CompanyResolveInput,
    output_model=CompanyResolveOutput,
    prompt_version="company-resolve-v1",
    build_prompt=_company_prompt,
    description="Pick the right org among real candidates (never fabricates).",
))
