"""JEV-4 — reach and selection tasks ("same budget, better choice").

Two bounded selectors that improve WHICH items are used within today's caps, never
how many. Neither can enlarge a probe wave or a query budget:

* ``reach.platform_select`` returns an ORDERED list of platform ids that the call
  site re-validates against the eligible set and truncates to the existing wave cap
  — JEV can only reorder/subset real, already-eligible platforms.
* ``reach.query_generate`` returns a capped list of query strings the call site
  length-checks and scope-checks against the subject/domain before use.

JEV never owns a number: changing which platforms/queries run changes findings, and
the existing scoring reacts to those inputs as always. JEV writes no score.
"""

from __future__ import annotations

import json
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from ..contract import JevTask, register

PLATFORM_SELECT = "reach.platform_select"
QUERY_GENERATE = "reach.query_generate"

# Hard ceilings on the model's output size (the call site caps again to the real
# per-run budget; these just bound the payload the seam will accept).
MAX_PLATFORM_IDS = 200
MAX_QUERIES = 12
_MAX_ID_LEN = 80
_MAX_QUERY_LEN = 512  # generous schema bound; jev_reach drops over its stricter op cap
_MAX_CANDIDATES = 400


def _dump(payload: BaseModel) -> str:
    return json.dumps(payload.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# reach.platform_select — per-subject wave selection
# ---------------------------------------------------------------------------
class PlatformCandidate(BaseModel):
    id: str = Field(max_length=_MAX_ID_LEN)
    category: str | None = Field(default=None, max_length=60)
    region: str | None = Field(default=None, max_length=60)
    rank: int | None = Field(default=None, ge=0)


class PlatformSelectInput(BaseModel):
    name: str | None = Field(default=None, max_length=120)
    email_localpart: str | None = Field(default=None, max_length=64)
    hints: list[str] = Field(default_factory=list, max_length=12)
    wave_cap: int = Field(ge=1, le=MAX_PLATFORM_IDS)
    candidates: list[PlatformCandidate] = Field(min_length=1, max_length=_MAX_CANDIDATES)


class PlatformSelectOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ordered_platform_ids: list[Annotated[str, Field(max_length=_MAX_ID_LEN)]] = Field(
        default_factory=list, max_length=MAX_PLATFORM_IDS
    )


def _platform_prompt(inp: PlatformSelectInput) -> tuple[str, str]:
    system = (
        "You choose which online platforms a specific subject is most likely to have "
        "an account on, to spend a fixed probe budget better. You are given the "
        "subject's signals and a pool of ELIGIBLE candidate platforms (id, category, "
        "region). Return `ordered_platform_ids`: the candidate ids most worth probing "
        "first, best-first, using ONLY ids from the pool. Prefer platforms matching "
        "the subject's region/language/interests and mainstream platforms; you need "
        "not include every id. Never invent an id. The caller keeps only the first "
        "few (the existing cap) and probes no more than today."
    )
    return system, _dump(inp)


# ---------------------------------------------------------------------------
# reach.query_generate — per-subject open-web queries
# ---------------------------------------------------------------------------
class QueryGenerateInput(BaseModel):
    email: str | None = Field(default=None, max_length=254)
    name: str | None = Field(default=None, max_length=120)
    domain: str | None = Field(default=None, max_length=253)
    employer: str | None = Field(default=None, max_length=120)
    handles: list[str] = Field(default_factory=list, max_length=8)
    engine: str = Field(max_length=40)
    max_queries: int = Field(ge=1, le=MAX_QUERIES)


class QueryGenerateOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    queries: list[Annotated[str, Field(max_length=_MAX_QUERY_LEN)]] = Field(
        default_factory=list, max_length=MAX_QUERIES
    )


def _query_prompt(inp: QueryGenerateInput) -> tuple[str, str]:
    system = (
        "You write focused web-search queries to find public information about ONE "
        "subject (an email address and/or the person/domain behind it), for the named "
        "search engine. Every query MUST be scoped to that subject — its email, name, "
        "domain, employer or known handles — using operators the engine supports "
        "(quotes, site:, filetype:). Never target an unrelated person or domain. "
        "Return at most the requested number of queries, best-first, each a single "
        "well-formed query string."
    )
    return system, _dump(inp)


register(JevTask(
    name=PLATFORM_SELECT,
    input_model=PlatformSelectInput,
    output_model=PlatformSelectOutput,
    prompt_version="platform-select-v1",
    build_prompt=_platform_prompt,
    description="Per-subject ordering of eligible platforms within the wave cap.",
))

register(JevTask(
    name=QUERY_GENERATE,
    input_model=QueryGenerateInput,
    output_model=QueryGenerateOutput,
    prompt_version="query-generate-v1",
    build_prompt=_query_prompt,
    description="Per-subject open-web queries within the existing query budget.",
))
