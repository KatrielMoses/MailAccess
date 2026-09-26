"""JEV-6 — narrative output tasks (the only phase that emits user-facing free text).

Hallucination control is load-bearing, so the call sites
(``backend.core.jev_narrative``) re-validate every output at the boundary and DEFER
/ drop anything that introduces an entity absent from the input. JEV supplies only
wording and grounded, hypothesis-framed correlations; it never changes the risk
level, any score, the severity order, or the SET of findings/actions.

* ``narrative.brief_wording`` — reword the already-decided Defender's Brief
  (summary, next action, finding lines) with the SAME finding count/order.
* ``narrative.finding_correlation`` — a small capped set of "analyst leads", each
  citing the finding ids it is built from, framed as hypotheses to verify.
"""

from __future__ import annotations

import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..contract import JevTask, register

BRIEF_WORDING = "narrative.brief_wording"
FINDING_CORRELATION = "narrative.finding_correlation"

MAX_FINDING_LINES = 12
MAX_LEADS = 6
MAX_BASED_ON = 8
_LINE_LEN = 400
_SUMMARY_LEN = 800
_LEAD_LEN = 400


def _dump(payload: BaseModel) -> str:
    return json.dumps(payload.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# narrative.brief_wording
# ---------------------------------------------------------------------------
class BriefFindingIn(BaseModel):
    severity: str = Field(max_length=20)
    text: str = Field(max_length=_LINE_LEN)


class BriefInput(BaseModel):
    risk_level: str = Field(max_length=20)
    subject_email: str = Field(max_length=254)
    subject_name: str | None = Field(default=None, max_length=120)
    next_action: str = Field(max_length=_LINE_LEN)
    findings: list[BriefFindingIn] = Field(default_factory=list, max_length=MAX_FINDING_LINES)


class BriefOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(max_length=_SUMMARY_LEN)
    next_action: str = Field(max_length=_LINE_LEN)
    finding_lines: list[Annotated[str, Field(max_length=_LINE_LEN)]] = Field(
        default_factory=list, max_length=MAX_FINDING_LINES
    )


def _brief_prompt(inp: BriefInput) -> tuple[str, str]:
    system = (
        "You rewrite an already-decided security 'Defender's Brief' into clear, natural "
        "language for the account owner. You are given the finished brief — do not "
        "change its meaning. Rewrite `summary` and `next_action`, and reword each "
        "finding line, returning EXACTLY as many finding_lines as you were given, in "
        "the same order. You MUST NOT introduce any email address, domain, personal "
        "name, platform, or breach that is not already in the input, and MUST NOT state "
        "the risk level or invent numbers. Describe findings as observations, never as "
        "'verified' or 'confirmed'. Keep it concise and factual."
    )
    return system, _dump(inp)


# ---------------------------------------------------------------------------
# narrative.finding_correlation
# ---------------------------------------------------------------------------
class FindingIn(BaseModel):
    id: str = Field(max_length=80)
    type: str = Field(max_length=60)
    summary: str = Field(max_length=_LINE_LEN)


class CorrelationInput(BaseModel):
    subject_email: str = Field(max_length=254)
    subject_name: str | None = Field(default=None, max_length=120)
    findings: list[FindingIn] = Field(min_length=1, max_length=60)
    breaches: list[str] = Field(default_factory=list, max_length=40)
    roles: list[str] = Field(default_factory=list, max_length=20)
    max_leads: int = Field(ge=1, le=MAX_LEADS)


class Lead(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(max_length=_LEAD_LEN)
    based_on: list[Annotated[str, Field(max_length=80)]] = Field(max_length=MAX_BASED_ON)
    severity_hint: Literal["low", "medium", "high"]


class CorrelationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    leads: list[Lead] = Field(default_factory=list, max_length=MAX_LEADS)


def _correlation_prompt(inp: CorrelationInput) -> tuple[str, str]:
    system = (
        "You connect an investigation's findings into a few 'analyst leads' — concrete "
        "things worth CHECKING NEXT, framed strictly as hypotheses to verify, never as "
        "facts. Each lead cites in `based_on` the exact finding ids it is built from "
        "(use only ids from the input). You MUST NOT name any email, domain, person, "
        "platform, or breach that is not present in the input findings/identity. Never "
        "call anything 'verified' or 'confirmed'. Return at most the requested number "
        "of leads, most useful first; if nothing worthwhile connects, return none."
    )
    return system, _dump(inp)


register(JevTask(
    name=BRIEF_WORDING,
    input_model=BriefInput,
    output_model=BriefOutput,
    prompt_version="brief-wording-v1",
    build_prompt=_brief_prompt,
    description="Natural-language rewrite of the already-decided Defender's Brief.",
))

register(JevTask(
    name=FINDING_CORRELATION,
    input_model=CorrelationInput,
    output_model=CorrelationOutput,
    prompt_version="finding-correlation-v1",
    build_prompt=_correlation_prompt,
    description="Grounded, hypothesis-framed analyst leads across findings.",
))
