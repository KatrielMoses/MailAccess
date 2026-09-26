"""JEV-5 — signal-hygiene tasks (investigate noise control).

Three conservative classifiers that feed cleaner signals into the existing engine;
none writes a band or a score. Each biases against over-correction — the call sites
(``backend.core.jev_signal``) only act on a confident verdict and otherwise DEFER
to today's behavior.

* ``signal.role_system_classify`` — person vs shared/system mailbox (non-obvious
  addresses only; a confident role/shared answer gates personal enumeration).
* ``signal.common_name_context`` — is a common-name hit the subject or a same-name
  stranger (a confident ``is_subject`` lets the engine lift its common-name cap; a
  confident ``coincidental`` excludes the hit).
* ``signal.breach_canonicalize`` — do two breach source-name variants name the same
  breach (a confident ``yes`` collapses them; nothing is ever dropped or invented).
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..contract import JevTask, register

ROLE_SYSTEM_CLASSIFY = "signal.role_system_classify"
COMMON_NAME_CONTEXT = "signal.common_name_context"
BREACH_CANONICALIZE = "signal.breach_canonicalize"

# High floors: these tasks reduce noise, so a hesitant answer must DEFER, not act.
_FLOOR = 0.85


def _dump(payload: BaseModel) -> str:
    return json.dumps(payload.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# signal.role_system_classify
# ---------------------------------------------------------------------------
class RoleInput(BaseModel):
    localpart: str = Field(min_length=1, max_length=64)
    domain: str = Field(max_length=253)
    display_name: str | None = Field(default=None, max_length=120)
    seen_role: str | None = Field(default=None, max_length=80)


class RoleOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["person", "role_or_shared", "unclear"]


def _role_prompt(inp: RoleInput) -> tuple[str, str]:
    system = (
        "You decide whether an email address belongs to one individual person or is a "
        "shared / role / system mailbox (e.g. team, department, automated, or generic "
        "inbox) — even when the local-part is not an obvious word like 'info' or "
        "'noreply'. Consider the local-part, domain, and any display name/role seen. "
        "Answer 'role_or_shared' only when you are confident it is not a single "
        "person's mailbox; 'person' for an individual; 'unclear' otherwise. When "
        "unsure, prefer 'person' — a real person on an unusual address must not be "
        "mistaken for a shared inbox."
    )
    return system, _dump(inp)


# ---------------------------------------------------------------------------
# signal.common_name_context
# ---------------------------------------------------------------------------
class CommonNameInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    subject_email: str = Field(max_length=254)
    evidence: list[str] = Field(default_factory=list, max_length=20)


class CommonNameOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relation: Literal["is_subject", "coincidental", "unclear"]


def _common_name_prompt(inp: CommonNameInput) -> tuple[str, str]:
    system = (
        "A common personal name was tied to a subject email by some evidence. Decide "
        "whether that evidence really identifies the SUBJECT ('is_subject') or is a "
        "different person who merely shares the same common name ('coincidental'), or "
        "'unclear'. Weigh whether the platforms/handles credibly connect to this exact "
        "email. Because the name is common, only answer 'is_subject' when the evidence "
        "clearly points to the subject; on any doubt answer 'unclear' so the cautious "
        "default stands. Never over-claim a common-name identity."
    )
    return system, _dump(inp)


# ---------------------------------------------------------------------------
# signal.breach_canonicalize
# ---------------------------------------------------------------------------
class BreachInput(BaseModel):
    name_a: str = Field(min_length=1, max_length=120)
    name_b: str = Field(min_length=1, max_length=120)
    domain_a: str | None = Field(default=None, max_length=253)
    domain_b: str | None = Field(default=None, max_length=253)
    date_a: str | None = Field(default=None, max_length=40)
    date_b: str | None = Field(default=None, max_length=40)


class BreachOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    same_breach: Literal["yes", "no", "unclear"]
    canonical_name: str | None = Field(default=None, max_length=120)


def _breach_prompt(inp: BreachInput) -> tuple[str, str]:
    system = (
        "You decide whether two breach source-name variants refer to the SAME data "
        "breach incident (e.g. 'LinkedIn Scrape 2021' vs 'linkedin_2021'), using the "
        "names and any domain/date. Answer 'yes' only when you are confident they are "
        "the same breach, and give the best canonical_name; otherwise 'no' or "
        "'unclear'. Never merge two distinct breaches on doubt — keeping them separate "
        "is safe, wrongly collapsing them is not."
    )
    return system, _dump(inp)


register(JevTask(
    name=ROLE_SYSTEM_CLASSIFY,
    input_model=RoleInput,
    output_model=RoleOutput,
    prompt_version="role-system-v1",
    build_prompt=_role_prompt,
    min_confidence=_FLOOR,
    description="Person vs shared/system mailbox for a non-obvious address.",
))

register(JevTask(
    name=COMMON_NAME_CONTEXT,
    input_model=CommonNameInput,
    output_model=CommonNameOutput,
    prompt_version="common-name-v1",
    build_prompt=_common_name_prompt,
    min_confidence=_FLOOR,
    description="Common-name hit: the subject vs a same-name stranger.",
))

register(JevTask(
    name=BREACH_CANONICALIZE,
    input_model=BreachInput,
    output_model=BreachOutput,
    prompt_version="breach-canon-v1",
    build_prompt=_breach_prompt,
    min_confidence=_FLOOR,
    description="Do two breach source-name variants name the same breach.",
))
