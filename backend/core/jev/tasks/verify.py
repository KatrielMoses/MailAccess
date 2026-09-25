"""JEV-2 — verification intelligence tasks.

Three bounded readers of noisy server replies/signals. Their output is only
evidence handed to the existing classifiers' consumers: the existing grading and
eligibility logic still decides every final label, and none of these outputs
carries a label such as "verified" / "valid" / "provider_verified" (the enums
below cannot express one).

Conservative by construction:
* every enum has an explicit ``unknown`` / ``unclear`` and the prompts ask for it
  on any doubt;
* the confidence floors are high, so a hesitant positive DEFERs to today's
  classifier instead of becoming evidence;
* call sites (``backend.core.jev_verify``) additionally ignore a positive answer
  wherever it could only upgrade a result — see that module.
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..contract import JevTask, register

REPLY_CLASSIFY = "verify.reply_classify"
CATCHALL_JUDGE = "verify.catchall_judge"
M365_SIGNAL_READ = "verify.m365_signal_read"

# High floors: on this path a DEFER (today's classifier) beats a hesitant answer.
_FLOOR = 0.9


def _dump(payload: BaseModel) -> str:
    return json.dumps(payload.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)


_CONSERVATIVE = (
    " Prefer 'unknown' whenever the text is ambiguous, generic, truncated, or a "
    "policy / rate-limit / greylist message. A wrong positive is worse than "
    "'unknown'; if unsure, answer unknown with a low confidence."
)


# ---------------------------------------------------------------------------
# verify.reply_classify — one mail-server reply -> verdict
# ---------------------------------------------------------------------------
class ReplyInput(BaseModel):
    protocol: Literal["smtp_rcpt", "imap_login"]
    code: int | None = Field(default=None, ge=0, le=999)
    text: str = Field(max_length=600)
    provider: str | None = Field(default=None, max_length=40)


class ReplyOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Literal["exists", "no_such_user", "catch_all", "temporary", "blocked", "unknown"]
    reason: str = Field(default="", max_length=200)  # accepted; never stored


def _reply_prompt(inp: ReplyInput) -> tuple[str, str]:
    system = (
        "You read one reply from a mail server that was asked whether a mailbox "
        "accepts mail, and classify what it means for that address. "
        "'exists' = the address is accepted; 'no_such_user' = the address is "
        "rejected as unknown; 'catch_all' = the reply shows the domain accepts every "
        "address; 'temporary' = a transient deferral (greylist / try again later); "
        "'blocked' = the check itself was refused (rate limit, policy, spam block) so "
        "nothing was learned; 'unknown' = anything else." + _CONSERVATIVE
    )
    return system, _dump(inp)


# ---------------------------------------------------------------------------
# verify.catchall_judge — real address vs random control probe
# ---------------------------------------------------------------------------
class Probe(BaseModel):
    code: int | None = Field(default=None, ge=0, le=999)
    text: str = Field(max_length=400)


class CatchallInput(BaseModel):
    domain: str = Field(max_length=253)
    provider: str | None = Field(default=None, max_length=40)
    # Optional: the real address's response is not always available at the
    # detection point (the SMTP detector probes only the random control).
    real_address: Probe | None = None
    control_probe: Probe


class CatchallOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    catch_all: Literal["yes", "no", "unclear"]


def _catchall_prompt(inp: CatchallInput) -> tuple[str, str]:
    system = (
        "A domain was probed with a random address that should not exist (the "
        "control), optionally alongside a real address. If the control gets an "
        "accepting response, the domain accepts every address (catch-all) and no "
        "individual address on it can be positively confirmed. Answer 'yes' when the "
        "control's response is an accept (equivalent to the real address's accept when "
        "given), 'no' only when the control is clearly rejected, 'unclear' otherwise."
        + _CONSERVATIVE
    )
    return system, _dump(inp)


# ---------------------------------------------------------------------------
# verify.m365_signal_read — Microsoft / Outlook signal interpretation
# ---------------------------------------------------------------------------
class M365Input(BaseModel):
    signals: dict[str, str | int | bool | None] = Field(default_factory=dict)


class M365Output(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mailbox: Literal["exists", "not_exists", "unknown"]
    managed_tenant: Literal["yes", "no", "unknown"]


def _m365_prompt(inp: M365Input) -> tuple[str, str]:
    system = (
        "You interpret Microsoft 365 / Outlook signals (credential-type existence "
        "result, throttle status, realm / namespace type, autodiscover outcome) that "
        "may be partial or conflicting. Decide whether the mailbox exists and whether "
        "the domain is a managed Microsoft 365 tenant. A throttled or rate-limited "
        "existence signal proves nothing about existence." + _CONSERVATIVE
    )
    return system, _dump(inp)


register(JevTask(
    name=REPLY_CLASSIFY,
    input_model=ReplyInput,
    output_model=ReplyOutput,
    prompt_version="reply-classify-v1",
    build_prompt=_reply_prompt,
    min_confidence=_FLOOR,
    description="Classify a novel/ambiguous SMTP-RCPT or IMAP-login reply.",
))

register(JevTask(
    name=CATCHALL_JUDGE,
    input_model=CatchallInput,
    output_model=CatchallOutput,
    prompt_version="catchall-judge-v1",
    build_prompt=_catchall_prompt,
    min_confidence=_FLOOR,
    description="Judge a borderline catch-all real-vs-control probe pair.",
))

register(JevTask(
    name=M365_SIGNAL_READ,
    input_model=M365Input,
    output_model=M365Output,
    prompt_version="m365-signal-read-v1",
    build_prompt=_m365_prompt,
    min_confidence=_FLOOR,
    description="Interpret partial/conflicting M365 existence + tenant signals.",
))
