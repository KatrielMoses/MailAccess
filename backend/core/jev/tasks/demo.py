"""JEV-0 demo task: "is this string a plausible personal name?"

Exists ONLY to exercise the seam end to end (registry → prompt → model → schema
→ cache → metrics → fallback). It is deliberately NOT wired into any real
decision; name handling in the engine is untouched until a later JEV phase.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..contract import DEFER, JevTask, register
from ..seam import judge

TASK_NAME = "demo.plausible_personal_name"


class NameInput(BaseModel):
    text: str = Field(min_length=1, max_length=200)

    @field_validator("text")
    @classmethod
    def _normalize(cls, value: str) -> str:
        # Normalized before hashing so trivially different spellings share a cache key.
        return " ".join(value.split())


class NameOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_personal_name: bool


def _prompt(inp: NameInput) -> tuple[str, str]:
    system = (
        "You classify short strings. Decide whether the string is plausibly a real "
        "human's personal name (given name and/or family name, any culture). Company "
        "names, usernames, role titles, placeholders and random text are not."
    )
    return system, f"String: {inp.text!r}"


TASK = register(
    JevTask(
        name=TASK_NAME,
        input_model=NameInput,
        output_model=NameOutput,
        prompt_version="demo-name-v1",
        build_prompt=_prompt,
        description="Demo only — plausible personal name (not wired to any decision).",
    )
)


def fallback_is_personal_name(text: str) -> bool:
    """Today-style rigid rule: 2-4 alphabetic, capitalized tokens."""
    tokens = text.split()
    return 2 <= len(tokens) <= 4 and all(
        t[:1].isupper() and t.replace("-", "").replace("'", "").isalpha() for t in tokens
    )


async def is_plausible_personal_name(text: str) -> tuple[bool, str]:
    """Reference caller pattern for JEV-1+: ask JEV, fall back deterministically.

    Returns ``(answer, source)`` where source is ``"jev"`` or ``"rule"``.
    """
    verdict = await judge(TASK_NAME, {"text": text})
    if verdict is DEFER:
        return fallback_is_personal_name(text), "rule"
    return verdict.output.is_personal_name, verdict.provenance.source
