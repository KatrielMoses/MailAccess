"""JEV-0.2 — provider adapters behind the seam.

The task registry (JEV-0) is unchanged; only HOW a task's request is issued differs
by configured provider. Two adapters share one interface —
``await run(profile, task, inp, *, timeout) -> dict | DeferReason`` returning a JSON
object (with a ``confidence`` field) the seam validates against the task's schema:

* ``chat`` — OpenAI-compatible chat completions (provider ``jev`` hosted, or
  ``openai`` for any base_url incl. local llama.cpp / atomic.chat). Prompt-and-parse
  via :mod:`.client`.
* ``ollaya`` — the local typed-decision server. The task's OUTPUT SCHEMA is
  translated into Ollaya ``questions`` (enums → choice/criteria, bounded fields →
  typed fields); the typed answer is mapped back into the schema shape. No prompting.

Activation, caching, metrics, limits and the breaker all stay in the seam.
"""

from __future__ import annotations

import asyncio
import enum
import json
import logging
import typing
from dataclasses import dataclass
from typing import Any, Literal

import httpx

from . import client
from .contract import DeferReason, JevTask

_LOG = logging.getLogger(__name__)

OLLAYA = "ollaya"
# ``jev`` (hosted TypeSafe) and ``ollaya`` (local) both speak the typed-decisions
# System One protocol — same request body, same nested answer shape — so they share
# the one adapter below. ``openai`` remains a generic OpenAI-compatible chat provider
# (atomic.chat / llama.cpp) driven by prompt-and-parse in :mod:`.client`.
CHAT_PROVIDERS = frozenset({"openai"})
TYPED_PROVIDERS = frozenset({"jev", OLLAYA})
KNOWN_PROVIDERS = CHAT_PROVIDERS | TYPED_PROVIDERS

DEFAULT_OLLAYA_BASE = "http://localhost:11435"
DEFAULT_JEV_BASE = "https://api.typesafe.ai"
DEFAULT_JEV_MODEL = "jev-latest"
_OLLAYA_PATHS = ("/v1/systemone", "/api/decide")
_MAX_RESPONSE_BYTES = 64 * 1024


@dataclass(frozen=True)
class Profile:
    """A resolved reasoner provider profile (never logged with its key)."""

    provider: str
    base_url: str
    model: str
    api_key: str = ""

    @property
    def identity_material(self) -> str:
        # Keyed for the breaker: provider + endpoint + key fingerprint (opaque).
        return f"{self.provider}\x1f{self.base_url}\x1f{self.model}\x1f{self.api_key}"

    def config_ok(self) -> bool:
        if self.provider == "openai":
            return bool(self.base_url and self.model)
        if self.provider == "jev":
            # Hosted TypeSafe: an API key is mandatory (Bearer auth, off-loopback).
            return bool(self.base_url and self.model and self.api_key)
        if self.provider == OLLAYA:
            return bool(self.base_url and self.model)
        return False


def _uses_legacy_shortcut(settings: Any) -> bool:
    """A bare ``JEV_API_KEY`` with no explicit provider (JEV-0.1 compatibility)."""
    return bool((getattr(settings, "jev_api_key", "") or "").strip()) and not (
        getattr(settings, "jev_provider", "") or ""
    ).strip()


def resolve_profile(settings: Any) -> Profile | None:
    """The configured provider profile, or None when unconfigured."""
    provider = (getattr(settings, "jev_provider", "") or "").strip().lower()
    key = (getattr(settings, "jev_api_key", "") or "").strip()
    if not provider:
        if key:
            provider = "jev"  # legacy shortcut: a bare key means the hosted provider
        else:
            return None
    base = (getattr(settings, "jev_base_url", "") or "").strip()
    model = (getattr(settings, "jev_model", "") or "").strip()
    if provider == OLLAYA and not base:
        base = DEFAULT_OLLAYA_BASE
    if provider == "jev":
        base = base or DEFAULT_JEV_BASE
        model = model or DEFAULT_JEV_MODEL
    return Profile(provider=provider, base_url=base, model=model, api_key=key)


def is_enabled(settings: Any) -> bool:
    """Master switch: explicitly enabled, or the legacy key shortcut."""
    return bool(getattr(settings, "jev_enabled", False)) or _uses_legacy_shortcut(settings)


def provider_cache_tag(profile: Profile) -> str:
    """Cache-key fragment for the provider. Typed-decision providers include the
    questions-spec version so a change to the schema→questions idiom invalidates
    cleanly; the provider name keeps ``jev`` and ``ollaya`` caches distinct."""
    if profile.provider in TYPED_PROVIDERS:
        return f"{profile.provider}:{QUESTIONS_VERSION}"
    return profile.provider


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
async def run(
    profile: Profile,
    task: JevTask[Any, Any],
    inp: Any,
    *,
    system: str,
    user: str,
    timeout: float,
) -> dict[str, Any] | DeferReason:
    """Issue one request to the configured provider; return a JSON object or reason."""
    if profile.provider in CHAT_PROVIDERS:
        return await client.chat_json(
            base_url=profile.base_url, api_key=profile.api_key, model=profile.model,
            system=system, user=user, timeout=timeout, task=task.name,
        )
    if profile.provider in TYPED_PROVIDERS:
        return await _ollaya_run(profile, task, inp, timeout=timeout)
    return DeferReason.NO_PROVIDER


# ---------------------------------------------------------------------------
# Ollaya adapter — schema -> questions, typed answer -> schema shape
# ---------------------------------------------------------------------------
async def _ollaya_run(
    profile: Profile, task: JevTask[Any, Any], inp: Any, *, timeout: float
) -> dict[str, Any] | DeferReason:
    decomposer = _DECOMPOSERS.get(task.name)
    if task.name in _GENERATIVE_TASKS and decomposer is None:
        # Free-text extraction / generation is out of distribution for a typed-decision
        # model: there is no decision to make, only prose to write. DEFER — these tasks
        # need a generative provider (chat), which stays their only backend.
        _LOG.debug("Ollaya: generative task, no typed form (task=%s)", task.name)
        return DeferReason.SCHEMA
    try:
        questions = schema_to_questions(task.output_model)
    except UnsupportedForOllaya:
        # JEV-0.4: a list-shaped task that decomposes into atomic choices runs the
        # per-item form; anything else DEFERs (JEV-0.3 behavior).
        if decomposer is None:
            _LOG.debug("Ollaya schema unsupported, no decomposer (task=%s)", task.name)
            return DeferReason.SCHEMA
        return await _ollaya_decomposed(profile, task, inp, decomposer, timeout=timeout)
    except Exception:
        _LOG.debug("Ollaya schema translation failed (task=%s)", task.name)
        return DeferReason.SCHEMA
    body = {
        "model": profile.model,
        "state": inp.model_dump(mode="json") if hasattr(inp, "model_dump") else inp,
        "questions": questions,
    }
    headers = {"Content-Type": "application/json"}
    if profile.api_key:
        headers["Authorization"] = f"Bearer {profile.api_key}"
    base = profile.base_url.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=timeout, transport=client._TRANSPORT) as http:
            answers = await _first_path(http, base, body, headers, task.name)
            if isinstance(answers, DeferReason):
                return answers
            return _answers_to_output(task.output_model, answers)
    except (httpx.ConnectError, httpx.ConnectTimeout, OSError):
        return DeferReason.PROVIDER_UNREACHABLE
    except httpx.TimeoutException:
        return DeferReason.TIMEOUT
    except httpx.HTTPError:
        return DeferReason.PROVIDER_UNREACHABLE
    except Exception:
        return DeferReason.INTERNAL


async def _ollaya_post(
    http: httpx.AsyncClient, url: str, body: dict[str, Any], headers: dict[str, str], task: str
) -> dict[str, Any] | DeferReason:
    resp = await http.post(url, json=body, headers=headers)
    status = resp.status_code
    if status == 404:
        return DeferReason.MODEL_NOT_LOADED  # endpoint or model absent → try next path
    if status == 402:
        return DeferReason.CREDITS_EXHAUSTED  # hosted jev: out of credits (hard trip)
    if status in (401, 403):
        return DeferReason.AUTH_FAILED
    if status == 429:
        return DeferReason.RATE_LIMITED
    if status >= 500:
        return DeferReason.SERVER_ERROR
    if status != 200:
        return DeferReason.HTTP_STATUS
    raw = resp.content[:_MAX_RESPONSE_BYTES]
    try:
        payload = json.loads(raw)
    except ValueError:
        return DeferReason.NON_JSON
    if not isinstance(payload, dict):
        return DeferReason.NON_JSON
    # Typed answers live under one of these keys, or at the top level.
    for key in ("answers", "decisions", "result", "data"):
        block = payload.get(key)
        if isinstance(block, dict):
            block = dict(block)
            for meta_key in ("confidence", "score"):
                if meta_key in payload and meta_key not in block:
                    block[meta_key] = payload[meta_key]
            return block
    return payload


# ---------------------------------------------------------------------------
# JEV-0.4 — per-item typed-decision form for decomposable list tasks
# ---------------------------------------------------------------------------
# A decomposable task registers a Decomposer: it turns the task input into many
# atomic choice items, then reassembles the atomic answers into the task's output
# dict IN OUR CODE (the model only ever answers one choice). The seam validates the
# assembled dict against the task schema exactly as for the one-shot form.
_MAX_DECOMPOSE_ITEMS = 60
_DECOMPOSE_CONCURRENCY = 8


@dataclass(frozen=True)
class DecisionItem:
    key: str  # opaque handle the assembler uses to place this answer
    field: str  # the Ollaya questions field name
    question: dict[str, Any]  # a choice/typed spec (same idiom as schema_to_questions)
    state: dict[str, Any]  # the per-item Ollaya input (context for this one decision)


class Decomposer:
    """Per-item form of a list task. Subclasses implement ``items`` + ``assemble``."""

    def items(self, inp: Any) -> list[DecisionItem]:  # pragma: no cover - interface
        raise NotImplementedError

    def assemble(  # pragma: no cover - interface
        self, inp: Any, answers: dict[str, str]
    ) -> dict[str, Any] | None:
        raise NotImplementedError


_DECOMPOSERS: dict[str, Decomposer] = {}


def register_decomposer(task_name: str, decomposer: Decomposer) -> None:
    _DECOMPOSERS[task_name] = decomposer


async def _ollaya_decomposed(
    profile: Profile, task: JevTask[Any, Any], inp: Any, decomposer: Decomposer, *, timeout: float
) -> dict[str, Any] | DeferReason:
    try:
        items = decomposer.items(inp)[:_MAX_DECOMPOSE_ITEMS]
    except Exception:
        _LOG.debug("Ollaya decompose build failed (task=%s)", task.name)
        return DeferReason.SCHEMA
    if not items:
        return DeferReason.SCHEMA
    headers = {"Content-Type": "application/json"}
    if profile.api_key:
        headers["Authorization"] = f"Bearer {profile.api_key}"
    base = profile.base_url.rstrip("/")
    sem = asyncio.Semaphore(_DECOMPOSE_CONCURRENCY)

    async def _one(
        http: httpx.AsyncClient, item: DecisionItem
    ) -> tuple[str, float | None] | DeferReason:
        body = {"model": profile.model, "state": item.state,
                "questions": {item.field: item.question}}
        async with sem:
            answer = await _first_path(http, base, body, headers, task.name)
        if isinstance(answer, DeferReason):
            return answer
        raw = answer.get(item.field)
        value = answer_value(raw)
        if value is None:
            return DeferReason.SCHEMA  # partial answer → DEFER the whole task
        return str(value).strip().lower(), answer_confidence(raw)

    try:
        async with httpx.AsyncClient(timeout=timeout, transport=client._TRANSPORT) as http:
            results = await asyncio.gather(*(_one(http, item) for item in items))
    except (httpx.ConnectError, httpx.ConnectTimeout, OSError):
        return DeferReason.PROVIDER_UNREACHABLE
    except httpx.TimeoutException:
        return DeferReason.TIMEOUT
    except httpx.HTTPError:
        return DeferReason.PROVIDER_UNREACHABLE
    except Exception:
        return DeferReason.INTERNAL

    answers: dict[str, str] = {}
    confidences: list[float] = []
    for item, result in zip(items, results):
        if isinstance(result, DeferReason):
            return result  # a provider error or partial answer defers the whole task
        value, conf = result
        answers[item.key] = value
        if conf is not None:
            confidences.append(conf)
    try:
        out = decomposer.assemble(inp, answers)
    except Exception:
        _LOG.debug("Ollaya decompose assemble failed (task=%s)", task.name)
        return DeferReason.SCHEMA
    if out is None:
        return DeferReason.SCHEMA
    # Verdict confidence = MIN of the atomic per-item confidences (conservative); the
    # seam's floor then gates the assembled decision. 1.0 when the provider gave none.
    out.setdefault("confidence", min(confidences) if confidences else 1.0)
    return out


async def _first_path(
    http: httpx.AsyncClient, base: str, body: dict[str, Any], headers: dict[str, str], task: str
) -> dict[str, Any] | DeferReason:
    """POST to /v1/systemone, falling back to /api/decide only when it is absent."""
    reason: DeferReason | None = None
    for path in _OLLAYA_PATHS:
        answer = await _ollaya_post(http, base + path, body, headers, task)
        if isinstance(answer, DeferReason):
            reason = answer
            if answer is DeferReason.MODEL_NOT_LOADED:
                continue
            return answer
        return answer
    return reason or DeferReason.PROVIDER_UNREACHABLE


# Version of the schema→questions translation. Part of the typed-provider cache key
# so a change to the question idiom invalidates cleanly. Bumped for JEV-0.5: the
# System One spec — booleans → ``noul``, enums → ``choice`` with a ``criteria`` DICT
# and per-question ``instructions`` — verified live against both api.typesafe.ai and
# a local Ollaya server.
QUESTIONS_VERSION = "q2"

# Tasks whose real output is generated prose / free-text extraction, not a typed
# decision. A typed-decision model (jev or ollaya) has nothing to answer for these,
# so they DEFER to the chat provider. The list-shaped generative tasks
# (query_generate, brief_wording, finding_correlation) already DEFER because their
# schema has no typed fields; bio_extract needs an explicit entry because its one
# enum field would otherwise make it look answerable while the point is the strings.
_GENERATIVE_TASKS = frozenset({"identity.bio_extract"})


def _humanize(token: str) -> str:
    """A short human-readable gloss for a field/label name used as instructions or
    per-option guidance (the model was trained on natural-language criteria)."""
    return token.replace("_", " ").replace("-", " ").strip()


def choice_question(labels: typing.Iterable[Any], instructions: str = "") -> dict[str, Any]:
    """Build a System One ``choice`` question. ``criteria`` is a DICT of
    ``{label: guidance}`` (both backends reject a bare list). Used by the one-shot
    schema translation and by the per-item decomposers so both speak one idiom."""
    criteria = {str(label): _humanize(str(label)) for label in labels}
    q: dict[str, Any] = {"type": "choice", "criteria": criteria}
    if instructions:
        q["instructions"] = instructions
    return q


class UnsupportedForOllaya(ValueError):
    """A task output field cannot be expressed in Ollaya's Custom-JSON idiom.

    Our tasks are enum/choice/boolean decisions plus short typed fields — a direct
    fit. Anything exotic (a list, a nested object) is out of distribution, so the
    adapter DEFERs that task to the chat providers / existing logic rather than
    sending a shape the fine-tuned model was not trained on.
    """


def schema_to_questions(output_model: Any) -> dict[str, Any]:
    """Build a task's Ollaya Custom-JSON ``questions`` from its output schema.

    The registered output schema is the source of truth — this never maps a task
    onto one of Ollaya's built-in presets. Raises :class:`UnsupportedForOllaya`
    when a field is not expressible in the choice/typed idiom.
    """
    questions: dict[str, Any] = {}
    for name, field in output_model.model_fields.items():
        ann, _optional = _unwrap_optional(field.annotation)
        if ann is str:
            # A free-text field carries no typed decision. Skip it when it is not
            # required (has a default or is Optional) — it falls back to the schema
            # default and the typed core still validates. A REQUIRED free-text field
            # means the task is not a typed decision → DEFER.
            if not field.is_required():
                continue
            raise UnsupportedForOllaya(f"field {name!r} is a required free-text field")
        questions[name] = _field_to_question(name, field)
    if not questions:
        # Nothing but free-text: no decision for the typed model to make.
        raise UnsupportedForOllaya("no typed-decision fields in output schema")
    return questions


def _field_to_question(name: str, field: Any) -> dict[str, Any]:
    ann, _optional = _unwrap_optional(field.annotation)
    origin = typing.get_origin(ann)
    instructions = (getattr(field, "description", None) or _humanize(name)).strip()
    if origin is Literal:
        # Enum-as-Literal → a choice over the exact values (in the trained idiom).
        return choice_question([str(v) for v in typing.get_args(ann)], instructions)
    if isinstance(ann, type) and issubclass(ann, enum.Enum):
        return choice_question([str(m.value) for m in ann], instructions)
    if ann is bool:
        # A boolean is a yes/no probability question — the System One ``noul`` type.
        return {"type": "noul", "instructions": instructions}
    # int has no System One type (both backends reject ``integer``); lists / nested
    # objects are out of distribution. Refuse so the task DEFERs cleanly.
    raise UnsupportedForOllaya(f"field {name!r} ({ann!r}) is not a typed-decision field")


def answer_value(raw: Any) -> Any:
    """The scalar answer from a System One field result.

    The server nests each answer by type:
      * ``noul``   → ``{"type":"noul","noul":0.93}`` — a yes-probability; ≥0.5 is yes.
      * ``choice`` → ``{"type":"choice","choice":"no_such_user","confidence":1.0,...}``.
      * ``score``  → ``{"type":"score","score":1.0,"confidence":1.0,"legend":{...}}``.
    Some paths / mocks return the bare value. Handle all of them.
    """
    if isinstance(raw, dict):
        kind = raw.get("type")
        if kind == "noul" and isinstance(raw.get("noul"), int | float):
            return bool(float(raw["noul"]) >= 0.5)
        if kind == "score" and "score" in raw:
            return raw["score"]
        for key in ("choice", "value", "answer", "number", "text"):
            if key in raw:
                return raw[key]
        # Bare typed answers without an explicit ``type`` tag.
        if isinstance(raw.get("noul"), int | float):
            return bool(float(raw["noul"]) >= 0.5)
        return None
    return raw


def answer_confidence(raw: Any) -> float | None:
    """Per-answer confidence in [0, 1].

    ``choice``/``score`` carry an explicit ``confidence``. ``noul`` carries only a
    yes-probability ``p``; its confidence is the distance from the coin-flip, i.e.
    ``max(p, 1 - p)`` (a 0.93 yes and a 0.07 no are both 0.93-confident)."""
    if isinstance(raw, dict):
        if isinstance(raw.get("noul"), int | float):
            p = float(raw["noul"])
            return max(p, 1.0 - p)
        val = raw.get("confidence")
        if isinstance(val, int | float):
            return float(val)
    return None


def _answers_to_output(output_model: Any, answers: dict[str, Any]) -> dict[str, Any]:
    """Coerce Ollaya's typed answers into the schema shape (+ a confidence).

    The verdict confidence is the MIN of the per-field confidences (conservative —
    the seam's floor then gates on the least-certain field); 1.0 when none is given.
    """
    out: dict[str, Any] = {}
    confidences: list[float] = []
    for name, field in output_model.model_fields.items():
        if name not in answers:
            continue
        raw = answers[name]
        out[name] = _coerce_answer(field.annotation, answer_value(raw))
        conf = answer_confidence(raw)
        if conf is not None:
            confidences.append(conf)
    if not confidences:
        block_conf = answers.get("confidence", answers.get("score"))
        if isinstance(block_conf, int | float):
            confidences.append(float(block_conf))
    out["confidence"] = min(confidences) if confidences else 1.0
    return out


def _coerce_answer(annotation: Any, value: Any) -> Any:
    ann, _optional = _unwrap_optional(annotation)
    if value is None:
        return None
    if ann is bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, int | float):  # a bare noul probability
            return float(value) >= 0.5
        return str(value).strip().lower() in {"true", "yes", "1"}
    if ann is int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return value
    return value  # choice / enum / str pass through as-is


def _unwrap_optional(annotation: Any) -> tuple[Any, bool]:
    origin = typing.get_origin(annotation)
    if origin is typing.Annotated:
        return _unwrap_optional(typing.get_args(annotation)[0])
    import types as _types

    if origin in (typing.Union, _types.UnionType):
        args = typing.get_args(annotation)
        non_none = [a for a in args if a is not type(None)]
        if len(non_none) == 1:
            inner, _ = _unwrap_optional(non_none[0])
            return inner, len(non_none) != len(args)
    return annotation, False
