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

CHAT_PROVIDERS = frozenset({"jev", "openai"})
OLLAYA = "ollaya"
KNOWN_PROVIDERS = CHAT_PROVIDERS | {OLLAYA}

DEFAULT_OLLAYA_BASE = "http://localhost:11435"
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
        if self.provider in CHAT_PROVIDERS:
            needs_key = self.provider == "jev"
            return bool(self.base_url and self.model and (self.api_key or not needs_key))
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
    return Profile(provider=provider, base_url=base, model=model, api_key=key)


def is_enabled(settings: Any) -> bool:
    """Master switch: explicitly enabled, or the legacy key shortcut."""
    return bool(getattr(settings, "jev_enabled", False)) or _uses_legacy_shortcut(settings)


def provider_cache_tag(profile: Profile) -> str:
    """Cache-key fragment for the provider. Ollaya includes the questions-spec
    version so a change to the schema→questions idiom invalidates cleanly."""
    if profile.provider == OLLAYA:
        return f"{OLLAYA}:{QUESTIONS_VERSION}"
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
    if profile.provider == OLLAYA:
        return await _ollaya_run(profile, task, inp, timeout=timeout)
    return DeferReason.NO_PROVIDER


# ---------------------------------------------------------------------------
# Ollaya adapter — schema -> questions, typed answer -> schema shape
# ---------------------------------------------------------------------------
async def _ollaya_run(
    profile: Profile, task: JevTask[Any, Any], inp: Any, *, timeout: float
) -> dict[str, Any] | DeferReason:
    try:
        questions = schema_to_questions(task.output_model)
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
            reason: DeferReason | None = None
            for path in _OLLAYA_PATHS:
                answers = await _ollaya_post(http, base + path, body, headers, task.name)
                if isinstance(answers, DeferReason):
                    reason = answers
                    # Only fall through to /api/decide when the endpoint is absent.
                    if answers is DeferReason.MODEL_NOT_LOADED:
                        continue
                    return answers
                return _answers_to_output(task.output_model, answers)
            return reason or DeferReason.PROVIDER_UNREACHABLE
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


# Version of the schema→questions translation. Part of the Ollaya cache key so a
# change to the question idiom invalidates cleanly (JEV-0.3).
QUESTIONS_VERSION = "q1"
# The yes/no choice used for boolean fields (the model's trained idiom).
_YES_NO = ("yes", "no")


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
        questions[name] = _field_to_question(name, field.annotation)
    return questions


def _field_to_question(name: str, annotation: Any) -> dict[str, Any]:
    ann, optional = _unwrap_optional(annotation)
    origin = typing.get_origin(ann)
    q: dict[str, Any]
    if origin is Literal:
        # Enum-as-Literal → a choice over the exact values (in the trained idiom).
        q = {"type": "choice", "criteria": [str(v) for v in typing.get_args(ann)]}
    elif isinstance(ann, type) and issubclass(ann, enum.Enum):
        q = {"type": "choice", "criteria": [str(m.value) for m in ann]}
    elif ann is bool:
        # A boolean rides the same choice idiom as a yes/no decision.
        q = {"type": "choice", "criteria": list(_YES_NO)}
    elif ann is int:
        q = {"type": "integer"}
    elif ann is str:
        q = {"type": "string"}
    else:
        # Lists / nested objects are out of distribution for the typed-decisions
        # model — refuse so the task DEFERs cleanly instead of sending noise.
        raise UnsupportedForOllaya(f"field {name!r} ({ann!r}) is not an Ollaya choice/typed field")
    if optional:
        q["required"] = False
    return q


def _answers_to_output(output_model: Any, answers: dict[str, Any]) -> dict[str, Any]:
    """Coerce Ollaya's typed answers into the schema shape (+ a confidence)."""
    out: dict[str, Any] = {}
    for name, field in output_model.model_fields.items():
        if name not in answers:
            continue
        out[name] = _coerce_answer(field.annotation, answers[name])
    confidence = answers.get("confidence", answers.get("score"))
    # A typed decision is deterministic; default to high confidence when the
    # provider does not score it (the seam's floor still gates it).
    out["confidence"] = float(confidence) if isinstance(confidence, int | float) else 1.0
    return out


def _coerce_answer(annotation: Any, value: Any) -> Any:
    ann, _optional = _unwrap_optional(annotation)
    if value is None:
        return None
    if ann is bool:
        if isinstance(value, bool):
            return value
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
