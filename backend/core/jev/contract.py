"""The JEV task contract — what every JEV-1…6 decision registers against.

A task is a small, frozen :class:`JevTask` spec: a stable name, a typed input
model, a typed output model, a versioned prompt builder and an optional
confidence floor. Registering a spec is the ONLY step needed to add a task; the
plumbing (client, cache, limits, metrics, guards) is shared and task-agnostic.

The output model is checked at registration so the "schema-bounded" guarantee is
structural, not a convention: every field must be a bool, an int (selection
index), an Enum / Literal, a length-capped ``str``, or an Optional / length-capped
list of those, and the model must forbid extra keys. Floats are rejected outright
— JEV never owns a number; its only float is the envelope ``confidence``, which
the seam uses for gating and never hands to scoring.
"""

from __future__ import annotations

import enum
import types
import typing
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Generic, Literal, TypeVar

from annotated_types import MaxLen
from pydantic import BaseModel

InT = TypeVar("InT", bound=BaseModel)
OutT = TypeVar("OutT", bound=BaseModel)

_TASK_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_.")


class DeferReason(str, enum.Enum):
    """Why a call resolved to DEFER (recorded in metrics, never shown to users)."""

    NO_KEY = "no_key"
    FORCED_OFF = "forced_off"
    MISSING_CONFIG = "missing_config"
    UNKNOWN_TASK = "unknown_task"
    INVALID_INPUT = "invalid_input"
    CIRCUIT_OPEN = "circuit_open"
    RUN_CEILING = "run_ceiling"
    TIMEOUT = "timeout"
    TRANSPORT = "transport"
    AUTH_FAILED = "auth_failed"
    CREDITS_EXHAUSTED = "credits_exhausted"
    RATE_LIMITED = "rate_limited"
    SERVER_ERROR = "server_error"
    HTTP_STATUS = "http_status"
    OVERSIZE = "oversize"
    NON_JSON = "non_json"
    SCHEMA = "schema_fail"
    LOW_CONFIDENCE = "low_confidence"
    INTERNAL = "internal"


class _Defer:
    """The DEFER sentinel type. There is exactly one instance: :data:`DEFER`."""

    _instance: _Defer | None = None

    def __new__(cls) -> _Defer:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __bool__(self) -> bool:
        return False

    def __repr__(self) -> str:
        return "DEFER"

    def __reduce__(self) -> str:
        return "DEFER"


DEFER = _Defer()
DeferType = _Defer


@dataclass(frozen=True)
class Provenance:
    """Marks a result as JEV-assisted. ``cached`` is True when served from cache."""

    task: str
    prompt_version: str
    model: str
    cached: bool = False
    source: Literal["jev"] = "jev"


@dataclass(frozen=True)
class Verdict(Generic[OutT]):
    output: OutT
    confidence: float
    provenance: Provenance


@dataclass(frozen=True)
class JevTask(Generic[InT, OutT]):
    """One JEV decision.

    ``build_prompt`` returns ``(system, user)``. Bump ``prompt_version`` whenever
    the prompt or the output schema changes — it is part of the cache key, so a
    stale verdict can never be replayed against a new prompt.
    ``min_confidence`` may only raise the global ``JEV_MIN_CONFIDENCE`` floor.
    """

    name: str
    input_model: type[InT]
    output_model: type[OutT]
    prompt_version: str
    build_prompt: Callable[[InT], tuple[str, str]]
    min_confidence: float | None = None
    description: str = field(default="", compare=False)


class TaskSpecError(ValueError):
    """A task spec violates the contract (raised at registration, not at call)."""


_REGISTRY: dict[str, JevTask[Any, Any]] = {}


def register(task: JevTask[InT, OutT]) -> JevTask[InT, OutT]:
    """Register a task spec. Re-registering the identical spec is a no-op."""
    _validate_spec(task)
    existing = _REGISTRY.get(task.name)
    if existing is not None and existing != task:
        raise TaskSpecError(f"JEV task {task.name!r} is already registered")
    _REGISTRY[task.name] = task
    return task


def get_task(name: str) -> JevTask[Any, Any] | None:
    return _REGISTRY.get(name)


def registered_tasks() -> list[str]:
    return sorted(_REGISTRY)


def unregister(name: str) -> None:
    """Drop a task (tests only)."""
    _REGISTRY.pop(name, None)


# ---------------------------------------------------------------------------
# Spec validation
# ---------------------------------------------------------------------------
def _validate_spec(task: JevTask[Any, Any]) -> None:
    if not task.name or set(task.name) - _TASK_NAME_CHARS:
        raise TaskSpecError(f"JEV task name {task.name!r} must be [a-z0-9_.]+")
    if not task.prompt_version:
        raise TaskSpecError(f"JEV task {task.name!r} needs a prompt_version")
    if task.min_confidence is not None and not 0.0 <= task.min_confidence <= 1.0:
        raise TaskSpecError(f"JEV task {task.name!r} min_confidence must be in [0, 1]")
    for model in (task.input_model, task.output_model):
        if not (isinstance(model, type) and issubclass(model, BaseModel)):
            raise TaskSpecError(f"JEV task {task.name!r}: {model!r} is not a pydantic model")
    out = task.output_model
    if out.model_config.get("extra") != "forbid":
        raise TaskSpecError(
            f"JEV task {task.name!r}: output model must set extra='forbid'"
        )
    if not out.model_fields:
        raise TaskSpecError(f"JEV task {task.name!r}: output model has no fields")
    if "confidence" in out.model_fields:
        raise TaskSpecError(
            f"JEV task {task.name!r}: 'confidence' is the reserved envelope field"
        )
    for fname, finfo in out.model_fields.items():
        if not _bounded(finfo.annotation, finfo.metadata):
            raise TaskSpecError(
                f"JEV task {task.name!r}: output field {fname!r} is not schema-bounded "
                f"(allowed: bool, int, Enum, Literal, str/list with max_length; no floats)"
            )


def _has_max_len(metadata: list[Any]) -> bool:
    return any(isinstance(m, MaxLen) for m in metadata)


def _bounded(annotation: Any, metadata: list[Any]) -> bool:
    # Unwrap Annotated[X, ...] (nested constraints live in its metadata).
    if typing.get_origin(annotation) is typing.Annotated:
        base, *extra = typing.get_args(annotation)
        return _bounded(base, [*metadata, *_flatten_meta(extra)])
    origin = typing.get_origin(annotation)
    if annotation is bool or annotation is int:
        return True
    if annotation is float:
        return False
    if isinstance(annotation, type) and issubclass(annotation, enum.Enum):
        return True
    if origin is Literal:
        return True
    if annotation is str:
        return _has_max_len(metadata)
    # A nested object is bounded when it forbids extra keys and every one of its own
    # fields is bounded (recursive) — so "schema-bounded, no floats" holds all the
    # way down. Used for list-of-object outputs like the analyst-leads section.
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        if annotation.model_config.get("extra") != "forbid" or not annotation.model_fields:
            return False
        return all(
            _bounded(f.annotation, f.metadata) for f in annotation.model_fields.values()
        )
    if origin in (typing.Union, types.UnionType):
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        return bool(args) and all(_bounded(a, metadata) for a in args)
    if origin in (list, tuple):
        args = [a for a in typing.get_args(annotation) if a is not Ellipsis]
        return _has_max_len(metadata) and bool(args) and all(_bounded(a, []) for a in args)
    return False


def _flatten_meta(items: list[Any]) -> list[Any]:
    out: list[Any] = []
    for item in items:
        # pydantic's Field(max_length=...) inside Annotated arrives as FieldInfo.
        inner = getattr(item, "metadata", None)
        if isinstance(inner, list):
            out.extend(inner)
        else:
            out.append(item)
    return out
