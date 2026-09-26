"""``await judge(task_name, payload) -> Verdict | DEFER`` — the one JEV entry point.

Guard order (each resolves to DEFER and the caller runs today's logic):

  no provider → forced off → not enabled → unknown task → missing config → invalid
  input → circuit open → cache hit (served, still floor-gated) → run ceiling spent →
  concurrency slot / per-call timeout → provider error (unreachable / auth / credits
  / model-not-loaded / …) → non-JSON → schema failure → confidence below floor.

The provider/enabled checks are first and touch nothing else, so with the reasoner
off (the default) the seam performs no I/O at all. ``judge`` never raises except for
caller cancellation.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import math
import time
from typing import Any

from pydantic import BaseModel, ValidationError

from ... import config as _config
from . import adapters, breaker, cache, limits, metrics
from .contract import DEFER, DeferReason, DeferType, JevTask, Provenance, Verdict, get_task

_LOG = logging.getLogger(__name__)

# Version of the seam-owned output contract appended to every system prompt. Part
# of the cache key alongside the task's own prompt_version.
_CONTRACT_VERSION = "c1"
# Below this much run-ceiling headroom a call is not worth starting.
_MIN_CALL_SECONDS = 0.05
# Outcomes where the reasoner is inactive: nothing (not even a metrics file) is written.
_INERT_REASONS = frozenset({
    DeferReason.NO_PROVIDER.value,
    DeferReason.NOT_ENABLED.value,
    DeferReason.FORCED_OFF.value,
})


def is_active() -> bool:
    """Whether the reasoner may be consulted: a provider profile is configured AND
    enabled AND not forced off.

    The same condition :func:`judge` checks first — exposed so a call site can skip
    building payloads entirely when the reasoner is off.
    """
    s = _config.settings
    if s.jev_force_off or not adapters.is_enabled(s):
        return False
    profile = adapters.resolve_profile(s)
    return profile is not None and profile.config_ok()


async def judge(task_name: str, payload: BaseModel | dict[str, Any]) -> Verdict[Any] | DeferType:
    start = time.monotonic()
    cache_hit = model_called = False
    try:
        outcome, cache_hit, model_called = await _judge(task_name, payload)
    except Exception as exc:  # the seam must never break its caller
        _LOG.debug("JEV internal error (task=%s): %s", task_name, type(exc).__name__)
        outcome = DeferReason.INTERNAL
    reason = outcome.value if isinstance(outcome, DeferReason) else None
    metrics.record(
        task_name,
        latency_ms=(time.monotonic() - start) * 1000.0,
        defer_reason=reason,
        cache_hit=cache_hit,
        model_called=model_called,
    )
    if reason not in _INERT_REASONS:
        metrics.persist(str(getattr(_config.settings, "jev_metrics_dir", "") or ""))
    return DEFER if isinstance(outcome, DeferReason) else outcome


async def _judge(
    task_name: str, payload: BaseModel | dict[str, Any]
) -> tuple[Verdict[Any] | DeferReason, bool, bool]:
    s = _config.settings
    profile = adapters.resolve_profile(s)
    if profile is None:
        return DeferReason.NO_PROVIDER, False, False
    if s.jev_force_off:
        return DeferReason.FORCED_OFF, False, False
    if not adapters.is_enabled(s):
        return DeferReason.NOT_ENABLED, False, False
    task = get_task(task_name)
    if task is None:
        return DeferReason.UNKNOWN_TASK, False, False
    if not profile.config_ok():
        return DeferReason.MISSING_CONFIG, False, False
    inp = _coerce_input(task, payload)
    if inp is None:
        return DeferReason.INVALID_INPUT, False, False
    ident = breaker.identity(profile.identity_material, "")
    cooldown = float(s.jev_breaker_cooldown_seconds)
    if breaker.blocked(ident, cooldown):
        return DeferReason.CIRCUIT_OPEN, False, False

    floor = max(float(s.jev_min_confidence), float(task.min_confidence or 0.0))
    # The provider is part of the cache key: a chat and an Ollaya verdict for the
    # same task/payload are not interchangeable, and Ollaya's tag carries the
    # questions-spec version so a spec change invalidates cleanly.
    version = f"{task.prompt_version}+{_CONTRACT_VERSION}+{adapters.provider_cache_tag(profile)}"
    provenance = Provenance(task=task.name, prompt_version=task.prompt_version, model=profile.model)
    root = cache.cache_dir(s.jev_cache_path)
    key = cache.cache_key(
        task.name, cache.normalize_payload(inp.model_dump(mode="json")), profile.model, version
    )

    if not s.jev_cache_refresh:
        hit = cache.read(root, task.name, key, int(s.jev_cache_ttl_seconds))
        if hit is not None:
            parsed = _parse_output(task, {**hit["output"], "confidence": hit["confidence"]})
            if not isinstance(parsed, DeferReason):  # a stale-shape entry is just a miss
                output, confidence = parsed
                if confidence < floor:
                    return DeferReason.LOW_CONFIDENCE, True, False
                cached = dataclasses.replace(provenance, cached=True)
                return Verdict(output, confidence, cached), True, False

    timeout = max(0.0, s.jev_timeout_ms / 1000.0)
    scope = limits.current_scope()
    if scope is not None:
        remaining = scope.remaining()
        if remaining <= _MIN_CALL_SECONDS:
            return DeferReason.RUN_CEILING, False, False
        timeout = min(timeout, remaining)

    system, user = task.build_prompt(inp)
    system = f"{system}\n\n{_contract_footer(task)}"

    t0 = time.monotonic()
    sem = limits.semaphore(s.jev_max_concurrency)
    try:
        try:
            await asyncio.wait_for(sem.acquire(), timeout=timeout)
        except asyncio.TimeoutError:
            return DeferReason.TIMEOUT, False, False
        try:
            left = timeout - (time.monotonic() - t0)
            if left <= 0:
                return DeferReason.TIMEOUT, False, False
            if not breaker.acquire(ident, cooldown):
                return DeferReason.CIRCUIT_OPEN, False, False
            try:
                result = await adapters.run(
                    profile, task, inp, system=system, user=user, timeout=left,
                )
            except BaseException:  # cancelled mid-request: free a half-open probe
                breaker.release_probe(ident)
                raise
            breaker.record(
                ident,
                result if isinstance(result, DeferReason) else None,
                int(s.jev_breaker_failure_threshold),
            )
        finally:
            sem.release()
    finally:
        if scope is not None:
            scope.charge(time.monotonic() - t0)

    if isinstance(result, DeferReason):
        return result, False, True
    parsed = _parse_output(task, result)
    if isinstance(parsed, DeferReason):
        return parsed, False, True
    output, confidence = parsed
    cache.write(
        root,
        task.name,
        key,
        output=output.model_dump(mode="json"),
        confidence=confidence,
        model=profile.model,
        prompt_version=version,
    )
    if confidence < floor:
        return DeferReason.LOW_CONFIDENCE, False, True
    return Verdict(output, confidence, provenance), False, True


def _coerce_input(task: JevTask[Any, Any], payload: Any) -> BaseModel | None:
    if isinstance(payload, task.input_model):
        return payload
    if isinstance(payload, BaseModel):
        payload = payload.model_dump()
    if not isinstance(payload, dict):
        return None
    try:
        return task.input_model.model_validate(payload)
    except ValidationError:
        return None


def _parse_output(
    task: JevTask[Any, Any], obj: dict[str, Any]
) -> tuple[BaseModel, float] | DeferReason:
    obj = dict(obj)
    confidence = obj.pop("confidence", None)
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, int | float)
        or not math.isfinite(confidence)
        or not 0.0 <= confidence <= 1.0
    ):
        return DeferReason.SCHEMA
    try:
        # Strict JSON-mode validation: no "true"→True or "1"→1 coercion, while
        # Enum fields still accept their JSON string values.
        output = task.output_model.model_validate_json(json.dumps(obj), strict=True)
    except ValidationError:
        return DeferReason.SCHEMA
    return output, float(confidence)


def _contract_footer(task: JevTask[Any, Any]) -> str:
    schema = task.output_model.model_json_schema()
    schema.setdefault("properties", {})["confidence"] = {
        "type": "number", "minimum": 0, "maximum": 1,
    }
    schema.setdefault("required", []).append("confidence")
    return (
        "Respond with ONE JSON object and nothing else — no prose, no markdown. "
        "It must validate against this JSON Schema (no extra keys). `confidence` is "
        "your calibrated probability (0-1) that the answer is correct; if unsure, "
        "give a low confidence rather than guessing.\n"
        + json.dumps(schema, sort_keys=True, separators=(",", ":"))
    )
