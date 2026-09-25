"""Async OpenAI-compatible chat caller for the JEV seam.

Modeled on :mod:`backend.core.mailaccess_pro_client` (host-as-config, one total
deadline, streamed body with a size cap) with one deliberate difference: it never
raises. Every transport / HTTP / decode failure is returned as a
:class:`DeferReason` so the seam resolves it to DEFER. The API key and the
prompt/response bodies are never logged.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import httpx

from .contract import DeferReason

_LOG = logging.getLogger(__name__)

_CHAT_PATH = "/chat/completions"
# A verdict is a handful of enum/bool fields; anything near this is not one.
_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_OUTPUT_TOKENS = 256

# Test seam: an httpx transport (e.g. MockTransport) used instead of the network.
_TRANSPORT: httpx.AsyncBaseTransport | None = None


async def chat_json(
    *,
    base_url: str,
    api_key: str,
    model: str,
    system: str,
    user: str,
    timeout: float,
    task: str,
) -> dict[str, Any] | DeferReason:
    """Ask the model for one JSON object. Returns the parsed object or a reason."""
    url = base_url.rstrip("/") + _CHAT_PATH
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0,
        "max_tokens": _MAX_OUTPUT_TOKENS,
        "response_format": {"type": "json_object"},
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=timeout, transport=_TRANSPORT) as client:
            result = await asyncio.wait_for(
                _post(client, url, body, headers, task), timeout=timeout
            )
    except asyncio.TimeoutError:
        _LOG.debug("JEV call timed out (task=%s)", task)
        return DeferReason.TIMEOUT
    except (httpx.HTTPError, OSError) as exc:
        _LOG.debug("JEV transport error (task=%s): %s", task, type(exc).__name__)
        return DeferReason.TRANSPORT
    except Exception as exc:  # never let the seam raise
        _LOG.debug("JEV client internal error (task=%s): %s", task, type(exc).__name__)
        return DeferReason.INTERNAL
    return result


async def _post(
    client: httpx.AsyncClient,
    url: str,
    body: dict[str, Any],
    headers: dict[str, str],
    task: str,
) -> dict[str, Any] | DeferReason:
    async with client.stream("POST", url, json=body, headers=headers) as resp:
        chunks: list[bytes] = []
        size = 0
        async for chunk in resp.aiter_bytes():
            size += len(chunk)
            if size > _MAX_RESPONSE_BYTES:
                if resp.status_code != 200:
                    break  # an error page only needs its head for classification
                return DeferReason.OVERSIZE
            chunks.append(chunk)
        status = resp.status_code
    body = b"".join(chunks)
    if status != 200:
        reason = classify_error(status, body)
        _LOG.debug("JEV HTTP %d → %s (task=%s)", status, reason.value, task)
        return reason
    return _extract_object(body)


# Provider error vocabularies for "out of credits / quota". OpenAI-compatible
# APIs signal this as 429 insufficient_quota, 402 Payment Required, or a
# billing/credit message; matched case-insensitively on the error body.
_CREDIT_MARKERS = (
    "insufficient_quota", "quota", "credit", "billing", "payment", "balance",
    "exceeded your current", "out of tokens",
)


def classify_error(status: int, body: bytes) -> DeferReason:
    """Map a non-success response to a DeferReason the circuit breaker understands."""
    text = body[:8192].decode("utf-8", "replace").lower()
    if status == 402 or any(m in text for m in _CREDIT_MARKERS):
        return DeferReason.CREDITS_EXHAUSTED
    if status in (401, 403):
        return DeferReason.AUTH_FAILED
    if status == 429:
        return DeferReason.RATE_LIMITED
    if status >= 500:
        return DeferReason.SERVER_ERROR
    return DeferReason.HTTP_STATUS


def _extract_object(raw: bytes) -> dict[str, Any] | DeferReason:
    """Pull the JSON object out of an OpenAI-style completion envelope."""
    try:
        envelope = json.loads(raw)
        if isinstance(envelope, dict) and "error" in envelope and "choices" not in envelope:
            # Some gateways report failures (incl. exhausted credits) with HTTP 200.
            return classify_error(200, raw)
        content = envelope["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError):
        return DeferReason.NON_JSON
    if not isinstance(content, str):
        return DeferReason.NON_JSON
    text = content.strip()
    # Tolerate one surrounding ```json fence; anything else must be bare JSON.
    if text.startswith("```"):
        text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        obj = json.loads(text)
    except ValueError:
        return DeferReason.NON_JSON
    if not isinstance(obj, dict):
        return DeferReason.NON_JSON
    return obj
