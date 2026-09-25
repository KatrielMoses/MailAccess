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
        if resp.status_code != 200:
            _LOG.debug("JEV HTTP %d (task=%s)", resp.status_code, task)
            return DeferReason.HTTP_STATUS
        chunks: list[bytes] = []
        size = 0
        async for chunk in resp.aiter_bytes():
            size += len(chunk)
            if size > _MAX_RESPONSE_BYTES:
                return DeferReason.OVERSIZE
            chunks.append(chunk)
    return _extract_object(b"".join(chunks))


def _extract_object(raw: bytes) -> dict[str, Any] | DeferReason:
    """Pull the JSON object out of an OpenAI-style completion envelope."""
    try:
        envelope = json.loads(raw)
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
