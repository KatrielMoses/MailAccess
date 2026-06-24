from __future__ import annotations

import asyncio
import html
import json
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

import httpx

from .platform_health import get_health_db

_ENDPOINT_PATTERNS = (
    "https://{domain}/forgot-password",
    "https://{domain}/account/forgot",
    "https://{domain}/users/password/new",
    "https://{domain}/auth/forgot-password",
    "https://{domain}/reset-password",
    "https://{domain}/account/reset",
    "https://{domain}/api/auth/forgot-password",
    "https://{domain}/api/v1/auth/forgot-password",
    "https://accounts.{domain}/forgot-password",
)

_SUCCESS_SIGNALS = (
    "check your email",
    "reset link sent",
    "if an account exists",
    "email has been sent",
    "password reset",
    "we sent",
)

_FAILURE_SIGNALS = (
    "not found",
    "no account",
    "doesn't exist",
    "does not exist",
    "not registered",
    "invalid email",
    "no user found",
    "account not found",
)

_BLOCKED_STATUSES = {403, 429}
_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
_SIGNAL_CORPUS_PATH = Path(__file__).resolve().parents[2] / "data" / "reset_signals.json"
_SIGNAL_CORPUS: dict[str, dict[str, list[str]]] | None = None


def _english_signal_defaults() -> dict[str, dict[str, list[str]]]:
    return {
        "EN": {
            "success": list(_SUCCESS_SIGNALS),
            "failure": list(_FAILURE_SIGNALS),
        }
    }


def _load_signal_corpus() -> dict[str, dict[str, list[str]]]:
    global _SIGNAL_CORPUS

    if _SIGNAL_CORPUS is not None:
        return _SIGNAL_CORPUS

    try:
        loaded = json.loads(_SIGNAL_CORPUS_PATH.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError("reset signal corpus must be an object")
        corpus: dict[str, dict[str, list[str]]] = {}
        for language, signals in loaded.items():
            if not isinstance(language, str) or not isinstance(signals, dict):
                raise ValueError("invalid reset signal language entry")
            success = signals.get("success")
            failure = signals.get("failure")
            if not isinstance(success, list) or not all(isinstance(item, str) for item in success):
                raise ValueError("invalid reset success signals")
            if not isinstance(failure, list) or not all(isinstance(item, str) for item in failure):
                raise ValueError("invalid reset failure signals")
            corpus[language.upper()] = {"success": success, "failure": failure}
        if "EN" not in corpus:
            raise ValueError("reset signal corpus is missing English defaults")
        _SIGNAL_CORPUS = corpus
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        _SIGNAL_CORPUS = _english_signal_defaults()
    return _SIGNAL_CORPUS


def detect_language(text: str) -> str:
    ranges = (
        ("RU", "\u0400", "\u04ff"),
        ("ZH", "\u4e00", "\u9fff"),
        ("JA", "\u3040", "\u30ff"),
        ("KO", "\uac00", "\ud7af"),
        ("AR", "\u0600", "\u06ff"),
        ("HI", "\u0900", "\u097f"),
    )
    for language, start, end in ranges:
        if any(start <= character <= end for character in text):
            return language
    return "EN"


@dataclass(frozen=True)
class _ProbeResult:
    value: bool | None
    blocked: bool = False
    responded: bool = False


class _ProbeLanguage:
    def __init__(self) -> None:
        self.hint: str | None = None
        self._lock = asyncio.Lock()

    async def classify(self, text: str) -> bool | None:
        async with self._lock:
            if self.hint is None:
                self.hint = detect_language(text)
        return _classify_text(text, self.hint)


def _classify_text(text: str, language_hint: str = "EN") -> bool | None:
    decoded = urllib.parse.unquote_plus(html.unescape(text))
    lowered = decoded.lower()
    corpus = _load_signal_corpus()
    signals = corpus.get(language_hint.upper(), corpus["EN"])
    if any(signal.lower() in lowered for signal in signals["success"]):
        return True
    if any(signal.lower() in lowered for signal in signals["failure"]):
        return False
    return None


async def _post_json(
    url: str, email: str, client: httpx.AsyncClient, language: _ProbeLanguage
) -> _ProbeResult:
    try:
        resp = await client.post(
            url,
            json={"email": email},
            headers={**_DEFAULT_HEADERS, "Accept": "application/json"},
            timeout=6.0,
        )
    except (httpx.TimeoutException, httpx.RequestError):
        return _ProbeResult(None)
    classification = await language.classify(resp.text)
    if resp.status_code in _BLOCKED_STATUSES:
        return _ProbeResult(None, blocked=True, responded=True)
    return _ProbeResult(classification, responded=True)


async def _post_form(
    url: str, email: str, client: httpx.AsyncClient, language: _ProbeLanguage
) -> _ProbeResult:
    try:
        resp = await client.post(
            url,
            data={"email": email},
            headers={
                **_DEFAULT_HEADERS,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=6.0,
        )
    except (httpx.TimeoutException, httpx.RequestError):
        return _ProbeResult(None)
    classification = await language.classify(resp.text)
    if resp.status_code in _BLOCKED_STATUSES:
        return _ProbeResult(None, blocked=True, responded=True)
    return _ProbeResult(classification, responded=True)


async def _probe_endpoint(
    url: str, email: str, client: httpx.AsyncClient, language: _ProbeLanguage
) -> _ProbeResult:
    async def _attempt() -> _ProbeResult:
        json_result = await _post_json(url, email, client, language)
        if json_result.value is not None or json_result.blocked:
            return json_result
        form_result = await _post_form(url, email, client, language)
        if form_result.value is not None or form_result.blocked:
            return form_result
        return _ProbeResult(
            None,
            blocked=json_result.blocked or form_result.blocked,
            responded=json_result.responded or form_result.responded,
        )

    try:
        return await asyncio.wait_for(_attempt(), timeout=6.0)
    except asyncio.TimeoutError:
        return _ProbeResult(None)


async def probe(domain: str, email: str, client: httpx.AsyncClient) -> bool | None:
    """
    Return True when reset flow implies an account, False when it denies one,
    or None when the domain is blocked, absent, or inconclusive.
    """
    clean_domain = domain.strip().lower().removeprefix("www.")
    health_key = f"reset_prober:{clean_domain}"

    try:
        health = get_health_db()
        if not await health.should_probe_async(health_key):
            return None
    except Exception:
        health = None

    urls = [pattern.format(domain=clean_domain) for pattern in _ENDPOINT_PATTERNS]
    language = _ProbeLanguage()

    async def _timed_endpoint(url: str) -> tuple[_ProbeResult, int]:
        t0 = time.perf_counter()
        result = await _probe_endpoint(url, email, client, language)
        return result, int((time.perf_counter() - t0) * 1000)

    tasks = [asyncio.create_task(_timed_endpoint(url)) for url in urls]
    blocked = 0
    responded = 0
    try:
        for task in asyncio.as_completed(tasks):
            result, latency_ms = await task
            if health is not None:
                outcome = (
                    "hit" if result.value is True
                    else "miss" if result.value is False
                    else "inconclusive"
                )
                try:
                    await health.record_probe_async(
                        platform=health_key,
                        domain=clean_domain,
                        outcome=outcome,
                        latency_ms=latency_ms,
                        content_length=0,
                    )
                except Exception:
                    pass
            if result.responded:
                responded += 1
            if result.blocked:
                blocked += 1
            if result.value is not None:
                for pending in tasks:
                    if not pending.done():
                        pending.cancel()
                return result.value
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    if responded and blocked == responded:
        return None
    return None
