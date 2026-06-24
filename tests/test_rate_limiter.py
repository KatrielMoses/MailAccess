from __future__ import annotations

import asyncio
import time

import pytest

from backend.config import settings
from backend.core.rate_limiter import DomainRateLimiter


def _configure(
    monkeypatch: pytest.MonkeyPatch,
    *,
    enabled: bool = True,
    delay_ms: int = 30,
    delays: dict[str, float] | None = None,
    overrides: dict[str, int] | None = None,
) -> None:
    monkeypatch.setattr(settings, "rate_limit_enabled", enabled)
    monkeypatch.setattr(settings, "request_delay_ms", delay_ms)
    monkeypatch.setattr(settings, "rate_limit_delays", delays or {})
    monkeypatch.setattr(settings, "rate_limit_overrides", overrides or {})


async def test_acquire_disabled_returns_immediately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch, enabled=False, delay_ms=10_000)
    limiter = DomainRateLimiter()

    await asyncio.wait_for(limiter.acquire("x.com"), timeout=0.05)


async def test_concurrent_acquire_same_domain_serialized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch, delay_ms=30)
    limiter = DomainRateLimiter()
    started = time.monotonic()

    await asyncio.gather(limiter.acquire("x.com"), limiter.acquire("x.com"))

    assert time.monotonic() - started >= 0.02


async def test_acquire_different_domains_dont_block_each_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch, delay_ms=30)
    limiter = DomainRateLimiter()

    await asyncio.wait_for(
        asyncio.gather(limiter.acquire("a.com"), limiter.acquire("b.com")),
        timeout=0.02,
    )


def test_set_delay_overrides_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch)
    limiter = DomainRateLimiter()

    limiter.set_delay("x.com", 0.5)

    assert limiter.get_delay("x.com") == 0.5


def test_get_delay_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, delay_ms=40)

    assert DomainRateLimiter().get_delay("unknown.example") == 0.04


def test_rate_limit_overrides_win_over_delays(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(
        monkeypatch,
        delays={"x.com": 2.0},
        overrides={"x.com": 125},
    )

    assert DomainRateLimiter().get_delay("x.com") == 0.125


async def test_acquire_zero_delay_returns_immediately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch, delay_ms=0)

    await asyncio.wait_for(DomainRateLimiter().acquire("x.com"), timeout=0.02)
