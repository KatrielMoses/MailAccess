"""S2 / R11 — a blocked or all-unknown sweep is never a successful all-negative.

An account-existence sweep that was entirely rate-limited (429) or entirely
inconclusive produced NO answer. It must not report ``SUCCESS``/``SUCCESS_EMPTY``
(which downstream reads as "checked, found nothing"), and it must not be cached
(so the next run actually re-probes rather than serving a fabricated negative).

Network-free: the probe layer is mocked.
"""
from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import backend.modules.account_discovery as AD
from backend.modules.base import ModuleStatus


@pytest.fixture
def tmp_path() -> Iterator[Path]:
    # pytest's own tmp_path fixture hits a Windows ACL bug on this machine's
    # shared Temp dir; mkdtemp avoids it (matches the other suites' pattern).
    path = Path(tempfile.mkdtemp(prefix="acctdisc-r11-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _setup(monkeypatch: pytest.MonkeyPatch, tmp_path: Any, probe: Any, n: int = 3) -> None:
    monkeypatch.setattr(AD.settings, "enable_account_discovery", True, raising=False)
    monkeypatch.setattr(AD, "_CACHE_DIR", tmp_path)
    # UC7.4: zero the retry backoff/jitter so the retry-path tests don't sleep for real.
    monkeypatch.setattr(AD, "_RETRY_BACKOFFS_S", (0.0, 0.0), raising=True)
    monkeypatch.setattr(AD, "_RETRY_JITTER_S", 0.0, raising=True)
    sites = {
        f"site{i}": {"name": f"site{i}", "id": f"site{i}",
                     "check_type": "email-existence", "domain": f"site{i}.com"}
        for i in range(n)
    }
    monkeypatch.setattr(
        AD, "load_mailaccess_sites", lambda: (sites, {"source": "test", "site_count": n})
    )
    monkeypatch.setattr(AD, "default_health_key", lambda defn: defn["name"])

    def _no_health() -> Any:
        raise RuntimeError("health disabled for test")

    monkeypatch.setattr(AD, "get_health_db", _no_health)
    monkeypatch.setattr(AD, "probe_site", probe)


def _rec(defn: dict, *, exists: Any, rate: bool = False) -> dict:
    return {"name": defn["name"], "exists": exists, "rateLimit": rate, "domain": defn["domain"]}


async def test_all_rate_limited_is_not_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    async def probe(client: Any, sem: Any, defn: dict, email: str, **kw: Any) -> dict:
        return _rec(defn, exists=None, rate=True)

    _setup(monkeypatch, tmp_path, probe)
    result = await AD.AccountDiscoveryModule().run("jane@corp.com")

    assert result.status == ModuleStatus.PARTIAL
    assert result.status not in (ModuleStatus.SUCCESS, ModuleStatus.SUCCESS_EMPTY)
    assert result.metadata["coverage_complete"] is False
    assert result.metadata["platforms_confirmed"] == 0
    assert result.metadata["platforms_not_found"] == 0
    assert result.metadata["platforms_rate_limited"] == 3
    # A blocked sweep must NOT be cached.
    assert list(tmp_path.glob("*.json")) == []


async def test_all_inconclusive_is_not_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    async def probe(client: Any, sem: Any, defn: dict, email: str, **kw: Any) -> dict:
        return _rec(defn, exists=None, rate=False)

    _setup(monkeypatch, tmp_path, probe)
    result = await AD.AccountDiscoveryModule().run("jane@corp.com")
    assert result.status == ModuleStatus.PARTIAL
    assert result.metadata["platforms_inconclusive"] == 3
    assert result.metadata["coverage_complete"] is False
    assert list(tmp_path.glob("*.json")) == []


async def test_all_miss_is_success_empty_and_cached(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    async def probe(client: Any, sem: Any, defn: dict, email: str, **kw: Any) -> dict:
        return _rec(defn, exists=False)

    _setup(monkeypatch, tmp_path, probe)
    result = await AD.AccountDiscoveryModule().run("jane@corp.com")
    assert result.status == ModuleStatus.SUCCESS_EMPTY  # honest all-negative
    assert result.metadata["coverage_complete"] is True
    assert result.metadata["platforms_not_found"] == 3
    assert list(tmp_path.glob("*.json"))  # cached (definitive coverage)


async def test_mixed_hit_and_block_is_partial(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    async def probe(client: Any, sem: Any, defn: dict, email: str, **kw: Any) -> dict:
        if defn["name"] == "site0":
            return _rec(defn, exists=True)
        return _rec(defn, exists=None, rate=True)

    _setup(monkeypatch, tmp_path, probe)
    result = await AD.AccountDiscoveryModule().run("jane@corp.com")
    assert result.status == ModuleStatus.PARTIAL  # found one, but coverage incomplete
    assert result.metadata["platforms_confirmed"] == 1
    assert result.metadata["coverage_complete"] is False


async def test_full_hits_is_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    async def probe(client: Any, sem: Any, defn: dict, email: str, **kw: Any) -> dict:
        return _rec(defn, exists=True)

    _setup(monkeypatch, tmp_path, probe)
    result = await AD.AccountDiscoveryModule().run("jane@corp.com")
    assert result.status == ModuleStatus.SUCCESS
    assert result.metadata["coverage_complete"] is True


async def test_blocked_sweep_reprobes_on_next_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    calls = {"n": 0}

    async def probe(client: Any, sem: Any, defn: dict, email: str, **kw: Any) -> dict:
        calls["n"] += 1
        return _rec(defn, exists=None, rate=True)

    monkeypatch.setattr(AD, "_RETRY_BACKOFFS_S", (0.0, 0.0), raising=True)  # fast test
    monkeypatch.setattr(AD, "_RETRY_JITTER_S", 0.0, raising=True)
    _setup(monkeypatch, tmp_path, probe)
    await AD.AccountDiscoveryModule().run("jane@corp.com")
    first = calls["n"]
    # UC7.4: a rate-limited check gets up to 2 retries, so 3 defns => 9 probes (the mock
    # stays rate-limited, so the retries don't clear it here).
    assert first == 9
    # Second run must actually probe again (nothing cached from the blocked sweep).
    await AD.AccountDiscoveryModule().run("jane@corp.com")
    assert calls["n"] == first + 9


async def test_transient_rate_limit_recovered_by_retry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """UC7.2: a check that is rate-limited on the first attempt but succeeds on the
    bounded retry becomes a real hit, not a dropped unknown."""
    seen: dict[str, int] = {}

    async def probe(client: Any, sem: Any, defn: dict, email: str, **kw: Any) -> dict:
        key = defn.get("name") or defn.get("domain") or id(defn)
        seen[key] = seen.get(key, 0) + 1
        if seen[key] == 1:
            return _rec(defn, exists=None, rate=True)   # first attempt: throttled
        return _rec(defn, exists=True)                   # retry: clears, real hit

    monkeypatch.setattr(AD, "_RETRY_BACKOFFS_S", (0.0, 0.0), raising=True)
    monkeypatch.setattr(AD, "_RETRY_JITTER_S", 0.0, raising=True)
    _setup(monkeypatch, tmp_path, probe)
    result = await AD.AccountDiscoveryModule().run("jane@corp.com")
    assert len(result.findings) == 3                     # all three recovered on retry
    assert not result.metadata.get("rate_limited")


async def test_retry_deadline_bounds_the_pool(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """UC7.4: with the per-run retry pool exhausted, no retries fire — the check stays
    unknown rather than ballooning the run."""
    calls = {"n": 0}

    async def probe(client: Any, sem: Any, defn: dict, email: str, **kw: Any) -> dict:
        calls["n"] += 1
        return _rec(defn, exists=None, rate=True)

    monkeypatch.setattr(AD, "_MAX_RETRY_WALL_S", 0.0, raising=True)  # pool already spent
    _setup(monkeypatch, tmp_path, probe)
    await AD.AccountDiscoveryModule().run("jane@corp.com")
    assert calls["n"] == 3  # one attempt per defn, no retries


def test_retry_after_parser():
    """UC7.4: Retry-After delta-seconds and HTTP-date parse to a bounded seconds value."""
    from backend.core.account_probe_ported import _retry_after_seconds

    class _Resp:
        def __init__(self, v):
            self.headers = {"retry-after": v} if v is not None else {}

    assert _retry_after_seconds(_Resp("5")) == 5.0
    assert _retry_after_seconds(_Resp("99999")) == 60.0        # capped
    assert _retry_after_seconds(_Resp("not-a-number")) is None
    assert _retry_after_seconds(_Resp(None)) is None
