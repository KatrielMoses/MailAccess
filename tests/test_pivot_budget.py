from __future__ import annotations

import asyncio
import time

import pytest

from backend.config import settings
from backend.modules import username_pivot as up
from backend.modules.base import ModuleResult, ModuleStatus


def _sites():
    sites = {f"Core{i}": {"id": f"core{i}", "name": f"Core{i}", "core": True, "alexaRank": 10 + i,
                          "url": f"https://core{i}.example/{{username}}"} for i in range(6)}
    # validated non-core sites: the pivot probes these after the core, but never
    # unvalidated/flappy ones (UC4).
    sites.update({f"Tail{i}": {"id": f"tail{i}", "name": f"Tail{i}", "alexaRank": 1000 + i,
                               "validated": "2026-10-21",
                               "url": f"https://tail{i}.example/{{username}}"} for i in range(4)})
    sites["Flappy"] = {"id": "flappy", "name": "Flappy", "alexaRank": 2,
                       "url": "https://flappy.example/{username}"}  # unvalidated: never pivoted
    sites["Noisy"] = {"id": "noisy", "name": "Noisy", "alwaysHit": "2026-10-20", "alexaRank": 1}
    return sites


def _collected():
    sweep = [{"platform": "Core3", "username": "janedoe", "confidence": "medium",
              "metadata": {"core": True, "display_name": "Jane Doe", "profile_username": "JaneD",
                           "other_handles": ["x:jane_x", "linkedin:jane-doe"]}}]
    return {
        "username_platforms": ModuleResult(status=ModuleStatus.SUCCESS, findings=sweep,
                                           metadata={"username_variants": ["janedoe"]}),
        "email_search_dork": ModuleResult(status=ModuleStatus.SUCCESS, findings=[
            {"platform": "x", "username": "someoneelse"}]),
    }


def test_usernames_ranked_by_tier_and_third_parties_excluded():
    ranked = up.ranked_usernames("janedoe@example.com", _collected())
    tiers = {u: t for u, t, _ in ranked}
    assert tiers["janed"] == 1 and tiers["jane_x"] == 1  # stated on a name-matched profile
    assert tiers["janedoe"] == 2
    assert "someoneelse" not in tiers  # a dork result is someone else
    assert [t for _u, t, _o in ranked] == sorted(t for _u, t, _o in ranked)


@pytest.fixture
def probes(monkeypatch, tmp_path):
    from backend.core import probe_cache
    monkeypatch.setattr(settings, "probe_cache_path", str(tmp_path / "pc.db"), raising=False)
    probe_cache._CONN = None
    probe_cache._CONN_PATH = None
    probe_cache.set_no_cache_read(False)
    calls: list[tuple[str, str]] = []

    async def fake_load(include_wave2=False):
        return _sites(), {"sites_loaded": 11}

    async def fake_probe(client, sem, name, defn, handle, timeout=6.0):
        calls.append((name, handle))
        await asyncio.sleep(0.01)
        if (name, handle) == ("Core3", "janed"):
            return "hit", f"https://core3.example/{handle}", {}
        return "miss", None, None

    monkeypatch.setattr(up, "load_username_sites", fake_load)
    monkeypatch.setattr(up, "probe_platform", fake_probe)
    monkeypatch.setattr(settings, "enable_username_pivot", True, raising=False)
    monkeypatch.setattr(settings, "username_pivot_budget_seconds", 45.0, raising=False)
    monkeypatch.setattr(settings, "probe_cache_enabled", False, raising=False)  # no shared cache
    return calls


def test_order_skip_seen_and_found(probes):
    sink: list = []
    result = asyncio.run(up.UsernamePivotModule().run("janedoe@example.com", _collected(), sink=sink))
    assert ("Core3", "janedoe") not in probes  # swept by the primary sweep
    assert all(name != "Noisy" for name, _ in probes)  # always-hit sites never pivoted
    assert all(name != "Flappy" for name, _ in probes)  # unvalidated sites never pivoted
    first = [n for n, h in probes if h == "janed"][:1]
    assert first == ["Core3"]  # where the sweep already found the person comes first
    assert [f["platform"] for f in result.findings] == ["Core3"]
    assert sink == result.findings  # streamed as found
    tail_positions = [i for i, (n, _h) in enumerate(probes) if n.startswith("Tail")]
    core_positions = [i for i, (n, _h) in enumerate(probes) if n.startswith("Core")]
    assert max(core_positions) < min(tail_positions)  # every handle's priority sites first


def test_budget_stops_new_probes(monkeypatch, probes):
    # A budget of one probe timeout leaves no room to start a probe at all.
    monkeypatch.setattr(settings, "username_pivot_budget_seconds", 6.0, raising=False)
    t0 = time.monotonic()
    result = asyncio.run(up.UsernamePivotModule().run("janedoe@example.com", _collected()))
    assert time.monotonic() - t0 < 2.0
    assert result.metadata["stopped_by_budget"] is True and probes == []
    assert result.status == ModuleStatus.PARTIAL  # out of time is never "nothing there"
