"""Tests for :mod:`backend.modules.account_discovery` probe resilience.

Individual Holehe site probes raise as sites change (KeyError('found'),
AttributeError on None, etc.). The module must isolate and *attribute* those
failures rather than dumping bare exception strings into ``errors``, and a
handful of broken sites must not drag the whole module to FAILED/PARTIAL when
other probes returned real results.
"""
from __future__ import annotations

import asyncio

import backend.modules.account_discovery as ad
from backend.modules.account_discovery import _holehe_platform_name


class _FakeClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


async def _probe_true(email, client, out):
    out.append({"name": "GoodSite", "exists": True, "domain": "goodsite.com"})


async def _probe_false(email, client, out):
    out.append({"name": "NoSite", "exists": False})


async def _probe_raises_keyerror(email, client, out):
    raise KeyError("found")


async def _probe_raises_attr(email, client, out):
    raise AttributeError("'NoneType' object has no attribute 'get'")


def _patch_common(monkeypatch, funcs):
    monkeypatch.setattr(ad.settings, "enable_account_discovery", True)
    monkeypatch.setattr(ad.settings, "request_delay_ms", 0)
    monkeypatch.setattr(ad, "_read_cache", lambda email: None)
    monkeypatch.setattr(ad, "_write_cache", lambda email, result: None)
    monkeypatch.setattr(ad, "import_submodules", lambda pkg: object())
    monkeypatch.setattr(ad, "get_functions", lambda mods: funcs)
    monkeypatch.setattr(ad, "build_client", lambda **kw: _FakeClient())


def test_probe_failures_are_attributed_and_do_not_fail_the_module(monkeypatch):
    _patch_common(
        monkeypatch,
        [_probe_true, _probe_false, _probe_raises_keyerror, _probe_raises_attr],
    )

    result = asyncio.run(ad.AccountDiscoveryModule().run("a@b.com"))

    assert result.status == ad.ModuleStatus.SUCCESS
    assert len(result.findings) == 1
    joined = " ".join(result.errors)
    assert "platform probe(s) errored" in joined
    # attributed to a platform label, not a bare "'found'" / empty string
    assert "found" in joined
    assert ": " in joined


def test_total_probe_washout_is_failed(monkeypatch):
    _patch_common(monkeypatch, [_probe_raises_keyerror, _probe_raises_attr])

    result = asyncio.run(ad.AccountDiscoveryModule().run("a@b.com"))

    assert result.status == ad.ModuleStatus.FAILED
    assert result.findings == []


def test_holehe_platform_name_prefers_module_tail():
    assert _holehe_platform_name(_probe_true) == "test_account_discovery"

    class _NoModule:
        __name__ = "customsite"

    obj = _NoModule()
    obj.__module__ = ""
    assert _holehe_platform_name(obj) == "customsite"
