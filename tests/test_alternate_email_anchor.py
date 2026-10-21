"""UC7.3a: alternate-email recursive anchoring (bounded, depth 1). Only Class-1-sourced
alternates are followed; the re-anchored accounts merge under one person as Class-1.
Synthetic fixtures; account_discovery is mocked (no network)."""

from __future__ import annotations

import asyncio

import pytest

from backend.modules import alternate_email_anchor as anchor_mod
from backend.modules.alternate_email_anchor import (
    AlternateEmailAnchorModule,
    class1_alt_emails,
)
from backend.modules.base import ModuleResult, ModuleStatus


def _alt(discovered, source):
    return {"platform": "alternate_email",
            "metadata": {"discovered_email": discovered, "sources": [source]}}


def _collected(*alts):
    return {"alternate_email": ModuleResult(status=ModuleStatus.SUCCESS, findings=list(alts))}


def test_only_class1_alternates_selected_and_capped():
    collected = _collected(
        _alt("a@proton.me", "breach_record"),       # Class-1
        _alt("b@gmail.com", "gravatar_profile"),     # Class-1
        _alt("c@guess.test", "permutation"),         # Class-2 guess → excluded
        _alt("d@mail.test", "github_commits"),       # Class-1, but over the cap of 2
    )
    got = class1_alt_emails("subject@acme.test", collected)
    assert got == ["a@proton.me", "b@gmail.com"]     # permutation dropped, capped at 2


def test_primary_is_never_reanchored():
    collected = _collected(_alt("subject@acme.test", "breach_record"))
    assert class1_alt_emails("subject@acme.test", collected) == []


def test_reanchored_accounts_are_class1_and_tagged(monkeypatch):
    async def fake_run(self, email):
        return ModuleResult(status=ModuleStatus.SUCCESS, findings=[
            {"platform": "Duolingo", "username": None, "confidence": "medium",
             "metadata": {"flow": "register"}}])

    import backend.modules.account_discovery as ad
    monkeypatch.setattr(ad.AccountDiscoveryModule, "run", fake_run)

    collected = _collected(_alt("alt@proton.me", "breach_record"))
    res = asyncio.run(AlternateEmailAnchorModule().run("subject@acme.test", collected))
    assert res.metadata["anchor_count"] == 1
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f["metadata"]["anchor_email"] == "alt@proton.me"
    assert f["email_linked"] is True
    # Class-1 registration signal preserved so the card counts it on the spine
    assert f["trace"]["signal_type"] in ("email_registration_check", "signin_or_reset_probe")


def test_no_class1_alternates_is_a_noop(monkeypatch):
    called = {"n": 0}

    async def fake_run(self, email):
        called["n"] += 1
        return ModuleResult(status=ModuleStatus.SUCCESS, findings=[])

    import backend.modules.account_discovery as ad
    monkeypatch.setattr(ad.AccountDiscoveryModule, "run", fake_run)

    collected = _collected(_alt("c@guess.test", "permutation"))  # Class-2 only
    res = asyncio.run(AlternateEmailAnchorModule().run("subject@acme.test", collected))
    assert res.findings == [] and called["n"] == 0  # account_discovery never invoked
