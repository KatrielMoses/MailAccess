"""Tests for :mod:`backend.modules.ghunt_module` credential loading.

Regression guard for the GHunt 2.x credential API.  ``ghunt`` >= 2.x loads
credentials through ``GHuntCreds(creds_path=...).load_creds()`` and writes a
base64 ``creds.m`` file.  An earlier loader called the removed
``ghunt.helpers.auth.load_creds(creds, file=...)`` and, when that raised,
fell back to ``json.loads`` on the (non-JSON) ``creds.m`` — surfacing as
``Failed to load GHunt credentials: Expecting value: line 1 column 1``.

This test pins the loader to the current GHuntCreds object API.
"""
from __future__ import annotations

import ghunt.objects.base as ghunt_base

from backend.modules.ghunt_module import _load_creds


def test_load_creds_uses_ghuntcreds_object_api(monkeypatch):
    calls: dict[str, object] = {}

    class FakeCreds:
        def __init__(self, creds_path: str = "") -> None:
            calls["creds_path"] = creds_path
            self.osids = {"session": "token"}
            self.cookies = {"SID": "x"}

        def load_creds(self, silent: bool = False) -> None:
            calls["loaded"] = True
            calls["silent"] = silent

    monkeypatch.setattr(ghunt_base, "GHuntCreds", FakeCreds)

    creds = _load_creds("/home/user/.malfrats/ghunt/creds.m")

    # It must load via the GHuntCreds object, not the removed helpers.auth path
    # and not the JSON fallback.
    assert isinstance(creds, FakeCreds)
    assert calls["creds_path"] == "/home/user/.malfrats/ghunt/creds.m"
    assert calls.get("loaded") is True
