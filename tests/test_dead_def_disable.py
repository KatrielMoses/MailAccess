"""UC7.4: a stale def is disabled (kept for documentation, never probed); a def merely
blocked from a datacenter IP stays enabled (it works on prod)."""

from __future__ import annotations

from backend.core.account_probe_ported import _site, ported_sites

# Confirmed dead everywhere (NXDOMAIN / 404 / parked), 2026-10-22.
_DISABLED = {"blip", "nike", "deliveroo", "badeggsonline", "chinaphonearena",
             "cpahero", "cracked_to", "nattyornot"}
# Reachable from a non-datacenter IP → datacenter block, left enabled.
_KEPT = {"teamleader", "venmo"}


def _probeable(sites):
    return {d["id"] for d in sites.values()
            if d.get("check_type") == "email-existence" and not d.get("disabled")}


def test_site_disabled_flag():
    assert "disabled" not in _site("z", "z.test", "x", "login", {})           # absent by default
    assert _site("y", "y.test", "x", "login", {}, disabled=True)["disabled"] is True


def test_dead_defs_disabled_and_excluded():
    sites = ported_sites()
    probeable = _probeable(sites)
    for sid in _DISABLED:
        assert sites[sid].get("disabled") is True, f"{sid} should be disabled"
        assert sid not in probeable, f"{sid} must not be probed"


def test_datacenter_blocked_defs_kept_enabled():
    sites = ported_sites()
    probeable = _probeable(sites)
    for sid in _KEPT:
        assert not sites[sid].get("disabled"), f"{sid} is a datacenter block, keep it enabled"
        assert sid in probeable, f"{sid} must still be probed (works on prod)"


def test_disabled_defs_still_catalogued():
    # disabled = documented, not deleted — the loader retains them.
    sites = ported_sites()
    for sid in _DISABLED:
        assert sid in sites
