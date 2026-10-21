"""UC2.1: extended registration checks (default_off) are opt-in, off by default."""

from __future__ import annotations

import pytest

from backend.config import settings
from backend.core.account_probe_ported import _site


def _probeable(sites, *, extended, intrusive=False):
    """Mirror account_discovery's probeable filter."""
    return [
        d for d in sites
        if d.get("check_type") == "email-existence"
        and not d.get("disabled")
        and (intrusive or not d.get("intrusive"))
        and (extended or not d.get("default_off"))
    ]


SITES = [
    _site("builtin_one", "a.example", "x", "login", {"url": "https://a.example"}),
    _site("builtin_two", "b.example", "x", "login", {"url": "https://b.example"}),
    _site("extended_one", "c.example", "x", "login", {"url": "https://c.example"}, default_off=True),
    _site("extended_two", "d.example", "x", "login", {"url": "https://d.example"}, default_off=True),
]


def test_site_default_off_flag():
    assert "default_off" not in _site("z", "z.example", "x", "login", {})  # absent by default
    assert _site("y", "y.example", "x", "login", {}, default_off=True)["default_off"] is True


def test_default_off_excluded_when_setting_false():
    ids = {d["id"] for d in _probeable(SITES, extended=False)}
    assert ids == {"builtin_one", "builtin_two"}  # the two extended ones are excluded


def test_default_off_included_when_setting_true():
    ids = {d["id"] for d in _probeable(SITES, extended=True)}
    assert ids == {"builtin_one", "builtin_two", "extended_one", "extended_two"}


def test_existing_defs_unaffected_either_way():
    builtins = [d for d in SITES if not d.get("default_off")]
    for extended in (True, False):
        got = {d["id"] for d in _probeable(SITES, extended=extended)}
        assert {b["id"] for b in builtins} <= got  # built-ins always present


def test_setting_defaults_off():
    assert settings.enable_extended_registration_checks is False


def test_catalogue_default_off_sites_are_email_existence():
    # Every default_off def in the real catalogue is a non-intrusive email-existence check.
    from backend.core.account_probe_ported import ported_sites

    for d in ported_sites().values():
        if d.get("default_off"):
            assert d.get("check_type") == "email-existence"
            assert not d.get("intrusive"), f"{d['id']} is default_off AND intrusive"
