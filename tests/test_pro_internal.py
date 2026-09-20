"""0.17.0 — the internal provisioning bridge: hash-only key sync + secret gate.

The website BFF calls POST /internal/pro/keys with a key's SHA-256 hash so the
CLI's /v1/enrich (which validates against THIS store) accepts website-issued keys.
Fail-closed: with no configured secret the route rejects everything.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.config import settings
from backend.core.pro_keys import (
    add_pro_key_hash,
    deactivate_pro_key_hash,
    delete_pro_key_hash,
    hash_key,
    set_pro_key_status_hash,
    validate_pro_key,
)
from backend.main import app


# --------------------------------------------------------------------------- #
# Store helpers (hash-only): the bridge never handles the raw key.
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_add_by_hash_then_validate_raw() -> None:
    raw = "map_bridge_add_001"
    assert await add_pro_key_hash(hash_key(raw), notes="sub_add") is True
    assert await validate_pro_key(raw) is True
    # Idempotent per hash: a second add is not "created".
    assert await add_pro_key_hash(hash_key(raw)) is False
    assert await validate_pro_key(raw) is True


@pytest.mark.asyncio
async def test_revoke_then_reactivate_by_hash() -> None:
    raw = "map_bridge_cycle_002"
    h = hash_key(raw)
    await add_pro_key_hash(h)
    assert await deactivate_pro_key_hash(h) is True
    assert await validate_pro_key(raw) is False
    # A re-provision reactivates the same hash (returns False = not newly created).
    assert await add_pro_key_hash(h) is False
    assert await validate_pro_key(raw) is True


@pytest.mark.asyncio
async def test_malformed_hash_is_rejected() -> None:
    with pytest.raises(ValueError):
        await add_pro_key_hash("not-a-valid-sha256")
    assert await deactivate_pro_key_hash("nope") is False


# --------------------------------------------------------------------------- #
# Expiry + lifecycle status — honored at validate_pro_key (the /v1/enrich gate).
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_expired_key_is_rejected() -> None:
    past = "map_bridge_expired_010"
    await add_pro_key_hash(hash_key(past), expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    assert await validate_pro_key(past) is False
    future = "map_bridge_future_011"
    await add_pro_key_hash(hash_key(future), expires_at=datetime.now(timezone.utc) + timedelta(days=30))
    assert await validate_pro_key(future) is True


@pytest.mark.asyncio
async def test_suspend_cuts_access_and_readd_restores() -> None:
    raw = "map_bridge_suspend_012"
    h = hash_key(raw)
    await add_pro_key_hash(h)
    assert await validate_pro_key(raw) is True
    assert await set_pro_key_status_hash(h, "suspended") is True
    assert await validate_pro_key(raw) is False
    # Re-provision (add) reactivates a suspended key.
    await add_pro_key_hash(h)
    assert await validate_pro_key(raw) is True


@pytest.mark.asyncio
async def test_delete_removes_key() -> None:
    raw = "map_bridge_delete_013"
    h = hash_key(raw)
    await add_pro_key_hash(h)
    assert await validate_pro_key(raw) is True
    assert await delete_pro_key_hash(h) is True
    assert await validate_pro_key(raw) is False
    # Deleting an absent row is a no-op.
    assert await delete_pro_key_hash(h) is False


def test_route_suspend_and_delete_with_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "mailaccess_pro_internal_secret", "s3cr3t")
    client = TestClient(app)
    h = hash_key("map_route_suspend_del_014")
    hdr = {"X-Internal-Secret": "s3cr3t"}
    exp = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    add = client.post("/internal/pro/keys", json={"action": "add", "key_hash": h, "expires_at": exp}, headers=hdr)
    assert add.status_code == 200 and add.json()["created"] is True
    susp = client.post("/internal/pro/keys", json={"action": "suspend", "key_hash": h}, headers=hdr)
    assert susp.status_code == 200 and susp.json()["changed"] is True
    dele = client.post("/internal/pro/keys", json={"action": "delete", "key_hash": h}, headers=hdr)
    assert dele.status_code == 200 and dele.json()["deleted"] is True


def test_route_activate_restores_suspended_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "mailaccess_pro_internal_secret", "s3cr3t")
    client = TestClient(app)
    hdr = {"X-Internal-Secret": "s3cr3t"}
    h = hash_key("map_route_activate_015")
    client.post("/internal/pro/keys", json={"action": "add", "key_hash": h}, headers=hdr)
    client.post("/internal/pro/keys", json={"action": "suspend", "key_hash": h}, headers=hdr)
    act = client.post("/internal/pro/keys", json={"action": "activate", "key_hash": h}, headers=hdr)
    assert act.status_code == 200 and act.json()["action"] == "activate" and act.json()["changed"] is True


def test_route_rejects_bad_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "mailaccess_pro_internal_secret", "s3cr3t")
    client = TestClient(app)
    r = client.post(
        "/internal/pro/keys",
        json={"action": "add", "key_hash": hash_key("z"), "expires_at": "not-a-date"},
        headers={"X-Internal-Secret": "s3cr3t"},
    )
    assert r.status_code == 400


# --------------------------------------------------------------------------- #
# Route: secret gate (fail-closed) + add/revoke.
# --------------------------------------------------------------------------- #
def test_route_fail_closed_when_no_secret_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "mailaccess_pro_internal_secret", "")
    client = TestClient(app)
    r = client.post(
        "/internal/pro/keys",
        json={"action": "add", "key_hash": hash_key("x")},
        headers={"X-Internal-Secret": "anything"},
    )
    assert r.status_code == 401


def test_route_wrong_secret_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "mailaccess_pro_internal_secret", "s3cr3t")
    client = TestClient(app)
    r = client.post(
        "/internal/pro/keys",
        json={"action": "add", "key_hash": hash_key("y")},
        headers={"X-Internal-Secret": "wrong"},
    )
    assert r.status_code == 401


def test_route_add_and_revoke_with_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "mailaccess_pro_internal_secret", "s3cr3t")
    client = TestClient(app)
    h = hash_key("map_route_cycle_777")
    add = client.post(
        "/internal/pro/keys",
        json={"action": "add", "key_hash": h, "notes": "sub_route"},
        headers={"X-Internal-Secret": "s3cr3t"},
    )
    assert add.status_code == 200 and add.json()["created"] is True
    rev = client.post(
        "/internal/pro/keys",
        json={"action": "revoke", "key_hash": h},
        headers={"X-Internal-Secret": "s3cr3t"},
    )
    assert rev.status_code == 200 and rev.json()["changed"] is True


def test_route_rejects_short_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "mailaccess_pro_internal_secret", "s3cr3t")
    client = TestClient(app)
    r = client.post(
        "/internal/pro/keys",
        json={"action": "add", "key_hash": "tooshort"},
        headers={"X-Internal-Secret": "s3cr3t"},
    )
    assert r.status_code == 422  # pydantic length gate
