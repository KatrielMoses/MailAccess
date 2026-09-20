"""0.17.0 — internal provisioning bridge (``POST /internal/pro/keys``).

The website (Next BFF) owns subscription/account/billing state and mints/rotates/
revokes Pro keys in its own account DB. But the CLI presents its key to the Python
``/v1/enrich``, which validates against THIS backend's entitlement store
(:mod:`backend.core.pro_keys`). Without a bridge a website-issued key would 401 in
the CLI. On every key change the website calls this endpoint with the key's
**SHA-256 hash** (never the raw key) so the two stores stay in sync and this store
remains the single authority for what ``/v1/enrich`` accepts.

Auth: a shared secret in ``X-Internal-Secret``, compared constant-time against
``settings.mailaccess_pro_internal_secret``. **Fail-closed:** while that secret is
empty (the default) the endpoint rejects everything, so merely mounting the route
changes nothing at runtime until a secret is deliberately configured. This is an
internal server-to-server seam — it must never be exposed publicly.
"""

from __future__ import annotations

import hmac
import logging
from datetime import datetime

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from ...config import settings
from ...core.pro_keys import (
    add_pro_key_hash,
    delete_pro_key_hash,
    set_pro_key_status_hash,
)

_LOG = logging.getLogger(__name__)

router = APIRouter()


class _KeyOp(BaseModel):
    action: str = Field(..., pattern="^(add|suspend|revoke|delete|activate)$")
    key_hash: str = Field(..., min_length=64, max_length=64)
    # ISO-8601 hard expiry (admin test keys are capped at 30 days by the website).
    expires_at: str | None = None
    notes: str | None = Field(default=None, max_length=200)


def _parse_expiry(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise HTTPException(status_code=400, detail="expires_at must be ISO-8601") from exc


def _authorized(secret_header: str | None) -> bool:
    """Constant-time secret check; fail-closed when no secret is configured."""
    configured = str(getattr(settings, "mailaccess_pro_internal_secret", "") or "")
    if not configured:
        return False
    return bool(secret_header) and hmac.compare_digest(str(secret_header), configured)


@router.post("/pro/keys")
async def pro_keys_op(
    op: _KeyOp,
    x_internal_secret: str | None = Header(default=None),
) -> dict:
    """Add or revoke an entitlement by key hash. Idempotent; hash-only."""
    if not _authorized(x_internal_secret):
        raise HTTPException(status_code=401, detail="unauthorized")
    try:
        if op.action == "add":
            created = await add_pro_key_hash(
                op.key_hash, notes=op.notes, expires_at=_parse_expiry(op.expires_at)
            )
            return {"ok": True, "action": "add", "created": created}
        if op.action == "suspend":
            changed = await set_pro_key_status_hash(op.key_hash, "suspended")
            return {"ok": True, "action": "suspend", "changed": changed}
        if op.action == "revoke":
            changed = await set_pro_key_status_hash(op.key_hash, "revoked")
            return {"ok": True, "action": "revoke", "changed": changed}
        if op.action == "activate":
            # Restore a suspended/revoked key (failed-payment recovery, admin resume).
            # Does NOT create — the key must already exist in the store.
            changed = await set_pro_key_status_hash(op.key_hash, "active")
            return {"ok": True, "action": "activate", "changed": changed}
        deleted = await delete_pro_key_hash(op.key_hash)
        return {"ok": True, "action": "delete", "deleted": deleted}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
