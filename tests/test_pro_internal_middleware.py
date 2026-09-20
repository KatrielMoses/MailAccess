"""Regression coverage for the private Pro entitlement bridge at the API edge."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.middleware.auth import APIKeyMiddleware


def test_internal_provisioning_route_reaches_its_own_auth(monkeypatch):
    """A mesh bridge request must not be rejected by self-host API-key auth."""
    app = FastAPI()
    app.add_middleware(APIKeyMiddleware)

    @app.post("/internal/pro/keys")
    async def provisioning_bridge():
        return {"reached": True}

    monkeypatch.setattr("backend.config.settings.mailaccess_api_key", "")
    response = TestClient(app).post("/internal/pro/keys", json={})

    assert response.status_code == 200
    assert response.json() == {"reached": True}
