from __future__ import annotations

import json

import pytest

from backend.modules.subdomain_surface import SubdomainSurfaceModule


class Response:
    status_code = 200

    def __init__(self, text: str):
        self.text = text


class Fetch:
    async def get(self, url: str):
        return Response("Contact: security@acme.org")


@pytest.mark.asyncio
async def test_subdomain_surface_filters_hosts_and_emails(monkeypatch):
    async def crtsh(*args):
        return {"www.acme.org", "evil.example.net"}

    async def certspotter(*args):
        return {"www.acme.org", "docs.acme.org"}

    monkeypatch.setattr("backend.modules.subdomain_surface.collect_crtsh", crtsh)
    monkeypatch.setattr("backend.modules.subdomain_surface.collect_certspotter", certspotter)
    monkeypatch.setattr("backend.modules.subdomain_surface.settings.enable_subdomain_surface", True)
    monkeypatch.setattr("backend.modules.subdomain_surface.settings.subdomain_surface_max_hosts", 8)

    result = await SubdomainSurfaceModule().run("acme.org", fetch=Fetch())
    assert result.metadata["subdomains_found"] == 2
    assert {x["metadata"]["email"] for x in result.findings} == {"security@acme.org"}
    assert {x["metadata"]["subdomain"] for x in result.findings} == {"www.acme.org", "docs.acme.org"}
    assert all("evil.example.net" not in x["metadata"]["subdomain"] for x in result.findings)
