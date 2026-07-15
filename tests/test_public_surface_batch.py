from __future__ import annotations

import json

import pytest

from backend.modules.package_ecosystems import PackageEcosystemsModule
from backend.modules.public_forge import PublicForgeModule
from backend.modules.public_surface_sweeper import PublicSurfaceSweeper


class Response:
    def __init__(self, status_code: int = 200, text: str = "", payload=None):
        self.status_code = status_code
        self.text = text or (json.dumps(payload) if payload is not None else "")

    def json(self):
        return json.loads(self.text or "{}")


class Fetch:
    def __init__(self, mapping):
        self.mapping = mapping
        self.urls = []

    async def get(self, url: str):
        self.urls.append(url)
        return self.mapping.get(url, Response(404))


@pytest.mark.asyncio
async def test_public_surface_keeps_exact_target_domain(monkeypatch):
    monkeypatch.setattr("backend.modules.public_surface_sweeper.settings.enable_public_surface_sweeper", True)
    monkeypatch.setattr("backend.modules.public_surface_sweeper.settings.public_surface_max_urls", 2)
    fetch = Fetch({
        "https://acme.org/.well-known/security.txt": Response(text="Contact: security@acme.org\nOther: a@acme.org.evil"),
    })
    result = await PublicSurfaceSweeper().run("acme.org", fetch=fetch)
    assert [x["metadata"]["email"] for x in result.findings] == ["security@acme.org"]
    assert result.metadata["urls_checked"] == 2


@pytest.mark.asyncio
async def test_public_forge_extracts_only_target_domain(monkeypatch):
    monkeypatch.setattr("backend.modules.public_forge.settings.enable_public_forge", True)
    monkeypatch.setattr("backend.modules.public_forge.settings.public_forge_max_projects", 1)
    monkeypatch.setattr("backend.modules.public_forge.settings.public_forge_max_commits", 2)
    fetch = Fetch({
        "https://gitlab.com/api/v4/projects?search=acme&simple=true&per_page=1": Response(payload=[{"id": 7, "web_url": "https://gitlab.com/acme/project", "path_with_namespace": "acme/project"}]),
        "https://gitlab.com/api/v4/projects/7/repository/commits?per_page=2": Response(payload=[{"id": "abc", "author_email": "dev@acme.org"}, {"id": "def", "author_email": "dev@other.com"}]),
    })
    result = await PublicForgeModule().run("acme.org", fetch=fetch)
    assert [x["metadata"]["email"] for x in result.findings] == ["dev@acme.org"]


@pytest.mark.asyncio
async def test_package_ecosystems_accepts_rubygems_and_packagist_emails(monkeypatch):
    monkeypatch.setattr("backend.modules.package_ecosystems.settings.enable_package_ecosystems", True)
    monkeypatch.setattr("backend.modules.package_ecosystems.settings.package_ecosystems_max_packages", 1)
    fetch = Fetch({
        "https://rubygems.org/api/v1/search.json?query=acme": Response(payload=[{"name": "acme-gem"}]),
        "https://rubygems.org/api/v2/rubygems/acme-gem.json": Response(payload={"authors": "Dev <dev@acme.org>"}),
        "https://packagist.org/search.json?q=acme": Response(payload={"results": [{"name": "vendor/acme"}]}),
        "https://repo.packagist.org/p2/vendor/acme.json": Response(payload={"packages": {"vendor/acme": [{"authors": [{"email": "maintainer@acme.org"}]}]}}),
    })
    result = await PackageEcosystemsModule().run("acme.org", fetch=fetch)
    assert {x["metadata"]["email"] for x in result.findings} == {"dev@acme.org", "maintainer@acme.org"}
