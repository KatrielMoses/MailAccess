import pytest

from backend.modules.base import ModuleResult, ModuleStatus
from backend.modules.email_identity_enrichment import EmailIdentityEnrichmentModule


class FakeSource:
    def __init__(self, name):
        self.name = name

    async def run(self, *args, **kwargs):
        return ModuleResult(status=ModuleStatus.SUCCESS, findings=[{"platform": self.name, "metadata": {}}])


class FailingSource:
    def __init__(self, name):
        self.name = name

    async def run(self, *args, **kwargs):
        return ModuleResult(
            status=ModuleStatus.PARTIAL,
            errors=[f"{self.name} unavailable"],
        )


@pytest.mark.asyncio
async def test_identity_enrichment_runs_all_keyless_sources(monkeypatch):
    monkeypatch.setattr("backend.modules.email_identity_enrichment.GravatarLookupModule", lambda: FakeSource("gravatar"))
    monkeypatch.setattr("backend.modules.email_identity_enrichment.GitHubCommitsModule", lambda: FakeSource("github"))
    monkeypatch.setattr("backend.modules.email_identity_enrichment.KeybaseModule", lambda: FakeSource("keybase"))
    monkeypatch.setattr("backend.modules.email_identity_enrichment.HackerNewsModule", lambda: FakeSource("hackernews"))
    monkeypatch.setattr("backend.modules.email_identity_enrichment.FediverseDiscoveryModule", lambda: FakeSource("fediverse"))
    result = await EmailIdentityEnrichmentModule().run_with_payload({"email": "alice@acme.org"})
    assert set(result.metadata["sources"]) == {"gravatar", "github_commits", "keybase", "hackernews", "fediverse"}
    assert len(result.findings) == 5


@pytest.mark.asyncio
async def test_enrichment_partial_when_sources_fail(monkeypatch):
    monkeypatch.setattr("backend.modules.email_identity_enrichment.GravatarLookupModule", lambda: FailingSource("gravatar"))
    monkeypatch.setattr("backend.modules.email_identity_enrichment.GitHubCommitsModule", lambda: FakeSource("github"))
    monkeypatch.setattr("backend.modules.email_identity_enrichment.KeybaseModule", lambda: FakeSource("keybase"))
    monkeypatch.setattr("backend.modules.email_identity_enrichment.HackerNewsModule", lambda: FailingSource("hackernews"))
    monkeypatch.setattr("backend.modules.email_identity_enrichment.FediverseDiscoveryModule", lambda: FakeSource("fediverse"))

    result = await EmailIdentityEnrichmentModule().run_with_payload({"email": "alice@acme.org"})

    assert result.status is ModuleStatus.PARTIAL
    assert result.metadata["source_failures"] == 2
    assert set(result.metadata["failed_sources"]) == {"gravatar", "hackernews"}


@pytest.mark.asyncio
async def test_enrichment_success_when_all_sources_ok(monkeypatch):
    for name, source in (
        ("GravatarLookupModule", "gravatar"),
        ("GitHubCommitsModule", "github"),
        ("KeybaseModule", "keybase"),
        ("HackerNewsModule", "hackernews"),
        ("FediverseDiscoveryModule", "fediverse"),
    ):
        monkeypatch.setattr(
            f"backend.modules.email_identity_enrichment.{name}",
            lambda source=source: FakeSource(source),
        )

    result = await EmailIdentityEnrichmentModule().run_with_payload({"email": "alice@acme.org"})

    assert result.status is ModuleStatus.SUCCESS
    assert result.metadata["source_failures"] == 0
    assert result.metadata["source_total"] == 5
