import pytest

from backend.modules.base import ModuleResult, ModuleStatus
from backend.modules.email_identity_enrichment import EmailIdentityEnrichmentModule


class FakeSource:
    def __init__(self, name):
        self.name = name

    async def run(self, *args, **kwargs):
        return ModuleResult(status=ModuleStatus.SUCCESS, findings=[{"platform": self.name, "metadata": {}}])


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
