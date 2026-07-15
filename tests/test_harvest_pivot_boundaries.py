from __future__ import annotations

from types import SimpleNamespace

import pytest

from backend.core.harvest_runner import _record_module_result
from backend.modules.base import ModuleResult, ModuleStatus
from backend.modules.name_to_github_profile import NameToGitHubProfileModule
from backend.modules.person_email_pivot import PersonEmailPivotModule
from backend.modules.security_txt import _parse_security_txt


class _Response:
    def __init__(self, payload: dict[str, object], status_code: int = 200) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict[str, object]:
        return self._payload


class _Fetch:
    def __init__(self, responses: dict[str, _Response]) -> None:
        self.responses = responses
        self.urls: list[str] = []

    async def get(self, url: str) -> _Response:
        self.urls.append(url)
        return self.responses[url]


@pytest.mark.asyncio
async def test_person_email_pivot_rejects_matching_name_on_external_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("backend.modules.person_email_pivot.settings.enable_email_search_dork", False)
    fetch = _Fetch({
        "https://api.github.com/search/users?q=Alice+Smith+org:acme&per_page=5": _Response({"items": [{"login": "alice"}]}),
        "https://api.github.com/search/users?q=Alice+Smith&per_page=5": _Response({"items": []}),
        "https://api.github.com/users/alice": _Response({"email": "alice@gmail.com", "html_url": "https://github.com/alice"}),
    })

    result = await PersonEmailPivotModule().run_with_payload(
        {"domain": "acme.com", "names": [{"name": "Alice Smith"}]}, fetch=fetch
    )

    assert result.findings == []
    assert result.metadata["github_emails_found"] == 0


@pytest.mark.asyncio
async def test_name_to_github_profile_accepts_only_target_domain_email() -> None:
    fetch = _Fetch({
        "https://api.github.com/search/users?q=Alice+Smith+org:acme&per_page=5": _Response({"items": [{"login": "alice"}]}),
        "https://api.github.com/users/alice": _Response({
            "email": "alice@acme.com",
            "html_url": "https://github.com/alice",
            "blog": "",
        }),
    })

    result = await NameToGitHubProfileModule().run_with_payload(
        {"name": "Alice Smith", "domain": "acme.com"}, fetch=fetch
    )

    assert len(result.findings) == 1
    assert result.findings[0]["metadata"]["email"] == "alice@acme.com"
    assert result.findings[0]["metadata"]["on_domain"] is True


def test_security_txt_requires_exact_target_domain() -> None:
    text = "\n".join([
        "Contact: mailto:security@notacme.com",
        "Contact: mailto:security@acme.com",
    ])

    assert _parse_security_txt(text, "acme.com") == ["security@acme.com"]


def test_reactive_pivot_results_accumulate_instead_of_overwriting() -> None:
    ctx = SimpleNamespace(module_results={})
    _record_module_result(
        ctx,
        "person_email_pivot",
        ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[{"metadata": {"email": "alice@acme.com"}}],
            metadata={"names_attempted": 1, "github_emails_found": 1},
        ),
    )
    _record_module_result(
        ctx,
        "person_email_pivot",
        ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[{"metadata": {"email": "bob@acme.com"}}],
            metadata={"names_attempted": 1, "github_emails_found": 1},
        ),
    )

    result = ctx.module_results["person_email_pivot"]
    assert [item["metadata"]["email"] for item in result.findings] == [
        "alice@acme.com",
        "bob@acme.com",
    ]
    assert result.metadata["names_attempted"] == 2
    assert result.metadata["github_emails_found"] == 2
