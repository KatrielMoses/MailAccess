"""UC7.3b: derive GitHub logins from an email and verify each against a Class-1 fact.
A derived handle becomes an account only when GET /users/{login} confirms the subject
(public email match, or a linked site on the subject's domain). Synthetic fixtures only.
"""

from __future__ import annotations

import asyncio
import json

import httpx

from backend.modules.github_commits import GitHubCommitsModule, derive_github_handles


def test_derive_includes_domain_token_handles():
    handles = derive_github_handles("sampleuser@rootbox.test")
    # local part, and local + a domain-word split (root / box / rootbox)
    assert "sampleuser" in handles
    assert "sampleuser-root" in handles and "rootbox" in handles


def test_derive_skips_domain_tokens_for_freemail():
    handles = derive_github_handles("sampleuser@gmail.com")
    assert handles == ["sampleuser"]  # no gmail tokens


def _verify(email, domain, user_by_login):
    """Run _verify_derived_handles against a mock GitHub that returns the given users."""
    def handler(request):
        login = request.url.path.rsplit("/", 1)[-1]
        if login in user_by_login:
            return httpx.Response(200, text=json.dumps(user_by_login[login]))
        return httpx.Response(404, text="{}")

    async def go():
        async with httpx.AsyncClient(base_url="https://api.github.com",
                                     transport=httpx.MockTransport(handler)) as client:
            return await GitHubCommitsModule()._verify_derived_handles(client, {}, email, domain)

    return asyncio.run(go())


def test_verified_by_public_email_becomes_account():
    found = _verify("sampleuser@rootbox.test", "rootbox.test", {
        "sampleuser-root": {"login": "sampleuser-root", "email": "sampleuser@rootbox.test",
                            "name": "Sample User", "html_url": "https://github.com/sampleuser-root"},
    })
    assert len(found) == 1
    assert found[0]["username"] == "sampleuser-root" and found[0]["confidence"] == "high"
    assert found[0]["email_linked"] is True
    assert found[0]["metadata"]["verified_by"] == "public_email"


def test_verified_by_linked_domain_becomes_account():
    found = _verify("sampleuser@rootbox.test", "rootbox.test", {
        "sampleuser-root": {"login": "sampleuser-root", "email": None,
                            "blog": "https://rootbox.test", "name": "Sample User",
                            "html_url": "https://github.com/sampleuser-root"},
    })
    assert len(found) == 1 and found[0]["metadata"]["verified_by"] == "linked_domain"


def test_unconfirmed_handle_is_not_shown():
    # the login exists but nothing ties it to the subject -> not an account (the guess
    # alone is not evidence)
    found = _verify("sampleuser@rootbox.test", "rootbox.test", {
        "sampleuser": {"login": "sampleuser", "email": "someone-else@elsewhere.test",
                       "blog": "https://unrelated.example", "name": "Someone Else"},
    })
    assert found == []
