from __future__ import annotations

import asyncio

import pytest

from backend.config import settings
from backend.modules import linkedin_brightdata as lb
from backend.modules.base import ModuleResult, ModuleStatus

URL = "https://www.linkedin.com/in/jane-doe/"

RECORD = {
    "name": "Jane Doe",
    "first_name": "Jane",
    "last_name": "Doe",
    "headline": "Security Engineer",
    "city": "Pune, Maharashtra, India",
    "country_code": "IN",
    "profile_photo": "https://media.example/photo.jpg",
    "cover_photo": "https://media.example/cover.jpg",
    "about": "Builds things. Call +91 98450 12345 anytime.",
    "current_company": {"name": "Example Corp", "link": "https://www.linkedin.com/company/example"},
    "education": [{"title": "Example University", "start_year": "2018", "end_year": "2022",
                   "description": "x"}],
    "certifications": [{"name": "OSCP"}],
    "followers": 512,
    "connections": 500,
    "websites": ["https://github.com/janedoe"],
    "organizations": [{"title": "OWASP"}],
    "posts": [{"text": "p" * 300}, {"text": "two"}, {"text": "three"}, {"text": "four"}],
    "similar_profiles": [{"name": "Someone Else"}],
    "people_also_viewed": [{"name": "Another Person"}],
    "experience": [{"title": "Engineer", "company": "Example Corp"}],
    "email": "jane@example.com",
    "phone": "+91 98450 12345",
    "street_address": "12 MG Road",
}


def _collected(*, name="Jane Doe", links=None, country="IN", handles=("jane.doe",), profiles=1,
               own_link=True):
    # UC7.2: the card tests exercise the legitimate own-profile-link path (a LinkedIn URL
    # the person links to earns high); handle-guess tests opt out with own_link=False.
    if links is None:
        links = ["https://www.linkedin.com/in/jane-doe/"] if own_link else []
    findings = []
    for i, handle in enumerate(handles):
        findings.append({
            "platform": f"Site{i}", "username": handle, "confidence": "medium",
            "profile_url": f"https://site{i}.example/{handle}",
            "metadata": {"core": True, "display_name": name,
                         "location_normalized": {"country_code": country} if country else None,
                         "links": links if i == 0 else []},
        })
    for j in range(profiles - len(findings)):
        findings.append({"platform": f"Extra{j}", "username": "jane.doe", "confidence": "medium",
                         "metadata": {"core": True}})
    return {"username_platforms": ModuleResult(status=ModuleStatus.SUCCESS, findings=findings)}


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "brightdata_api_key", "bd-test-key", raising=False)
    monkeypatch.setattr(settings, "brightdata_disabled", False, raising=False)
    monkeypatch.setattr(lb, "_CACHE_DIR", tmp_path / "bd-cache")
    calls = []

    async def fake_fetch(url, **kw):
        calls.append(url)
        return dict(RECORD)

    monkeypatch.setattr(lb, "fetch_profile", fake_fetch)
    return calls


def _run(collected):
    return asyncio.run(lb.LinkedInBrightDataModule().run("jane@example.com", collected))


def test_url_from_own_profile_link_wins():
    c = _collected(links=["https://www.linkedin.com/in/Jane-Doe-123"])
    assert lb.find_profile_url(c) == ("https://www.linkedin.com/in/jane-doe-123/", "own_link")


def test_url_from_handle_prefers_hyphenated_dotted_handle():
    # Freemail subject: the local-part sweep handle is the person's own handle.
    c = _collected(handles=("janedoe", "jane.doe"), own_link=False)
    assert lb.find_profile_url(c, freemail=True) == ("https://www.linkedin.com/in/jane-doe/", "handle")


def test_domain_subject_does_not_guess_linkedin_from_local_part():
    """UC7.2: for a domain subject a bare local-part sweep handle must NOT seed a slug
    guess (that surfaced a stranger's profile). No spine handle, no own link => no URL."""
    c = _collected(handles=("roleuser",), own_link=False)
    assert lb.find_profile_url(c, freemail=False) is None


def test_spine_handle_seeds_the_guess():
    """A Class-1 account handle (e.g. the GitHub login from a commit-email match) is a
    trusted seed even for a domain subject — source 'spine_handle'."""
    c = {"github_commits": ModuleResult(status=ModuleStatus.SUCCESS, findings=[
        {"platform": "GitHub", "username": "jane-root",
         "metadata": {"source": "github_commits"}}])}
    assert lb.find_profile_url(c, freemail=False) == ("https://www.linkedin.com/in/jane-root/", "spine_handle")


def test_url_from_serp_slug_last():
    c = {"linkedin_serp": ModuleResult(status=ModuleStatus.SUCCESS, findings=[
        {"platform": "linkedin_snippet", "profile_url": "https://www.linkedin.com/in/jdoe"}])}
    assert lb.find_profile_url(c) == ("https://www.linkedin.com/in/jdoe/", "serp")
    assert lb.find_profile_url({}) is None


def test_name_match_rules():
    assert lb.names_match("Jane Doe", "jane q doe")
    assert lb.names_match("J Doe", "Jane Doe")
    assert not lb.names_match("Jane Doe", "Jane Smith")
    assert not lb.names_match("Jane", "Jane Doe")


def test_card_with_name_and_second_detail(_env):
    result = _run(_collected(country="IN"))
    assert result.status == ModuleStatus.SUCCESS
    card = result.findings[0]
    meta = card["metadata"]
    assert card["platform"] == "LinkedIn" and card["confidence"] == "high"
    assert meta["match"]["second_detail"] in ("country", "link_back")
    assert meta["display_name"] == "Jane Doe"
    assert meta["location_normalized"] == {"country_code": "IN", "city": "Pune", "region": "Maharashtra"}
    assert meta["current_company"] == "Example Corp"
    assert meta["education"] == [{"title": "Example University", "start_year": "2018", "end_year": "2022"}]
    assert meta["certifications"] == ["OSCP"] and meta["organizations"] == ["OWASP"]
    assert meta["followers"] == 512 and meta["connections"] == 500
    assert len(meta["recent_posts"]) == 3 and len(meta["recent_posts"][0]) == 200
    assert "98450" not in meta["bio"]  # phone cut from the about text
    assert _env == [URL]  # exactly one Bright Data call


def test_dropped_fields_never_appear(_env):
    text = repr(_run(_collected()).findings[0])
    for dropped in ("Someone Else", "Another Person", "Engineer\"", "jane@example.com",
                    "12 MG Road", "similar_profiles", "people_also_viewed", "experience"):
        assert dropped not in text


def test_name_only_accepted_with_few_profiles(_env):
    result = _run(_collected(country="US", profiles=2))  # no detail agrees (IN vs US, no link)
    RECORD_links = lb.extract_card(dict(RECORD), URL)["links"]
    assert RECORD_links == ["https://github.com/janedoe"]
    finding = result.findings[0] if result.findings else None
    assert finding and finding["confidence"] == "medium"
    assert finding["metadata"]["match"]["second_detail"] is None


def test_name_only_discarded_with_three_or_more_profiles(_env):
    result = _run(_collected(country="US", profiles=4))
    assert result.findings == [] and result.metadata["discarded"] == "no_second_detail"


def test_wrong_name_is_discarded(_env):
    result = _run(_collected(name="John Smith"))
    assert result.findings == [] and result.metadata["discarded"] == "name_mismatch"


def test_no_confirmed_name_means_no_call(_env):
    result = _run(_collected(name="K"))
    assert result.status == ModuleStatus.SKIPPED and _env == []


def test_guessed_url_caps_at_medium_even_with_detail(_env):
    """UC7.2: a slug guess (handle/spine) is never high, even when a second detail
    agrees — only a link on the person's own profile earns high."""
    collected = _collected(country="IN", own_link=False)  # handle path, detail agrees
    result = asyncio.run(lb.LinkedInBrightDataModule().run("jane@gmail.com", collected))
    assert result.findings and result.findings[0]["metadata"]["url_source"] == "handle"
    assert result.findings[0]["metadata"]["match"]["second_detail"] in ("country", "link_back")
    assert result.findings[0]["confidence"] == "medium"  # capped: a guess is never high


def test_cache_hit_skips_the_call(_env):
    _run(_collected())
    _run(_collected())
    assert _env == [URL]  # second run served from the 7-day cache


def test_inactive_without_key(monkeypatch, _env):
    monkeypatch.setattr(settings, "brightdata_api_key", None, raising=False)
    assert _run(_collected()).status == ModuleStatus.SKIPPED and _env == []
