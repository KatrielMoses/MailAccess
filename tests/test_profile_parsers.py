"""UC3 profile parsers: one saved-response test per parser, plus the field rules.

Fixtures in tests/fixtures/profiles/ are built from consented test handles and scrubbed
(names, handles, places, ids and every extracted value replaced) by dev tooling; each
records the fields its parser must return.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from backend.core.mailaccess_sites_loader import load_mailaccess_sites
from backend.core.probe_detector import detect_hit
from backend.core.profiles import FIELD_KEYS, enrich
from backend.core.profiles.fields import Profile, scrub
from backend.core.profiles.geo import normalize_location
from backend.core.profiles.sites import PARSERS

FIXTURES = sorted((Path(__file__).parent / "fixtures" / "profiles").glob("*.json"))


class _FakeClient:
    def __init__(self, pages: dict[str, str]) -> None:
        self.pages = pages
        self.calls: list[str] = []

    async def request(self, method, url, **kwargs):
        self.calls.append(url)

        class _Resp:
            pass

        resp = _Resp()
        resp.status_code, resp.text = (200, self.pages[url]) if url in self.pages else (404, "")
        return resp


def _run(defn, username, body, snapshot, pages):
    profile = {"_body": body, "_probe_response": snapshot}
    asyncio.run(enrich(_FakeClient(pages), defn, username, profile))
    return profile


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_parser_on_saved_response(path: Path) -> None:
    fx = json.loads(path.read_text())
    corpus, _ = load_mailaccess_sites()
    profile = _run(corpus[fx["site_id"]], fx["username"], fx["body"], fx["snapshot"], fx["follow_ups"])
    got = {k: profile[k] for k in [*FIELD_KEYS.values(), "location_normalized"] if k in profile}
    assert got == fx["expected"]
    assert "_body" not in profile  # the full body is never kept
    sources = profile.get("field_sources", {})
    assert all(sources.get(key) for key in got if key != "location_normalized")


def test_every_parser_has_a_fixture_or_is_synthetic_only() -> None:
    have = {json.loads(p.read_text())["site_id"] for p in FIXTURES}
    # Reddit/Keybase/Discord: no consented test handle has an account, so they are covered
    # by the synthetic-shape tests below (Discord is existence-only).
    assert set(PARSERS) - have <= {"reddit", "keybase", "discord_2"}


def test_reddit_and_keybase_shapes() -> None:
    corpus, _ = load_mailaccess_sites()
    reddit = json.dumps({"data": {"name": "someone", "created_utc": 1600000000, "total_karma": 12,
                                  "verified": True, "icon_img": "https://styles.example/a.png?x=1",
                                  "subreddit": {"title": "Some One", "public_description": "hi",
                                                "subscribers": 3}}})
    p = _run(corpus["reddit"], "someone", reddit, {"url": "https://www.reddit.com/user/someone/about.json"}, {})
    assert p["display_name"] == "Some One" and p["posts"] == 12 and p["followers"] == 3
    keybase = json.dumps({"them": [{"basics": {"username": "someone", "ctime": 1500000000},
                                    "profile": {"full_name": "Some One", "location": "Lisbon, Portugal",
                                                "bio": "b"},
                                    "proofs_summary": {"all": [{"service_url": "https://github.com/someone"}]}}]})
    p = _run(corpus["keybase"], "someone", keybase, {"url": "https://keybase.io/x"}, {})
    assert p["location_normalized"] == {"country_code": "PT", "city": "Lisbon"}
    assert p["other_handles"] == ["github:someone"]


def test_location_normalisation() -> None:
    assert normalize_location("Indore, India") == {"country_code": "IN", "city": "Indore"}
    assert normalize_location("Pune, Maharashtra, India") == {
        "country_code": "IN", "city": "Pune", "region": "Maharashtra"}
    assert normalize_location("IN") == {"country_code": "IN"}
    assert normalize_location("https://api.chess.com/pub/country/IN") == {"country_code": "IN"}
    assert normalize_location("Ireland (IE)") == {"country_code": "IE"}
    assert normalize_location("12 MG Road, Pune") is None  # a street address: refused
    assert normalize_location("+91 98450 12345") is None  # a phone number: refused


def test_phone_numbers_and_addresses_are_never_stored() -> None:
    p = Profile()
    p.set("bio", "Call me on +44 20 7946 0958. Worked 2019-2020.", "https://x.example")
    p.set("location", "221B Baker Street, London", "https://x.example")
    meta: dict = {}
    p.merge_into(meta)
    assert "7946" not in meta["bio"] and "2019-2020" in meta["bio"]
    assert "location" not in meta
    assert scrub("+1 (555) 010-9999") is None


def test_default_images_and_email_names_are_dropped() -> None:
    p = Profile()
    p.set("avatar", "https://cdn.example/default_avatar.png", "u")
    p.set("name", "someone@example.com", "u")
    p.set("banner", "//img.example/banner.jpg", "u")
    meta: dict = {}
    p.merge_into(meta)
    assert "avatar_url" not in meta and "display_name" not in meta
    assert meta["banner_url"] == "https://img.example/banner.jpg"


def test_links_in_bios_give_linkedin_and_other_handles() -> None:
    p = Profile()
    p.set("bio", "Security engineer https://www.linkedin.com/in/some-one and https://x.com/someone", "u")
    meta: dict = {}
    p.merge_into(meta)
    assert meta["linkedin_url"] == "https://www.linkedin.com/in/some-one"
    assert set(meta["other_handles"]) == {"linkedin:some-one", "x:someone"}


def test_instagram_bare_page_is_inconclusive_only_404_is_missing() -> None:
    corpus, _ = load_mailaccess_sites()
    ig = dict(corpus["instagram_2"])
    ig["presenseStrs"] = ["(@someone)"]
    assert detect_hit(ig, "<title>Instagram</title>", 200, "") == "inconclusive"
    assert detect_hit(ig, "<title>Instagram</title>", 404, "") == "miss"
    assert detect_hit(ig, '<meta property="og:title" content="S (@someone) x">', 200, "") == "hit"
