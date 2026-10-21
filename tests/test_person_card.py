from __future__ import annotations

from backend.core.person_card import build_card, names_match


def _report(findings_by_module, **extra):
    base = {
        "original_email": "jane.doe@example.com",
        "canonical_email": "janedoe@example.com",
        "name_consensus": {"confirmed_name": "Jane Doe"},
        "findings_by_module": findings_by_module,
    }
    base.update(extra)
    return base


def _acct(platform, username=None, module_meta=None, confidence="low", **f):
    return {"platform": platform, "username": username, "confidence": confidence,
            "profile_url": f.get("url", f"https://{platform.lower()}/{username or ''}"),
            "email_linked": f.get("email_linked", False),
            "metadata": module_meta or {}}


def test_account_dedup_across_modules():
    data = _report({
        "username_platforms": [_acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe"}, "medium")],
        "username_pivot": [_acct("GitHub", "janedoe", {"source": "username_pivot", "display_name": "Jane Doe"})],
        "account_discovery": [_acct("GitHub", "janedoe", {"verification": "unverified"}, "medium", email_linked=True)],
    })
    card = build_card(data)
    gh = [a for a in card["accounts"] if a["platform"] == "GitHub"]
    assert len(gh) == 1
    assert set(gh[0]["modules"]) == {"username_platforms", "username_pivot", "account_discovery"}
    assert gh[0]["tier"] == "core" and gh[0]["confidence"] == "medium"


def test_collision_guard_keeps_bare_same_name_out_of_aggregates():
    data = _report({
        "username_platforms": [
            _acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe",
                                        "avatar_url": "https://a/1.png"}),
            # same name, unrelated handle, no second signal -> listed but NOT aggregated
            _acct("Medium", "jdwriter", {"core": True, "display_name": "Jane Doe",
                                         "avatar_url": "https://a/x.png"}),
        ],
    })
    card = build_card(data)
    by = {a["platform"]: a for a in card["accounts"]}
    assert by["GitHub"]["in_aggregates"] is True
    assert by["Medium"]["in_aggregates"] is False          # gate 4: no wrong-person photo
    assert card["counts"]["photos"] == 1
    assert [p["source"] for p in card["photos"]] == ["GitHub"]


def test_collision_guard_name_plus_cross_handle_ties_in():
    data = _report({
        "username_platforms": [
            _acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe",
                                        "other_handles": ["x:jane_x"]}),
            _acct("X", "jane_x", {"core": True, "display_name": "Jane Doe"}),  # cross-linked handle
        ],
    })
    card = build_card(data)
    assert all(a["in_aggregates"] for a in card["accounts"])


def test_photo_perceptual_dedup():
    data = _report({
        "username_platforms": [
            _acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe",
                                        "avatar_url": "https://a/1.png", "avatar_phash": "ffffffff00000000"}),
            _acct("Instagram", "janedoe", {"core": True, "display_name": "Jane Doe",
                                           "avatar_url": "https://a/2.png", "avatar_phash": "ffffffff00000001"}),  # dist 1
            _acct("Snapchat", "janedoe", {"core": True, "display_name": "Jane Doe",
                                          "avatar_url": "https://a/3.png", "avatar_phash": "0000ffff0000ffff"}),  # far
        ],
    })
    card = build_card(data)
    assert card["counts"]["photos"] == 2  # the two near-identical ones collapse


def test_timeline_earliest_and_latest():
    data = _report({
        "username_platforms": [
            _acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe",
                                        "joined_at": "2020-01-01T00:00:00Z", "last_active_at": "2024-06-01T00:00:00Z"}),
            _acct("Chess", "janedoe", {"core": True, "display_name": "Jane Doe",
                                       "joined_at": "2018-05-01T00:00:00Z", "last_active_at": "2026-02-01T00:00:00Z"}),
        ],
    })
    card = build_card(data)
    assert card["timeline"] == {"first_seen": "2018-05-01T00:00:00Z", "last_seen": "2026-02-01T00:00:00Z"}


def test_timeline_omitted_when_no_dates():
    data = _report({"username_platforms": [_acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe"})]})
    assert build_card(data)["timeline"] == {}


def test_location_disagreement_shows_both_not_guessed():
    data = _report({
        "username_platforms": [
            _acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe",
                                        "location_normalized": {"city": "Pune", "country_code": "IN"}}),
            _acct("Docker", "janedoe", {"core": True, "display_name": "Jane Doe",
                                        "location_normalized": {"city": "Pune", "country_code": "IN"}}),
            _acct("Chess", "janedoe", {"core": True, "display_name": "Jane Doe",
                                       "location_normalized": {"country_code": "US"}}),
        ],
    })
    loc = build_card(data)["locations"]
    assert loc["primary"]["country_code"] == "IN"       # most sources wins; never guessed
    assert loc["countries"] == ["IN", "US"]             # disagreement surfaced
    assert any(e.get("country_code") == "US" for e in loc["also_seen"])


def test_names_primary_and_variants():
    data = _report({
        "username_platforms": [
            _acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe", "other_handles": ["x:jd"]}),
            _acct("Bandlab", "janedoe", {"core": True, "display_name": "JD Doe"}),  # variant, same subject handle
        ],
    })
    names = build_card(data)["names"]
    assert names["primary"] == "Jane Doe"
    assert {v["name"] for v in names["variants"]} == {"JD Doe"}


def test_card_present_with_no_name():
    data = _report({"username_platforms": [_acct("GitHub", "janedoe", {"core": True})]}, name_consensus={})
    card = build_card(data)
    assert card["counts"]["accounts"] == 1 and card["names"]["primary"] is None


def test_names_match_rule():
    assert names_match("Jane Doe", "jane q doe")
    assert names_match("J Doe", "Jane Doe")
    assert not names_match("Jane Doe", "Jane Smith")
    assert not names_match("Jane", "Jane Doe")


def test_username_subject_uses_handle():
    data = {"subject_username": "janedoe", "name_consensus": {"confirmed_name": "Jane Doe"},
            "findings_by_module": {"username_platforms": [
                _acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe"})]}}
    card = build_card(data)
    assert card["subject"] == {"type": "username", "value": "janedoe"}
    assert card["accounts"][0]["in_aggregates"] is True
