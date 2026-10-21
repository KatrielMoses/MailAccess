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
    meta = dict(module_meta or {})
    acct = {"platform": platform, "username": username, "confidence": confidence,
            "profile_url": f.get("url", f"https://{platform.lower()}/{username or ''}"),
            "email_linked": f.get("email_linked", False),
            "metadata": meta}
    # UC7.2: a username-sweep account joins the identity spine only when it is
    # email-linked or UC7.1 corroborated it up. Test fixtures opt in with
    # corroborated=True (the match UC7.1 lifted to the spine); a bare match stays out.
    if f.get("corroborated"):
        meta["localpart_group"] = "corroborated"
        acct["trace"] = {"signal_type": "username_match",
                         "username_corroboration": {"tier": "possible"}}
    return acct


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
                                        "avatar_url": "https://a/1.png"}, corroborated=True),
            # same name, unrelated handle, no second signal -> listed but NOT aggregated
            _acct("Medium", "jdwriter", {"core": True, "display_name": "Jane Doe",
                                         "avatar_url": "https://a/x.png"}),
        ],
    }, subject_username="janedoe")  # --username mode: handle-based accounts aggregate
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
                                        "other_handles": ["x:jane_x"]}, corroborated=True),
            _acct("X", "jane_x", {"core": True, "display_name": "Jane Doe"}),  # cross-linked handle ties in
        ],
    }, subject_username="janedoe")
    card = build_card(data)
    assert all(a["in_aggregates"] for a in card["accounts"])


def test_photo_perceptual_dedup():
    data = _report({
        "username_platforms": [
            _acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe",
                                        "avatar_url": "https://a/1.png", "avatar_phash": "ffffffff00000000"}, corroborated=True),
            _acct("Instagram", "janedoe", {"core": True, "display_name": "Jane Doe",
                                           "avatar_url": "https://a/2.png", "avatar_phash": "ffffffff00000001"}, corroborated=True),  # dist 1
            _acct("Snapchat", "janedoe", {"core": True, "display_name": "Jane Doe",
                                          "avatar_url": "https://a/3.png", "avatar_phash": "0000ffff0000ffff"}, corroborated=True),  # far
        ],
    }, subject_username="janedoe")
    card = build_card(data)
    assert card["counts"]["photos"] == 2  # the two near-identical ones collapse


def test_timeline_earliest_and_latest():
    data = _report({
        "username_platforms": [
            _acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe",
                                        "joined_at": "2020-01-01T00:00:00Z", "last_active_at": "2024-06-01T00:00:00Z"}, corroborated=True),
            _acct("Chess", "janedoe", {"core": True, "display_name": "Jane Doe",
                                       "joined_at": "2018-05-01T00:00:00Z", "last_active_at": "2026-02-01T00:00:00Z"}, corroborated=True),
        ],
    }, subject_username="janedoe")
    card = build_card(data)
    assert card["timeline"] == {"first_seen": "2018-05-01T00:00:00Z", "last_seen": "2026-02-01T00:00:00Z"}


def test_timeline_omitted_when_no_dates():
    data = _report({"username_platforms": [_acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe"})]})
    assert build_card(data)["timeline"] == {}


def test_location_disagreement_shows_both_not_guessed():
    data = _report({
        "username_platforms": [
            _acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe",
                                        "location_normalized": {"city": "Pune", "country_code": "IN"}}, corroborated=True),
            _acct("Docker", "janedoe", {"core": True, "display_name": "Jane Doe",
                                        "location_normalized": {"city": "Pune", "country_code": "IN"}}, corroborated=True),
            _acct("Chess", "janedoe", {"core": True, "display_name": "Jane Doe",
                                       "location_normalized": {"country_code": "US"}}, corroborated=True),
        ],
    }, subject_username="janedoe")
    loc = build_card(data)["locations"]
    assert loc["primary"]["country_code"] == "IN"       # most sources wins; never guessed
    assert loc["countries"] == ["IN", "US"]             # disagreement surfaced
    assert any(e.get("country_code") == "US" for e in loc["also_seen"])


def test_names_primary_and_variants():
    data = _report({
        "username_platforms": [
            _acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe", "other_handles": ["x:jd"]}, corroborated=True),
            _acct("Bandlab", "janedoe", {"core": True, "display_name": "JD Doe"}, corroborated=True),  # variant, same subject handle
        ],
    }, subject_username="janedoe")
    names = build_card(data)["names"]
    assert names["primary"] == "Jane Doe"
    assert {v["name"] for v in names["variants"]} == {"JD Doe"}


def test_card_present_with_no_name():
    data = _report({"username_platforms": [_acct("GitHub", "janedoe", {"core": True})]}, name_consensus={})
    card = build_card(data)
    assert card["counts"]["accounts"] == 1 and card["names"]["primary"] is None


def test_uc72_email_subject_bare_handle_match_not_in_aggregates():
    """UC7.2: for an email subject the spine is Class 1. A bare username_match whose
    handle merely equals the local part is NOT a tie (that was the Class-2 blend)."""
    data = _report({
        # A registration check carries no handle — the email itself is the tie.
        "account_discovery": [
            _acct("Canva", None, {"display_name": "Jane Doe"}, email_linked=True),  # Class-1 anchor
        ],
        "username_platforms": [
            _acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe"}),      # bare, uncorroborated
            _acct("Bahamut", "janedoe", {"core": True, "display_name": "Someone Else"}),  # stranger, same handle
        ],
    })
    card = build_card(data)
    by = {a["platform"]: a for a in card["accounts"]}
    assert by["Canva"]["in_aggregates"] is True            # email-anchored → identity
    assert by["GitHub"]["in_aggregates"] is False          # bare handle match: not the spine
    assert by["Bahamut"]["in_aggregates"] is False         # stranger kept out
    assert card["counts"]["linked_to_subject"] == 1        # only the email-anchored account


def test_uc72_username_subject_handle_match_stays_direct():
    """--username mode: the handle IS the identity, so a handle match stays direct."""
    data = {"subject_username": "janedoe", "name_consensus": {},
            "findings_by_module": {"username_platforms": [
                _acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe"})]}}
    card = build_card(data)
    assert card["accounts"][0]["in_aggregates"] is True
    assert card["counts"]["linked_to_subject"] == 1


def test_uc72r2_domain_subject_corroborated_class2_stays_out():
    """UC7.2 r2: a DOMAIN subject's identity is Class-1 only — a Class-2 match stays out
    of the aggregates even when UC7.1 corroborated it (the local part is a role)."""
    data = _report({
        "username_platforms": [
            _acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe"}, corroborated=True),
        ],
    }, original_email="role@acme.test", canonical_email="role@acme.test")
    card = build_card(data)
    assert card["accounts"][0]["in_aggregates"] is False
    assert card["counts"]["linked_to_subject"] == 0


def test_uc72r2_freemail_corroborated_class2_joins():
    """UC7.2 r2: a FREEMAIL subject's local part is their own handle, so a Class-2 match
    UC7.1 corroborated up to the spine DOES join the identity — when the handle is
    specific (UC7.3)."""
    data = _report({
        "username_platforms": [
            _acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe"}, corroborated=True),
        ],
    }, original_email="janedoe@gmail.com", canonical_email="janedoe@gmail.com")
    card = build_card(data)
    assert card["accounts"][0]["in_aggregates"] is True
    assert card["counts"]["linked_to_subject"] == 1


def test_uc73e_bare_common_firstname_freemail_stays_sparse():
    """UC7.3 Part 5: a bare common-first-name freemail (local part ``john``) is treated
    like a domain role — Class-1 only — so a corroborated Class-2 match does NOT blend in,
    even though the subject is freemail."""
    data = _report({
        "username_platforms": [
            _acct("GitHub", "john", {"core": True, "display_name": "John Smith"}, corroborated=True),
        ],
    }, original_email="john@gmail.com", canonical_email="john@gmail.com")
    card = build_card(data)
    assert card["accounts"][0]["in_aggregates"] is False
    assert card["counts"]["linked_to_subject"] == 0


def test_uc73e_specific_freemail_handle_keeps_corroborated_class2():
    """A compound/distinctive freemail handle (``janedoe``) is specific → corroborated
    Class-2 still joins (owner's photos/locations survive)."""
    data = _report({
        "username_platforms": [
            _acct("GitHub", "janedoe", {"core": True, "display_name": "Jane Doe",
                                        "avatar_url": "https://a/1.png"}, corroborated=True),
        ],
    }, original_email="janedoe@gmail.com", canonical_email="janedoe@gmail.com")
    card = build_card(data)
    assert card["accounts"][0]["in_aggregates"] is True


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
