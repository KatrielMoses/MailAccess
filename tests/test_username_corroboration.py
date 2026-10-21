"""UC7.1: context-aware corroboration of local-part username matches.

A bare @handle match (email local part) is scored against the rest of the report:
freemail subjects keep the handle's weight, domain subjects demote uncorroborated
bare matches and promote corroborated ones. Scoring only — nothing is dropped. All
fixtures synthetic (sampleperson; gmail.com / acme.test as provider/domain, not people).
"""

from __future__ import annotations

from backend.core.evidence import corroborate_username_matches, subject_is_freemail


def _um(host, user, name="", links=None, other_handles=None):
    return {
        "platform": host, "username": user, "profile_url": f"https://{host}/{user}",
        "label": "username_match",
        "metadata": {"display_name": name, "links": links or [],
                     "other_handles": other_handles or []},
        "trace": {"module": "username_platforms", "signal_type": "username_match"},
    }


def _confirmed(host, user, name=""):
    return {
        "platform": host, "username": user, "profile_url": f"https://{host}/{user}",
        "label": "possible", "metadata": {"display_name": name},
        "trace": {"module": "account_discovery", "signal_type": "email_registration_check"},
    }


def _domain_record(links):
    return {
        "platform": "whois", "metadata": {"links": links}, "label": None,
        "trace": {"module": "whois_lookup", "signal_type": "other:whois_lookup"},
    }


def _tier(f):
    return (f.get("trace") or {}).get("username_corroboration", {}).get("tier")


def _group(f):
    return (f.get("metadata") or {}).get("localpart_group")


def test_freemail_vs_domain_classification():
    assert subject_is_freemail("sampleperson@gmail.com") is True
    assert subject_is_freemail("role@acme.test") is False
    assert subject_is_freemail("sampleperson") is False  # username subject, no @


def test_domain_bare_collision_is_grouped():
    bare = _um("github.com", "roleuser")
    rows = [("username_platforms", bare)]
    corroborate_username_matches(rows, "roleuser@acme.test", {"confirmed_name": None})
    assert _tier(bare) == "none"
    assert _group(bare) == "uncorroborated"


def test_domain_match_linked_from_domain_context_is_promoted():
    linked = _um("patreon.com", "roleuser")
    rows = [
        ("username_platforms", linked),
        ("whois_lookup", _domain_record(["https://patreon.com/roleuser"])),
    ]
    corroborate_username_matches(rows, "roleuser@acme.test", {"confirmed_name": None})
    assert _tier(linked) == "possible"
    assert _group(linked) == "corroborated"
    assert linked["trace"]["username_corroboration"]["domain_context"] is True


def test_freemail_name_agreement_promotes_to_possible():
    match = _um("medium.com", "sampleperson", "Sample Person")
    rows = [("username_platforms", match)]
    corroborate_username_matches(rows, "sampleperson@gmail.com", {"confirmed_name": "Sample Person"})
    assert _tier(match) == "possible"
    assert _group(match) == "corroborated"


def test_freemail_bare_match_keeps_current_behaviour():
    """A freemail bare collision is NOT grouped away (local part is the chosen handle)."""
    bare = _um("rand.example", "sampleperson")
    rows = [("username_platforms", bare)]
    corroborate_username_matches(rows, "sampleperson@gmail.com", {"confirmed_name": "Sample Person"})
    assert _tier(bare) == "none"
    assert _group(bare) is None  # no grouping flag for freemail


def test_same_site_confirmed_plus_name_is_confirmed():
    match = _um("github.com", "sampleperson", "Sample Person")
    rows = [
        ("username_platforms", match),
        ("account_discovery", _confirmed("github.com", "sampleperson", "Sample Person")),
    ]
    corroborate_username_matches(rows, "sampleperson@gmail.com", {"confirmed_name": "Sample Person"})
    assert _tier(match) == "confirmed"
    assert _group(match) == "corroborated"


def test_cross_site_handle_name_consistency_promotes():
    """Same handle + same name on two sites corroborates even without a confirmed name."""
    a = _um("siteone.example", "jdoe", "Jamie Doe")
    b = _um("sitetwo.example", "jdoe", "Jamie Doe")
    rows = [("username_platforms", a), ("username_platforms", b)]
    corroborate_username_matches(rows, "jdoe@acme.test", {"confirmed_name": None})
    assert _tier(a) == "possible" and _tier(b) == "possible"
    assert a["trace"]["username_corroboration"]["cross_site"] is True


def test_linkback_to_confirmed_handle_promotes():
    match = _um("mastodon.example", "sampleperson",
                other_handles=["sampleperson@github.com"])
    rows = [
        ("username_platforms", match),
        ("account_discovery", _confirmed("github.com", "sampleperson", "Sample Person")),
    ]
    corroborate_username_matches(rows, "sampleperson@acme.test", {"confirmed_name": None})
    assert match["trace"]["username_corroboration"]["link_back"] is True
    assert _tier(match) == "possible"
