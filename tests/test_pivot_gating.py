"""UC7.2c: the pivot seeds only from the email-anchored spine, not the raw local part
of a domain subject nor a bare (name-unverified) username match. All fixtures synthetic.
"""

from __future__ import annotations

from backend.modules.base import ModuleResult, ModuleStatus
from backend.modules.username_pivot import ranked_usernames


def _collected(**modules):
    return {m: ModuleResult(status=ModuleStatus.SUCCESS, findings=list(fs))
            for m, fs in modules.items()}


def _seeds(email, collected):
    return {u for u, _tier, _origin in ranked_usernames(email, collected)}


def test_domain_subject_bare_match_and_local_part_do_not_seed():
    collected = _collected(username_platforms=[
        {"platform": "Flickr", "username": "roleuser", "metadata": {"core": True},
         "label": "username_match", "trace": {"signal_type": "username_match"}},
    ])
    seeds = _seeds("roleuser@acme.test", collected)
    assert "roleuser" not in seeds  # neither the local part nor the bare match seeds


def test_freemail_subject_local_part_seeds():
    collected = _collected(username_platforms=[])
    assert "janedoe" in _seeds("janedoe@gmail.com", collected)


def test_username_subject_handle_seeds():
    assert "janedoe" in _seeds("janedoe", _collected(username_platforms=[]))


def test_spine_handle_seeds_for_domain_subject():
    # A GitHub commit-author login (Class-1, tied to the email) is a trusted seed.
    collected = _collected(github_commits=[
        {"platform": "GitHub", "username": "jane-root",
         "metadata": {"profile_username": "jane-root"}},
    ])
    assert "jane-root" in _seeds("jane@acme.test", collected)


def test_name_verified_core_hit_seeds():
    # A core sweep hit whose parsed name matches a known name is spine-tied → seeds.
    collected = _collected(
        linkedin_serp=[{"platform": "linkedin_snippet", "metadata": {"display_name": "Jane Doe"},
                        "label": "possible", "trace": {"signal_type": "other:linkedin_serp"}}],
        username_platforms=[
            {"platform": "GitHub", "username": "janedoe",
             "metadata": {"core": True, "display_name": "Jane Doe", "profile_username": "janedoe"},
             "label": "username_match", "trace": {"signal_type": "username_match"}}],
    )
    assert "janedoe" in _seeds("jane@acme.test", collected)
