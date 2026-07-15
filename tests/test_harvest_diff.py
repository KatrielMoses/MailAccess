from backend.core.harvest_diff import compare_harvest_exports


def test_harvest_diff_reports_new_removed_and_unchanged_emails():
    result = compare_harvest_exports(
        {"harvested_at": "old", "emails": [{"email": "old@acme.org"}, {"email": "same@acme.org"}], "discovered_names": [{"name": "Old Name"}]},
        {"harvested_at": "new", "emails": [{"email": "new@acme.org"}, {"email": "same@acme.org"}], "discovered_names": [{"name": "New Name"}]},
    )
    assert result["emails"] == {"new": ["new@acme.org"], "removed": ["old@acme.org"], "unchanged": 1}
    assert result["names"]["new"] == ["new name"]
