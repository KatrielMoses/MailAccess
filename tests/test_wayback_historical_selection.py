from backend.modules.wayback import _select_historical_rows


def test_wayback_selection_keeps_old_and_new_snapshot_per_url():
    ranked = [
        ({"original": "https://acme.org/team", "timestamp": "20260101000000"}, 2.0),
        ({"original": "https://acme.org/team", "timestamp": "20200101000000"}, 2.0),
        ({"original": "https://acme.org/about", "timestamp": "20250101000000"}, 1.0),
    ]
    selected = _select_historical_rows(ranked, cap=3)
    keys = {(row["original"], row["timestamp"]) for row, _ in selected}
    assert ("https://acme.org/team", "20260101000000") in keys
    assert ("https://acme.org/team", "20200101000000") in keys
    assert len(selected) == 3
