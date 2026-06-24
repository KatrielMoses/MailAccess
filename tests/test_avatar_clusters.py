from __future__ import annotations

import pytest

from backend.core.enrichment.avatar_clusters import AvatarClusterer


def test_single_pair_returns_empty() -> None:
    clusters = AvatarClusterer().cluster([("github", "https://example.test/a.png")])
    assert clusters == []


def test_two_distinct_urls_with_no_hashes_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # _fetch_phashes is imported from avatar_hasher inside cluster() — patch the source
    import backend.core.avatar_hasher as hasher_mod

    monkeypatch.setattr(hasher_mod, "_fetch_phashes", lambda urls: {u: None for u in urls})

    pairs = [
        ("github", "https://example.test/a.png"),
        ("twitter", "https://example.test/b.png"),
    ]
    clusters = AvatarClusterer().cluster(pairs)
    assert clusters == []


def test_identical_urls_cluster_without_network() -> None:
    """Platforms sharing the same URL cluster via URL equality — no HTTP fetch needed."""
    pairs = [
        ("github", "https://example.test/shared.png"),
        ("twitter", "https://example.test/shared.png"),
        ("linkedin", "https://example.test/shared.png"),
    ]
    clusters = AvatarClusterer().cluster(pairs)

    assert len(clusters) == 1
    assert clusters[0]["cluster_size"] == 3
    assert set(clusters[0]["platforms"]) == {"github", "twitter", "linkedin"}


def test_two_identical_urls_form_cluster() -> None:
    pairs = [
        ("github", "https://example.test/same.png"),
        ("twitter", "https://example.test/same.png"),
    ]
    clusters = AvatarClusterer().cluster(pairs)

    assert len(clusters) == 1
    assert clusters[0]["cluster_size"] == 2


def test_singleton_not_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    """A platform with a unique URL that can't hash to any similar peer is excluded."""
    import backend.core.avatar_hasher as hasher_mod

    monkeypatch.setattr(hasher_mod, "_fetch_phashes", lambda urls: {u: None for u in urls})

    pairs = [
        ("github", "https://example.test/same.png"),
        ("twitter", "https://example.test/same.png"),
        ("instagram", "https://example.test/different.png"),
    ]
    clusters = AvatarClusterer().cluster(pairs)

    all_platforms = [p for c in clusters for p in c["platforms"]]
    assert "instagram" not in all_platforms
    # github and twitter still cluster (same URL)
    assert len(clusters) == 1
    assert set(clusters[0]["platforms"]) == {"github", "twitter"}


def test_hamming_distance_computation() -> None:
    assert AvatarClusterer._hamming("0000000000000000", "0000000000000001") == 1
    assert AvatarClusterer._hamming("0000000000000000", "ffffffffffffffff") == 64
    assert AvatarClusterer._hamming("aaaa000000000000", "aaaa000000000000") == 0


def test_hamming_threshold_respected(monkeypatch: pytest.MonkeyPatch) -> None:
    """URLs within Hamming distance ≤ max cluster; URLs beyond do not."""
    import backend.core.avatar_hasher as hasher_mod

    close_a = "0000000000000000"
    close_b = "0000000000000003"  # 2 bits differ
    far = "ffffffffffffffff"  # 64 bits differ

    mapping = {
        "https://example.test/a.png": close_a,
        "https://example.test/b.png": close_b,
        "https://example.test/c.png": far,
    }
    monkeypatch.setattr(hasher_mod, "_fetch_phashes", lambda urls: {u: mapping.get(u) for u in urls})

    pairs = [
        ("github", "https://example.test/a.png"),
        ("twitter", "https://example.test/b.png"),
        ("linkedin", "https://example.test/c.png"),
    ]
    clusters = AvatarClusterer(max_hamming_distance=5).cluster(pairs)

    assert len(clusters) == 1
    assert set(clusters[0]["platforms"]) == {"github", "twitter"}
