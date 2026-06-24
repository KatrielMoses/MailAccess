from __future__ import annotations

import pytest

from backend.core.enrichment.bio_clusters import BioClusterer


def test_single_pair_returns_empty() -> None:
    clusters = BioClusterer().cluster([("github", "Software Engineer | Python fan")])
    assert clusters == []


def test_empty_pairs_returns_empty() -> None:
    assert BioClusterer().cluster([]) == []


def test_two_identical_bios_form_cluster() -> None:
    pairs = [
        ("github", "Software Engineer | Python fan | he/him"),
        ("twitter", "Software Engineer | Python fan | he/him"),
    ]
    clusters = BioClusterer().cluster(pairs)

    assert len(clusters) == 1
    assert clusters[0]["cluster_size"] == 2
    assert set(clusters[0]["platforms"]) == {"github", "twitter"}


def test_cluster_dict_contains_required_keys() -> None:
    pairs = [
        ("github", "Software Engineer | Python fan | he/him"),
        ("twitter", "Software Engineer | Python fan | he/him"),
    ]
    cluster = BioClusterer().cluster(pairs)[0]

    assert "platforms" in cluster
    assert "similarity_score" in cluster
    assert "bio_excerpt" in cluster
    assert "cluster_size" in cluster


def test_three_token_reordered_bios_form_one_cluster() -> None:
    pairs = [
        ("github", "Software Engineer | Coffee enthusiast | Dad of 3"),
        ("twitter", "Dad of 3 | Software Engineer | Coffee enthusiast"),
        ("linkedin", "Coffee enthusiast | Dad of 3 | Software Engineer"),
    ]
    clusters = BioClusterer().cluster(pairs)

    assert len(clusters) == 1
    assert clusters[0]["cluster_size"] == 3
    assert clusters[0]["similarity_score"] >= 85.0
    assert set(clusters[0]["platforms"]) == {"github", "twitter", "linkedin"}


def test_two_similar_plus_one_unrelated_gives_one_cluster() -> None:
    pairs = [
        ("github", "Software Engineer | Python fan | Open source"),
        ("twitter", "Python fan | Software Engineer | Open source"),
        ("instagram", "Artist and musician | Traveling the world | Foodie"),
    ]
    clusters = BioClusterer().cluster(pairs)

    assert len(clusters) == 1
    assert set(clusters[0]["platforms"]) == {"github", "twitter"}


def test_threshold_override_prevents_clustering_of_near_duplicates() -> None:
    pairs = [
        ("github", "Software Engineer | Python fan and advocate"),
        ("twitter", "Software Engineer | Python enthusiast and advocate"),
    ]
    # At threshold=99, slight wording difference should prevent clustering
    clusters = BioClusterer(similarity_threshold=99).cluster(pairs)
    assert clusters == []


def test_threshold_override_clusters_at_lower_threshold() -> None:
    pairs = [
        ("github", "Software Engineer | Python fan and advocate"),
        ("twitter", "Software Engineer | Python enthusiast and advocate"),
    ]
    # At threshold=85, these similar bios cluster (actual score ~95)
    clusters = BioClusterer(similarity_threshold=85).cluster(pairs)
    assert len(clusters) == 1


def test_average_pairwise_three_entries() -> None:
    clusterer = BioClusterer()
    matrix = [
        [100.0, 90.0, 80.0],
        [90.0, 100.0, 85.0],
        [80.0, 85.0, 100.0],
    ]
    # Off-diagonal pairs: (0,1)=90, (0,2)=80, (1,2)=85 → mean = 85.0
    avg = clusterer._average_pairwise([0, 1, 2], matrix)
    assert avg == pytest.approx(85.0, abs=0.01)


def test_average_pairwise_single_index() -> None:
    clusterer = BioClusterer()
    assert clusterer._average_pairwise([0], [[100.0]]) == 100.0


def test_average_pairwise_empty() -> None:
    clusterer = BioClusterer()
    assert clusterer._average_pairwise([], []) == 0.0


def test_short_bios_below_min_chars_are_excluded() -> None:
    """Bios shorter than 5 non-whitespace chars after normalization are ignored."""
    pairs = [
        ("github", "hi"),
        ("twitter", "hi"),
        ("linkedin", "Software Engineer | Python fan | Open source"),
    ]
    # "hi" normalizes to "hi" (2 non-ws chars) → filtered out; linkedin alone → no cluster
    clusters = BioClusterer().cluster(pairs)
    assert clusters == []


def test_bio_excerpt_is_shortest_non_empty_bio() -> None:
    short_bio = "Python dev | Coffee"
    long_bio = "Python dev | Coffee | Software Engineer at Acme Corp | Open source contributor"
    pairs = [
        ("github", long_bio),
        ("twitter", short_bio),
    ]
    clusters = BioClusterer().cluster(pairs)

    assert len(clusters) == 1
    # bio_excerpt should be the shorter normalized bio
    excerpt = clusters[0]["bio_excerpt"]
    assert len(excerpt) <= len(long_bio)


def test_similarity_score_rounded_to_one_decimal() -> None:
    pairs = [
        ("github", "Software Engineer | Python fan | he/him"),
        ("twitter", "Software Engineer | Python fan | he/him"),
    ]
    clusters = BioClusterer().cluster(pairs)

    assert isinstance(clusters[0]["similarity_score"], float)
    # Verify it's rounded (not a raw float with many decimals)
    score = clusters[0]["similarity_score"]
    assert round(score, 1) == score
