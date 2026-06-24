from __future__ import annotations

from backend.core.identity_graph import IdentityGraph

_SHARED_AVATAR = "https://example.test/shared_avatar.png"
_SHARED_BIO = "Software Engineer | Coffee enthusiast | Dad of 3 | he/him"


def _finding(platform: str, **kwargs: object) -> dict:
    return {"module_name": platform, "data": {"platform": platform, **kwargs}}


def _result(*findings, email: str = "test@example.com") -> dict:
    return {"email": email, "findings": list(findings)}


def test_large_shared_username_graph_stays_linear() -> None:
    findings = [
        _finding(f"platform-{index}", username="common_handle")
        for index in range(500)
    ]

    graph = IdentityGraph.build(_result(*findings))

    assert len(graph.nodes) == 502  # email + username + 500 platforms
    assert len(graph.edges) < 2_000
    assert any(len(cluster) == 500 for cluster in graph.clusters)


# ---------------------------------------------------------------------------
# Phase 2A — same_avatar
# ---------------------------------------------------------------------------


def test_three_platforms_same_avatar_get_same_avatar_edges() -> None:
    result = _result(
        _finding("github", username="johndoe", photo_url=_SHARED_AVATAR),
        _finding("twitter", username="johndoe", photo_url=_SHARED_AVATAR),
        _finding("linkedin", username="johndoe", photo_url=_SHARED_AVATAR),
    )

    graph = IdentityGraph.build(result)

    same_avatar = [e for e in graph.edges if e.type == "same_avatar"]
    linked = {nid for e in same_avatar for nid in (e.source, e.target)}

    assert len(linked) == 3
    # Three platforms → C(3,2) = 3 pairwise edges
    assert len(same_avatar) == 3


def test_cluster_confidence_boosts_same_avatar_1_5x() -> None:
    result = _result(
        _finding("github", username="johndoe", photo_url=_SHARED_AVATAR),
        _finding("twitter", username="johndoe", photo_url=_SHARED_AVATAR),
        _finding("linkedin", username="johndoe", photo_url=_SHARED_AVATAR),
    )

    graph = IdentityGraph.build(result)
    confidence = graph.cluster_confidence()

    assert confidence
    top = max(confidence, key=lambda x: x["confidence"])
    assert any("1.5" in r for r in top["reasoning"])


def test_two_platforms_same_avatar_not_enough_for_edges() -> None:
    """Only 2 platforms → cluster_size < 3 → no same_avatar edges added."""
    result = _result(
        _finding("github", photo_url=_SHARED_AVATAR),
        _finding("twitter", photo_url=_SHARED_AVATAR),
    )

    graph = IdentityGraph.build(result)
    assert not any(e.type == "same_avatar" for e in graph.edges)


# ---------------------------------------------------------------------------
# Phase 2B — same_bio
# ---------------------------------------------------------------------------


def test_three_platforms_same_bio_get_same_bio_edges() -> None:
    result = _result(
        _finding("github", username="johndoe", metadata={"bio": _SHARED_BIO}),
        _finding("twitter", username="johndoe", metadata={"bio": _SHARED_BIO}),
        _finding("linkedin", username="johndoe", metadata={"bio": _SHARED_BIO}),
    )

    graph = IdentityGraph.build(result)

    same_bio = [e for e in graph.edges if e.type == "same_bio"]
    linked = {nid for e in same_bio for nid in (e.source, e.target)}

    assert len(linked) == 3
    assert len(same_bio) == 3


def test_same_bio_edge_carries_metadata() -> None:
    result = _result(
        _finding("github", username="johndoe", metadata={"bio": _SHARED_BIO}),
        _finding("twitter", username="johndoe", metadata={"bio": _SHARED_BIO}),
        _finding("linkedin", username="johndoe", metadata={"bio": _SHARED_BIO}),
    )

    graph = IdentityGraph.build(result)

    same_bio = [e for e in graph.edges if e.type == "same_bio"]
    assert same_bio
    meta = same_bio[0].metadata
    assert "similarity_score" in meta
    assert "bio_excerpt" in meta
    assert meta["cluster_size"] == 3


def test_cluster_confidence_boosts_same_bio_1_4x() -> None:
    result = _result(
        _finding("github", username="johndoe", metadata={"bio": _SHARED_BIO}),
        _finding("twitter", username="johndoe", metadata={"bio": _SHARED_BIO}),
        _finding("linkedin", username="johndoe", metadata={"bio": _SHARED_BIO}),
    )

    graph = IdentityGraph.build(result)
    confidence = graph.cluster_confidence()

    assert confidence
    top = max(confidence, key=lambda x: x["confidence"])
    assert any("bio" in r for r in top["reasoning"])
    assert any("1.4" in r for r in top["reasoning"])


def test_stacking_avatar_and_bio_boosts() -> None:
    """same_avatar and same_bio boosts stack: combined score hits cap (1.0)."""
    result = _result(
        _finding(
            "github",
            username="johndoe",
            photo_url=_SHARED_AVATAR,
            metadata={"bio": _SHARED_BIO},
        ),
        _finding(
            "twitter",
            username="johndoe",
            photo_url=_SHARED_AVATAR,
            metadata={"bio": _SHARED_BIO},
        ),
        _finding(
            "linkedin",
            username="johndoe",
            photo_url=_SHARED_AVATAR,
            metadata={"bio": _SHARED_BIO},
        ),
    )

    graph = IdentityGraph.build(result)

    assert any(e.type == "same_avatar" for e in graph.edges)
    assert any(e.type == "same_bio" for e in graph.edges)

    confidence = graph.cluster_confidence()
    assert confidence
    top = max(confidence, key=lambda x: x["confidence"])
    # username(0.30) + photo(0.20) = 0.50 × 1.5 (avatar) × 1.4 (bio) = 1.05 → capped at 1.0
    assert top["confidence"] == 1.0


def test_stacking_all_three_boosts_caps_at_one() -> None:
    """avatar (1.5×) + bio (1.4×) + temporal (1.3×) stack to 2.73× → capped at 1.0."""
    base = datetime(2022, 1, 1, tzinfo=timezone.utc)
    result = _result(
        _finding(
            "github",
            username="johndoe",
            photo_url=_SHARED_AVATAR,
            metadata={"bio": _SHARED_BIO, "created_at": base.isoformat()},
        ),
        _finding(
            "twitter",
            username="johndoe",
            photo_url=_SHARED_AVATAR,
            metadata={"bio": _SHARED_BIO, "created_at": (base + _td(days=10)).isoformat()},
        ),
        _finding(
            "linkedin",
            username="johndoe",
            photo_url=_SHARED_AVATAR,
            metadata={"bio": _SHARED_BIO, "created_at": (base + _td(days=20)).isoformat()},
        ),
        _finding(
            "reddit",
            username="johndoe",
            photo_url=_SHARED_AVATAR,
            metadata={"bio": _SHARED_BIO, "created_at": (base + _td(days=30)).isoformat()},
        ),
        _finding(
            "stackoverflow",
            username="johndoe",
            photo_url=_SHARED_AVATAR,
            metadata={"bio": _SHARED_BIO, "created_at": (base + _td(days=40)).isoformat()},
        ),
    )

    graph = IdentityGraph.build(result)

    assert any(e.type == "same_avatar" for e in graph.edges)
    assert any(e.type == "same_bio" for e in graph.edges)
    assert any(e.type == "same_signup_window" for e in graph.edges)

    confidence = graph.cluster_confidence()
    assert confidence
    top = max(confidence, key=lambda x: x["confidence"])
    # Raw would be: 0.50 base × 1.5 avatar × 1.4 bio × 1.3 temporal = 1.365 → clamp at 1.0
    assert top["confidence"] == 1.0
    # Verify all three boost reasons appear in reasoning
    reasoning = " ".join(top["reasoning"])
    assert "avatar" in reasoning
    assert "bio" in reasoning
    assert "signup window" in reasoning


def test_two_platforms_same_bio_below_threshold_no_edges() -> None:
    """Only 2 platforms → cluster_size < 3 → no same_bio edges added."""
    result = _result(
        _finding("github", metadata={"bio": _SHARED_BIO}),
        _finding("twitter", metadata={"bio": _SHARED_BIO}),
    )

    graph = IdentityGraph.build(result)
    assert not any(e.type == "same_bio" for e in graph.edges)


def test_bio_extracted_from_description_key() -> None:
    bio = "Data scientist | ML researcher | Python nerd | she/her"
    result = _result(
        _finding("github", username="alice", metadata={"description": bio}),
        _finding("twitter", username="alice", metadata={"description": bio}),
        _finding("linkedin", username="alice", metadata={"description": bio}),
    )

    graph = IdentityGraph.build(result)
    assert any(e.type == "same_bio" for e in graph.edges)


def test_same_bio_included_in_cluster_detection() -> None:
    """same_bio edges contribute to _identify_clusters, merging platform nodes."""
    result = _result(
        _finding("github", metadata={"bio": _SHARED_BIO}),
        _finding("twitter", metadata={"bio": _SHARED_BIO}),
        _finding("linkedin", metadata={"bio": _SHARED_BIO}),
    )

    graph = IdentityGraph.build(result)

    # _identify_clusters uses same_bio — all 3 platforms end up in one cluster
    assert any(len(c) >= 3 for c in graph.clusters)


# ---------------------------------------------------------------------------
# Phase 2E — same_signup_window (temporal clustering)
# ---------------------------------------------------------------------------

from datetime import datetime, timezone, timedelta as _td


def _d(year: int, month: int = 1, day: int = 1) -> str:
    return datetime(year, month, day, tzinfo=timezone.utc).isoformat()


def test_five_platforms_within_window_get_signup_edges() -> None:
    base = datetime(2022, 1, 1, tzinfo=timezone.utc)
    result = _result(
        _finding("github", metadata={"created_at": (base).isoformat()}),
        _finding("twitter", metadata={"created_at": (base + _td(days=10)).isoformat()}),
        _finding("linkedin", metadata={"created_at": (base + _td(days=20)).isoformat()}),
        _finding("reddit", metadata={"created_at": (base + _td(days=30)).isoformat()}),
        _finding("stackoverflow", metadata={"created_at": (base + _td(days=40)).isoformat()}),
    )

    graph = IdentityGraph.build(result)

    signup_edges = [e for e in graph.edges if e.type == "same_signup_window"]
    # C(5,2) = 10 pairwise edges for a 5-platform cluster
    assert len(signup_edges) == 10


def test_signup_edge_carries_temporal_metadata() -> None:
    base = datetime(2022, 1, 1, tzinfo=timezone.utc)
    result = _result(
        _finding("github", metadata={"created_at": (base).isoformat()}),
        _finding("twitter", metadata={"created_at": (base + _td(days=10)).isoformat()}),
        _finding("linkedin", metadata={"created_at": (base + _td(days=20)).isoformat()}),
        _finding("reddit", metadata={"created_at": (base + _td(days=30)).isoformat()}),
        _finding("stackoverflow", metadata={"created_at": (base + _td(days=40)).isoformat()}),
    )

    graph = IdentityGraph.build(result)

    signup_edges = [e for e in graph.edges if e.type == "same_signup_window"]
    assert signup_edges
    meta = signup_edges[0].metadata
    assert "earliest" in meta
    assert "latest" in meta
    assert "span_days" in meta
    assert "score" in meta
    assert "cluster_size" in meta


def test_no_signup_edges_when_fewer_than_five_platforms() -> None:
    """Minimum cluster size is 5; 4 platforms should produce no edges."""
    base = datetime(2022, 1, 1, tzinfo=timezone.utc)
    result = _result(
        _finding("github", metadata={"created_at": (base).isoformat()}),
        _finding("twitter", metadata={"created_at": (base + _td(days=5)).isoformat()}),
        _finding("linkedin", metadata={"created_at": (base + _td(days=10)).isoformat()}),
        _finding("reddit", metadata={"created_at": (base + _td(days=15)).isoformat()}),
    )

    graph = IdentityGraph.build(result)
    assert not any(e.type == "same_signup_window" for e in graph.edges)


def test_temporal_cluster_boosts_confidence() -> None:
    base = datetime(2022, 1, 1, tzinfo=timezone.utc)
    result = _result(
        _finding("github", username="user", metadata={"created_at": (base).isoformat()}),
        _finding("twitter", username="user", metadata={"created_at": (base + _td(days=10)).isoformat()}),
        _finding("linkedin", username="user", metadata={"created_at": (base + _td(days=20)).isoformat()}),
        _finding("reddit", username="user", metadata={"created_at": (base + _td(days=30)).isoformat()}),
        _finding("stackoverflow", username="user", metadata={"created_at": (base + _td(days=40)).isoformat()}),
    )

    graph = IdentityGraph.build(result)
    confidence = graph.cluster_confidence()
    assert confidence
    top = max(confidence, key=lambda x: x["confidence"])
    assert any("signup window" in r for r in top["reasoning"])


def test_signup_window_included_in_cluster_detection() -> None:
    """same_signup_window edges contribute to _identify_clusters."""
    base = datetime(2022, 1, 1, tzinfo=timezone.utc)
    result = _result(
        _finding("p1", metadata={"created_at": (base).isoformat()}),
        _finding("p2", metadata={"created_at": (base + _td(days=5)).isoformat()}),
        _finding("p3", metadata={"created_at": (base + _td(days=10)).isoformat()}),
        _finding("p4", metadata={"created_at": (base + _td(days=15)).isoformat()}),
        _finding("p5", metadata={"created_at": (base + _td(days=20)).isoformat()}),
    )

    graph = IdentityGraph.build(result)
    # All 5 platforms should end up in one cluster via same_signup_window
    assert any(len(c) >= 5 for c in graph.clusters)


# ---------------------------------------------------------------------------
# Phase 2E — shadow_findings
# ---------------------------------------------------------------------------


def test_shadow_profiles_emitted_in_graph_findings() -> None:
    result = _result(
        _finding("twitter", display_name="John Smith", email="john@gmail.com", username="jsmith"),
        _finding("steam", display_name="John Smith", email="john@protonmail.com", username="jsmith"),
    )

    graph = IdentityGraph.build(result)

    assert graph.shadow_findings
    sf = graph.shadow_findings[0]
    assert sf["type"] == "shadow_profile"
    assert sf["primary_email"] == "john@gmail.com"
    assert sf["shadow_email"] == "john@protonmail.com"


def test_shadow_findings_in_to_dict() -> None:
    result = _result(
        _finding("twitter", display_name="Jane Doe", email="jane@gmail.com"),
        _finding("reddit", display_name="Jane Doe", email="jane@protonmail.com"),
    )

    graph = IdentityGraph.build(result)
    d = graph.to_dict()
    assert "shadow_findings" in d


def test_no_shadow_findings_when_same_email() -> None:
    result = _result(
        _finding("twitter", display_name="John Smith", email="same@gmail.com"),
        _finding("steam", display_name="John Smith", email="same@gmail.com"),
    )

    graph = IdentityGraph.build(result)
    assert graph.shadow_findings == []


def test_anchor_email_excluded_from_shadow_findings() -> None:
    """The investigation target email should not appear in shadow pairs."""
    result = _result(
        _finding("twitter", display_name="Jane Doe", email="test@example.com"),
        _finding("reddit", display_name="Jane Doe", email="jane@protonmail.com"),
        email="test@example.com",
    )

    graph = IdentityGraph.build(result)
    # The anchor (test@example.com) should be excluded from shadow pairs
    for sf in graph.shadow_findings:
        assert sf.get("primary_email") != "test@example.com"
        assert sf.get("shadow_email") != "test@example.com"
