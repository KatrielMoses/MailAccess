from __future__ import annotations

from backend.core.profile_extractor import extract_profile


def test_extracts_name_and_bio_from_open_graph() -> None:
    html = (
        '<meta property="og:title" content="Maya Larsson">'
        '<meta property="og:description" content="Coffee enthusiast and dev.">'
        '<meta property="og:image" content="https://cdn.test/maya.png">'
    )
    out = extract_profile(html, "https://social.test/maya")
    assert out["display_name"] == "Maya Larsson"
    assert out["bio"] == "Coffee enthusiast and dev."
    assert out["avatar_url"] == "https://cdn.test/maya.png"


def test_open_graph_title_strips_handle_artifact() -> None:
    # og:title carries the same "(@handle) · Site" artifacts as <title>; they must be
    # stripped on every branch (not just the <title> fallback) or the padded string
    # leaks into name-consensus and overwrites the real name.
    html = '<meta property="og:title" content="Maya Larsson (@maya) · GitHub">'
    out = extract_profile(html, "https://github.com/maya")
    assert out["display_name"] == "Maya Larsson"


def test_title_fallback_strips_site_suffix_and_handle() -> None:
    html = "<title>Maya Larsson (@maya) · GitHub</title>"
    out = extract_profile(html, "https://github.com/maya")
    assert out["display_name"] == "Maya Larsson"


def test_placeholder_display_name_is_rejected() -> None:
    # A probe-hit display name feeds name-consensus as a person-name candidate, so a
    # placeholder like "Jane Doe" must be gated out rather than promoted to a name.
    html = '<meta property="og:title" content="Jane Doe">'
    assert "display_name" not in extract_profile(html, "https://social.test/jane")


def test_jsonld_name_and_location() -> None:
    html = (
        '<script type="application/ld+json">'
        '{"@type":"Person","name":"Carlos Ruiz",'
        '"address":{"addressLocality":"Madrid"}}'
        "</script>"
    )
    out = extract_profile(html, "https://prof.test/carlos")
    assert out["display_name"] == "Carlos Ruiz"
    assert out["location"] == "Madrid"


def test_junk_title_is_rejected() -> None:
    assert extract_profile("<title>Page not found</title>", "https://x.test/nope") == {}


def test_never_raises_on_garbage() -> None:
    assert extract_profile("", "https://x.test") == {}
    assert extract_profile("<meta property=og:title content=broken", "https://x.test") == {}
    assert extract_profile(None, "") == {}  # type: ignore[arg-type]


def test_non_http_avatar_dropped() -> None:
    html = '<meta property="og:image" content="/relative/avatar.png">'
    out = extract_profile(html, "https://x.test/u")
    assert "avatar_url" not in out
