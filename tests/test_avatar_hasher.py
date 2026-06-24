from __future__ import annotations

import io

import pytest


def _png_bytes(color: int = 128) -> bytes:
    """Generate minimal 8x8 grayscale PNG bytes for testing."""
    from PIL import Image

    img = Image.new("L", (8, 8), color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_phash_returns_16_char_hex_for_valid_image() -> None:
    from backend.core.avatar_hasher import phash_from_bytes

    result = phash_from_bytes(_png_bytes())

    assert result is not None
    assert len(result) == 16
    assert all(c in "0123456789abcdef" for c in result)


def test_phash_stability_same_bytes_same_hash() -> None:
    from backend.core.avatar_hasher import phash_from_bytes

    data = _png_bytes(color=200)

    assert phash_from_bytes(data) == phash_from_bytes(data)


def test_phash_returns_none_for_non_image_bytes() -> None:
    from backend.core.avatar_hasher import phash_from_bytes

    assert phash_from_bytes(b"not an image") is None
    assert phash_from_bytes(b"") is None
    assert phash_from_bytes(b"\x00" * 100) is None


def test_phash_different_images_may_differ() -> None:
    from backend.core.avatar_hasher import phash_from_bytes

    white = phash_from_bytes(_png_bytes(color=255))
    black = phash_from_bytes(_png_bytes(color=0))

    assert white is not None
    assert black is not None
    # Solid white vs solid black should differ (different pHash)
    assert white != black


def test_cache_hit_skips_network(monkeypatch: pytest.MonkeyPatch) -> None:
    import backend.core.avatar_hasher as mod

    url = "https://example.test/cached_avatar.png"
    monkeypatch.setitem(mod._CACHE, url, "deadbeef12345678")

    fetch_called = False

    async def _fake_get(*_args: object, **_kwargs: object) -> None:
        nonlocal fetch_called
        fetch_called = True
        raise AssertionError("network should not be reached for cached URL")

    import asyncio
    import httpx

    async def _run() -> str | None:
        async with httpx.AsyncClient() as client:
            monkeypatch.setattr(client, "get", _fake_get)
            return await mod.fetch_and_phash(url, client)

    result = asyncio.get_event_loop().run_until_complete(_run())

    assert result == "deadbeef12345678"
    assert not fetch_called


def test_rate_limit_at_20_urls_per_client() -> None:
    import backend.core.avatar_hasher as mod

    class _FakeClient:
        pass

    client = _FakeClient()

    for i in range(20):
        url = f"https://example.test/ratelimit_{i}.png"
        assert mod._claim_url(client, url) is True, f"URL {i} should be accepted"

    overflow = "https://example.test/ratelimit_overflow.png"
    assert mod._claim_url(client, overflow) is False

    # Existing URL is still accepted (not a new slot)
    assert mod._claim_url(client, "https://example.test/ratelimit_0.png") is True
