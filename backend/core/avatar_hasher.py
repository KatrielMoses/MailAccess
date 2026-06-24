"""Fetch and perceptually hash avatars as 8x8 grayscale images.

The image is normalized to a tiny grayscale thumbnail before a 64-bit pHash is
computed.  The resulting 16-character hexadecimal value is resilient to common
avatar resizing, format conversion, and small colour changes.
"""

from __future__ import annotations

import asyncio
import logging
from io import BytesIO
from weakref import WeakKeyDictionary

import httpx

_LOG = logging.getLogger(__name__)
_MAX_URLS_PER_CLIENT = 20
_CACHE: dict[str, str | None] = {}
_CLIENT_URLS: WeakKeyDictionary[object, set[str]] = WeakKeyDictionary()


def phash_from_bytes(data: bytes) -> str | None:
    """Return a 64-bit pHash as hexadecimal, or ``None`` for invalid image data."""
    try:
        import imagehash
        from PIL import Image

        with Image.open(BytesIO(data)) as image:
            normalized = image.convert("L").resize((8, 8))
            return str(imagehash.phash(normalized, hash_size=8))
    except Exception as exc:
        _LOG.debug("avatar decode or pHash failed: %s", exc)
        return None


def _claim_url(client: object, avatar_url: str) -> bool:
    """Track at most 20 unique URLs for each live HTTP client object."""
    urls = _CLIENT_URLS.setdefault(client, set())
    if avatar_url in urls:
        return True
    if len(urls) >= _MAX_URLS_PER_CLIENT:
        _LOG.warning(
            "avatar fetch limit reached for client session (%d URLs)", _MAX_URLS_PER_CLIENT
        )
        return False
    urls.add(avatar_url)
    return True


async def fetch_and_phash(avatar_url: str, client: httpx.AsyncClient) -> str | None:
    """Fetch and pHash an avatar, with a 20-unique-URL limit per client session."""
    if avatar_url in _CACHE:
        return _CACHE[avatar_url]
    if not _claim_url(client, avatar_url):
        return None

    try:
        response = await client.get(avatar_url)
        if response.status_code != 200:
            _LOG.debug("avatar fetch returned HTTP %s for %s", response.status_code, avatar_url)
            result = None
        elif not response.headers.get("content-type", "").lower().startswith("image/"):
            _LOG.debug("avatar response was not an image: %s", avatar_url)
            result = None
        else:
            # PIL + imagehash are CPU-bound; run in a thread pool so they don't
            # block the asyncio event loop.
            result = await asyncio.to_thread(phash_from_bytes, response.content)
    except Exception as exc:
        _LOG.debug("avatar fetch failed for %s: %s", avatar_url, exc)
        result = None

    _CACHE[avatar_url] = result
    return result


def _fetch_phashes(avatar_urls: list[str]) -> dict[str, str | None]:
    """Synchronously hash URLs for callers whose public API is synchronous."""
    results: dict[str, str | None] = {}
    pending = list(dict.fromkeys(url for url in avatar_urls if url not in _CACHE))
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            for url in pending:
                if not _claim_url(client, url):
                    results[url] = None
                    continue
                try:
                    response = client.get(url)
                    if response.status_code != 200:
                        value = None
                    elif not response.headers.get("content-type", "").lower().startswith("image/"):
                        value = None
                    else:
                        value = phash_from_bytes(response.content)
                except Exception as exc:
                    _LOG.debug("avatar fetch failed for %s: %s", url, exc)
                    value = None
                _CACHE[url] = value
                results[url] = value
    except Exception as exc:
        _LOG.debug("avatar client setup failed: %s", exc)
        results.update({url: None for url in pending})
    results.update({url: _CACHE.get(url) for url in avatar_urls if url not in results})
    return results
