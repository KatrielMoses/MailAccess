import asyncio

import pytest

from backend.core.concurrent_fetch_cache import ConcurrentFetchCache


class CancelSession:
    async def get(self, url):
        raise asyncio.CancelledError()


@pytest.mark.asyncio
async def test_cancelled_winner_cancels_shared_future():
    cache = ConcurrentFetchCache(CancelSession())
    with pytest.raises(asyncio.CancelledError):
        await cache.get("https://acme.org/")
    assert cache._in_flight["https://acme.org/"] .cancelled()
    await cache.aclose()
