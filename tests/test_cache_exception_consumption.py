import asyncio

import pytest

from backend.core.concurrent_fetch_cache import ConcurrentFetchCache


class ErrorSession:
    async def get(self, url):
        raise RuntimeError("network failure")


@pytest.mark.asyncio
async def test_cache_consumes_unawaited_shared_exception():
    cache = ConcurrentFetchCache(ErrorSession())
    with pytest.raises(RuntimeError):
        await cache.get("https://acme.org/")
    await asyncio.sleep(0)
    await cache.aclose()
