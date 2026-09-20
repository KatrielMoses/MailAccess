"""Root pytest configuration.

Re-exports the shared fetch-layer fixtures from :mod:`tests._fetch_fixtures`
so they're available as pytest fixtures everywhere under ``tests/``.  Module
test files can either import the helpers directly or request the fixtures
by name (``fetch_cache``, ``fake_session``) — both paths use the same
underlying objects.

Why a conftest at all:

* The ``FakeSession`` + ``make_cached_fetch`` helpers are used by 10+
  test files.  Putting them in ``_fetch_fixtures.py`` keeps them out of
  pytest's own collection (the leading underscore tells pytest to skip
  collection).
* Putting the re-exports here means a test can ask for ``fetch_cache``
  without caring which file the implementation lives in.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Hermetic test database (release-gate reproducibility).
#
# Point every test process at its OWN fresh temp SQLite DB — migrated to head by the
# session fixture below — BEFORE any ``backend`` import, so ``Settings`` and the
# import-time engine in ``backend.db.database`` bind to it. This stops the suite from
# reading/writing the developer's real ``~/.mailaccess/mailaccess.db``, whose Alembic
# revision is exactly what made the gate env-dependent: a box at a different revision
# saw failures that per-file isolation on another box did not (the "40 NEW" mirage).
# ``setdefault`` lets an explicit ``DATABASE_URL`` (e.g. CI) still win.
# ---------------------------------------------------------------------------
_HERMETIC_DB_DIR = tempfile.mkdtemp(prefix="mailaccess-test-db-")
os.environ.setdefault(
    "DATABASE_URL",
    f"sqlite+aiosqlite:///{Path(_HERMETIC_DB_DIR, 'test.db').as_posix()}",
)

# Make the tests directory importable so we can pull in the shared
# ``_fetch_fixtures`` module regardless of where pytest was invoked from.
_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

from _fetch_fixtures import (  # noqa: E402  (path-mutated import)
    FakeSession,
    LocalHttpServer,
    make_cached_fetch,
    make_cached_response,
    make_local_fetch,
)

from backend.core.concurrent_fetch_cache import (  # noqa: E402
    CachedFetch,
    ConcurrentFetchCache,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
def _hermetic_migrated_db() -> Any:
    """Migrate the per-process hermetic temp DB (set at import above) to head once,
    so DB-backed tests run against the current schema on ANY host rather than the
    developer's real ~/.mailaccess DB. DB-less files pay only the one-time cost."""
    import asyncio

    from backend.db.database import init_db

    asyncio.run(init_db())
    yield


@pytest.fixture
def fake_session() -> FakeSession:
    """Bare :class:`FakeSession` with no canned responses.

    Use this when the test wants to assert on ``call_log`` /
    ``call_count`` without dict lookups — every URL returns an empty
    200 by default.
    """
    return FakeSession()


@pytest.fixture
def fetch_cache(
    fake_session: FakeSession,
) -> tuple[CachedFetch, ConcurrentFetchCache, FakeSession]:
    """Yield ``(fetch, cache, session)`` for module tests.

    Pass ``responses_by_url=...`` via the :func:`make_cached_fetch`
    factory when you need canned bodies; the bare fixture is the
    minimal "give me a wired fetch" setup.
    """
    return make_cached_fetch(session=fake_session)


@pytest.fixture
def local_http() -> tuple[CachedFetch, ConcurrentFetchCache, LocalHttpServer]:
    """Yield ``(fetch, cache, server)`` backed by :class:`LocalHttpServer`.

    Use when the test specifically needs to drive the cache's URL
    normalisation / dedup logic against a real wire shape, rather than
    a canned lookup.  Most module tests should prefer ``fetch_cache``.
    """
    return make_local_fetch()


@pytest.fixture
def make_response() -> Any:
    """Expose :func:`make_cached_response` as a fixture for convenience."""
    return make_cached_response


__all__ = [
    "fake_session",
    "fetch_cache",
    "local_http",
    "make_response",
]