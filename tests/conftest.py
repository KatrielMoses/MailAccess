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

import atexit
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Home-folder isolation: no test may ever read or write the real ``~/.mailaccess``
# (it holds the developer's paid API keys, caches and databases).
#
# This must run at IMPORT time, before any ``backend`` / ``cli`` import: cli/main.py
# (ENV_FILE), cli/update_check.py and cli/sponsor_feed.py (_CACHE_FILE) and
# backend/config.py all fix their paths from ``Path.home()`` when first imported.
# ---------------------------------------------------------------------------
# Idempotent: a second import of this module (``from tests.conftest import ...``)
# must reuse the first run's values, not record the redirected home as the real one.
_REAL_HOME = Path(os.environ.setdefault("MAILACCESS_TEST_REAL_HOME", str(Path.home().resolve())))
if "MAILACCESS_TEST_HOME" not in os.environ:
    _fresh_home = Path(tempfile.mkdtemp(prefix="mailaccess-test-home-")).resolve()
    (_fresh_home / ".mailaccess").mkdir(mode=0o700, exist_ok=True)
    os.environ["MAILACCESS_TEST_HOME"] = str(_fresh_home)
    atexit.register(shutil.rmtree, str(_fresh_home), ignore_errors=True)
_TEST_HOME = Path(os.environ["MAILACCESS_TEST_HOME"])
os.environ["HOME"] = str(_TEST_HOME)
os.environ["USERPROFILE"] = str(_TEST_HOME)  # Windows

if Path.home().resolve() != _TEST_HOME:
    raise RuntimeError(
        f"Home-folder isolation failed: Path.home() is {Path.home()}, expected {_TEST_HOME}. "
        "Refusing to run tests that could touch the real ~/.mailaccess."
    )


def _under_real_mailaccess(path: Path) -> bool:
    try:
        return Path(path).expanduser().resolve().is_relative_to(_REAL_HOME / ".mailaccess")
    except (OSError, ValueError):
        return False


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

# Hard guard: ``setdefault`` above lets an ambient ``DATABASE_URL`` (e.g. one left
# in the shell from a live/replay run) win — which can silently point the whole
# suite at the developer's real ``~/.mailaccess/mailaccess.db``. Refuse to run
# against that DB rather than read/write it. A deliberate CI/test DB still wins.
# Compared against the REAL home recorded above: the redirected home would defeat this.
_REAL_DB = (_REAL_HOME / ".mailaccess" / "mailaccess.db").resolve()
_db_match = re.search(r"sqlite(?:\+\w+)?:///(.+)", os.environ["DATABASE_URL"])
if _db_match and Path(_db_match.group(1)).expanduser().resolve() == _REAL_DB:
    raise RuntimeError(
        f"Refusing to run tests against the real database ({_REAL_DB}). "
        "Unset DATABASE_URL (or point it at a test DB) and re-run."
    )

# Third-party provider credentials in the developer's .env (or shell) would make
# unrelated investigation/harvest tests call live, sometimes paid, APIs. Blank
# every one BEFORE any ``backend`` import, then again on the loaded ``settings``
# (a value already read stays set otherwise). Tests that need a key set it
# themselves. MailAccess's own keys (``MAILACCESS_*``) are deliberately kept.
PROVIDER_KEY_SETTINGS = (
    "netlas_api_key", "ipgeolocation_api_key", "whoisfreaks_api_key",
    "scrapingant_api_key", "scrapingant_proxy_residential_username",
    "scrapingant_proxy_residential_password", "scrapingant_proxy_datacenter_username",
    "scrapingant_proxy_datacenter_password", "proxy_url",
    "hibp_api_key", "haveibeenpwned_api_key", "breachdirectory_api_key",
    "hunter_io_api_key", "emailrep_api_key", "shodan_api_key", "serpapi_key",
    "github_token", "companies_house_api_key", "apollo_api_key", "pdl_api_key",
    "intelx_api_key", "dehashed_api_key", "snusbase_api_key", "brave_search_api_key",
    "google_cse_api_key", "google_cse_cx", "google_intel_api_key", "otx_api_key",
    "slack_webhook_url", "discord_webhook_url", "integration_webhook_url",
    "integration_webhook_secret",
    # The MailAccess Index is a live service: tests that need it set it themselves.
    "mailaccess_index_url", "mailaccess_index_key",
)
for _name in (*PROVIDER_KEY_SETTINGS, "serper_api_key"):
    os.environ[_name.upper()] = ""

# Make the tests directory importable so we can pull in the shared
# ``_fetch_fixtures`` module regardless of where pytest was invoked from.
_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

from backend.config import settings as _loaded_settings  # noqa: E402

for _name in PROVIDER_KEY_SETTINGS:
    if hasattr(_loaded_settings, _name):
        _default = "" if isinstance(getattr(_loaded_settings, _name), str) else None
        object.__setattr__(_loaded_settings, _name, _default)

# Second guard, after the imports that fix paths: the CLI's own files must sit in the
# temp home. If any is under the real ~/.mailaccess, refuse to run.
import cli.main as _cli_main  # noqa: E402
import cli.sponsor_feed as _cli_sponsor_feed  # noqa: E402
import cli.update_check as _cli_update_check  # noqa: E402

for _label, _path in (
    ("cli.main.ENV_FILE", _cli_main.ENV_FILE),
    ("cli.main._ENV_FILE", _cli_main._ENV_FILE),
    ("cli.update_check._CACHE_FILE", _cli_update_check._CACHE_FILE),
    ("cli.sponsor_feed._CACHE_FILE", _cli_sponsor_feed._CACHE_FILE),
):
    if _under_real_mailaccess(_path):
        raise RuntimeError(
            f"{_label} is {_path}, under the real ~/.mailaccess. "
            "Refusing to run tests that could touch real files."
        )

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
async def isolated_db(monkeypatch: pytest.MonkeyPatch) -> Any:
    """A private, migrated SQLite DB for one test, swapped in everywhere the app opens
    a session. Opt-in for tests that must not depend on whatever earlier tests did to
    the shared per-process database."""
    import sys

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    import backend.db.database as database

    workdir = Path(tempfile.mkdtemp(prefix="mailaccess-iso-db-"))
    engine = create_async_engine(f"sqlite+aiosqlite:///{(workdir / 'iso.db').as_posix()}")
    async with engine.begin() as conn:
        await conn.run_sync(database._apply_migrations)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    # Every module that bound a session factory at import (engine, retention, ...) gets
    # the private one, even if an earlier test already swapped some of them.
    for module in list(sys.modules.values()):
        if isinstance(getattr(module, "AsyncSessionLocal", None), async_sessionmaker):
            monkeypatch.setattr(module, "AsyncSessionLocal", factory)
    monkeypatch.setattr(database, "engine", engine)
    try:
        yield factory
    finally:
        await engine.dispose()
        shutil.rmtree(workdir, ignore_errors=True)


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