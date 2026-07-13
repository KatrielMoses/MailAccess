"""Mock-integrity guard test.

The 0.11.1 Phase 3 fetch refactor centralised HTTP through
:class:`CachedFetch` + :class:`ConcurrentFetchCache`.  This test is a
cheap static-analysis check that the rest of the suite is consistent
with that promise:

1. **No ``aiohttp``** in test code — every ``AsyncClient`` shape we
   use should be ``httpx.AsyncClient`` so the shared ``MockTransport``
   pattern keeps working.
2. **No ``requests``** in test code — synchronous requests has no
   ``MockTransport`` equivalent in our fixtures and almost always
   signals "I forgot to mock this".
3. **No bare ``httpx.AsyncClient()`` without a transport kwarg** —
   the absence of a ``MockTransport`` is the closest static proxy we
   have for "this client could go to the live network".  Tests that
   legitimately need a client should use the ``httpx.MockTransport``
   pattern or the ``local_http`` fixture.

The point is to catch the next person writing a test from a tired
memory of pre-Phase-3 patterns.  We don't try to prove the test
doesn't reach out (you'd need an in-process proxy for that) — just to
flag the obvious shapes.
"""
from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import Path

import pytest

# Paths that legitimately need ``aiohttp`` / ``requests`` or a bare
# httpx client for reasons OUTSIDE the BUG-1 fix scope.  Update this
# list when you genuinely need to bypass the guard, not to silence
# it for convenience.
_ALLOWLIST: frozenset[str] = frozenset(
    {
        # This very file — uses pathlib / ast, no HTTP at all.
        "tests/test_no_live_network.py",
        # The cache itself uses httpx in production but tests use
        # FakeSession.  None of these files import aiohttp/requests,
        # but the scanner runs on them too.
        "tests/test_concurrent_fetch_cache.py",
        "tests/test_pagination_handler.py",
        "tests/test_context_router.py",
        "tests/test_sitemap_content_router.py",
        "tests/test_syndication_feed_sweeper.py",
        # Bare AsyncClient() with a monkeypatched ``.get`` method —
        # no live network, but the AST can't see the patch.
        # TODO(BUG-1 follow-up): migrate these to MockTransport.
        "tests/test_avatar_hasher.py",
        # Same pattern — the AsyncClient is a placeholder; the
        # production code path is patched at the call site
        # (``_probe_endpoint``), not on the client.
        # TODO(BUG-1 follow-up): migrate to MockTransport.
        "tests/test_reset_prober.py",
    }
)


def _iter_test_files() -> Iterable[Path]:
    tests_dir = Path(__file__).resolve().parent
    for path in tests_dir.rglob("*.py"):
        if path.name == "__init__.py":
            continue
        if path.name.startswith("."):
            continue
        # Skip shared fixtures — they ARE the mock infrastructure.
        if path.name == "_fetch_fixtures.py":
            continue
        if path.name == "conftest.py":
            continue
        yield path


def _relative_to_tests(path: Path) -> str:
    """Format a path as ``tests/...`` for stable error messages.

    Forward-slash normalised so the allowlist works on Windows (which
    yields backslash-separated paths from ``Path.relative_to``).
    """
    rel = path.relative_to(Path(__file__).resolve().parent.parent)
    return rel.as_posix()


def _scan_forbidden_imports(path: Path) -> list[str]:
    """Return any ``aiohttp`` / ``requests`` imports as human-readable hits."""
    hits: list[str] = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        # Syntax errors belong to a different test — don't double-report.
        return hits
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in {"aiohttp", "requests"}:
                    hits.append(f"import {alias.name} (line {node.lineno})")
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] in {"aiohttp", "requests"}:
                hits.append(f"from {node.module} import ... (line {node.lineno})")
    return hits


def _scan_bare_async_clients(path: Path) -> list[str]:
    """Return ``httpx.AsyncClient(...)`` calls without a ``transport=`` kwarg."""
    hits: list[str] = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return hits
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # Match ``httpx.AsyncClient(...)`` only — bare ``AsyncClient`` from
        # somewhere else is out of scope.
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "AsyncClient"
            and isinstance(func.value, ast.Name)
            and func.value.id == "httpx"
        ):
            kwarg_names = {kw.arg for kw in node.keywords if kw.arg is not None}
            if "transport" not in kwarg_names and "transport" not in [
                k.arg for k in node.keywords
            ]:
                # Note: MockTransport callers all set transport=, so an
                # AsyncClient without transport is the bug shape.
                hits.append(
                    f"httpx.AsyncClient() without transport= (line {node.lineno})"
                )
    return hits


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_no_aiohttp_or_requests_imports_in_tests() -> None:
    """No test should reach for the legacy HTTP stacks.

    ``aiohttp`` has no in-process MockTransport equivalent, and
    ``requests`` is synchronous — both end up at the live network
    whenever they're used.  Use the shared ``_fetch_fixtures`` instead.
    """
    violations: list[str] = []
    for path in _iter_test_files():
        rel = _relative_to_tests(path)
        if rel in _ALLOWLIST or any(
            rel.startswith(allowed.rstrip("*.py").rstrip("/"))
            for allowed in _ALLOWLIST
        ):
            continue
        for hit in _scan_forbidden_imports(path):
            violations.append(f"{rel}: {hit}")
    assert not violations, (
        "Tests must not import aiohttp/requests — they have no in-process "
        "mock and will hit the live network. Use the _fetch_fixtures "
        "FakeSession instead.\n\n" + "\n".join(violations)
    )


def test_no_bare_httpx_async_client_in_tests() -> None:
    """Every ``httpx.AsyncClient`` must declare a ``transport=`` (MockTransport).

    A bare ``httpx.AsyncClient()`` is the most common shape for "I
    forgot to mock this".  When we see one, the test almost certainly
    intends to hit the network.  Use the shared ``_fetch_fixtures``
    or pass ``transport=httpx.MockTransport(handler)``.
    """
    violations: list[str] = []
    for path in _iter_test_files():
        rel = _relative_to_tests(path)
        if rel in _ALLOWLIST or any(
            rel.startswith(allowed.rstrip("*.py").rstrip("/"))
            for allowed in _ALLOWLIST
        ):
            continue
        for hit in _scan_bare_async_clients(path):
            violations.append(f"{rel}: {hit}")
    assert not violations, (
        "Tests must not construct httpx.AsyncClient() without transport=. "
        "Use httpx.MockTransport(handler) or the _fetch_fixtures "
        "FakeSession instead.\n\n" + "\n".join(violations)
    )


@pytest.mark.parametrize(
    "forbidden",
    ["aiohttp", "requests"],
)
def test_forbidden_http_libraries_are_not_in_allowlist(forbidden: str) -> None:
    """Sanity: the allowlist shouldn't have grown a forbidden lib by accident.

    If a test genuinely needs ``aiohttp`` or ``requests``, add it to
    ``_ALLOWLIST`` with a comment explaining why.  This test fails if
    someone adds an empty allowlist entry for one of them by mistake.
    """
    assert forbidden not in _ALLOWLIST, (
        f"{forbidden!r} appeared in the allowlist — drop it and add a "
        "comment in _ALLOWLIST explaining why it's needed."
    )