"""Pytest plugin: block outbound (non-local) network so the suite is hermetic.

Load with ``-p eval.harness.no_network``. Tests that attempt real network I/O
fail fast with a clear error instead of hanging, so the full suite terminates
deterministically and every failure can be catalogued. Localhost/loopback is
allowed (some tests spin a local HTTP server via the shared fixtures).

This is BASELINE TOOLING — it is not part of ``tests/`` and changes no test
code. It produces the "hermetic/offline" failing set, which is also what a CI
clean-room (no outbound reachability to third-party services) sees.
"""
from __future__ import annotations

import socket

_ALLOWED_PREFIXES = ("127.", "::1", "0.0.0.0")
_ALLOWED_HOSTS = {"localhost", "", None}

_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_getaddrinfo = socket.getaddrinfo


def _host_of(address: object) -> str:
    if isinstance(address, tuple) and address:
        return str(address[0])
    return str(address)


def _is_local(host: str) -> bool:
    if host in _ALLOWED_HOSTS:
        return True
    return any(host.startswith(p) for p in _ALLOWED_PREFIXES)


class BlockedNetworkError(ConnectionError):
    pass


def _guard_connect(self, address, *args, **kwargs):  # noqa: ANN001
    host = _host_of(address)
    if not _is_local(host):
        raise BlockedNetworkError(f"[no_network] blocked connect to {host}")
    return _real_connect(self, address, *args, **kwargs)


def _guard_connect_ex(self, address, *args, **kwargs):  # noqa: ANN001
    host = _host_of(address)
    if not _is_local(host):
        raise BlockedNetworkError(f"[no_network] blocked connect_ex to {host}")
    return _real_connect_ex(self, address, *args, **kwargs)


def _guard_getaddrinfo(host, *args, **kwargs):  # noqa: ANN001
    if not _is_local(str(host)):
        raise socket.gaierror(f"[no_network] blocked DNS resolution for {host}")
    return _real_getaddrinfo(host, *args, **kwargs)


def pytest_configure(config) -> None:  # noqa: ANN001
    socket.socket.connect = _guard_connect
    socket.socket.connect_ex = _guard_connect_ex
    socket.getaddrinfo = _guard_getaddrinfo


def pytest_unconfigure(config) -> None:  # noqa: ANN001
    socket.socket.connect = _real_connect
    socket.socket.connect_ex = _real_connect_ex
    socket.getaddrinfo = _real_getaddrinfo
