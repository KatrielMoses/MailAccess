from __future__ import annotations

import pytest

from backend.config import settings
from backend.core.proxy import _UA_POOL, ProxyConfig


def _configure(
    monkeypatch: pytest.MonkeyPatch,
    *,
    enabled: bool,
    url: str | None,
) -> None:
    monkeypatch.setattr(settings, "proxy_enabled", enabled)
    monkeypatch.setattr(settings, "proxy_url", url)


def test_proxy_config_disabled_when_setting_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch, enabled=False, url="http://127.0.0.1:8080")
    config = ProxyConfig()

    assert config.is_enabled is False
    assert config.proxy_url() is None


def test_proxy_config_disabled_when_url_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, enabled=True, url=None)

    assert ProxyConfig().is_enabled is False


def test_proxy_config_enabled_with_url(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://proxy.example:8443"
    _configure(monkeypatch, enabled=True, url=url)
    config = ProxyConfig()

    assert config.is_enabled is True
    assert config.proxy_url() == url


def test_proxy_config_validates_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, enabled=True, url="ftp://proxy.example")

    with pytest.raises(ValueError, match="Unsupported proxy scheme"):
        ProxyConfig()


@pytest.mark.parametrize("scheme", ["socks5", "socks4", "http", "https"])
def test_proxy_config_accepts_valid_schemes(
    scheme: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure(monkeypatch, enabled=True, url=f"{scheme}://proxy.example:1080")

    assert ProxyConfig().is_enabled is True


def test_proxy_config_tor_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, enabled=True, url="socks5://127.0.0.1:9050")

    assert ProxyConfig().is_tor is True


def test_proxy_config_non_tor_socks5(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, enabled=True, url="socks5://1.2.3.4:1080")

    assert ProxyConfig().is_tor is False


def test_random_ua_returns_from_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, enabled=False, url=None)
    config = ProxyConfig()

    assert all(config.random_ua() in _UA_POOL for _ in range(100))


def test_random_ua_distribution(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, enabled=False, url=None)
    config = ProxyConfig()

    assert len({config.random_ua() for _ in range(1_000)}) > 1


# ── H5: async httpx for proxy verification ────────────────────────────────────────


def test_verify_script_uses_async_httpx() -> None:
    """H5: verify_residential_proxy.py must use httpx.AsyncClient, not httpx.get.

    The script at scripts/verify_residential_proxy.py uses httpx.AsyncClient
    (confirmed at lines 56, 67, 77). This test ensures the script is never
    refactored to use httpx.get (sync) in its async main() function.
    """
    import ast
    from pathlib import Path

    script_path = Path(__file__).parents[1] / "scripts" / "verify_residential_proxy.py"
    with open(script_path) as fh:
        source = fh.read()

    tree = ast.parse(source)

    # Collect all httpx.get / httpx.post / httpx.put calls (sync)
    sync_calls: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_str = ""
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "httpx":
                    call_str = f"httpx.{node.func.attr}"
            if call_str and not call_str.startswith("httpx.AsyncClient"):
                sync_calls.append(call_str)

    assert sync_calls == [], (
        f"H5 regression: proxy verification script must not use sync httpx calls. "
        f"Found: {sync_calls}. Use httpx.AsyncClient instead."
    )

