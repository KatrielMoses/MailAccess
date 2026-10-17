"""No test may touch the real ~/.mailaccess (it holds the developer's paid API keys)."""

import os
from pathlib import Path

from tests import conftest


def test_home_is_the_temp_home_not_the_real_one():
    assert Path.home().resolve() == conftest._TEST_HOME
    assert Path.home().resolve() != conftest._REAL_HOME
    assert os.environ["HOME"] == str(conftest._TEST_HOME)
    assert (conftest._TEST_HOME / ".mailaccess").is_dir()


def test_cli_files_sit_under_the_temp_home():
    import cli.main as main
    import cli.sponsor_feed as sponsor_feed
    import cli.update_check as update_check

    for path in (main.ENV_FILE, main._ENV_FILE, update_check._CACHE_FILE, sponsor_feed._CACHE_FILE):
        resolved = Path(path).resolve()
        assert resolved.is_relative_to(conftest._TEST_HOME / ".mailaccess"), resolved
        assert not resolved.is_relative_to(conftest._REAL_HOME / ".mailaccess"), resolved


def test_real_database_guard_still_points_at_the_real_home():
    assert conftest._REAL_DB == (conftest._REAL_HOME / ".mailaccess" / "mailaccess.db").resolve()
    assert not str(conftest._REAL_DB).startswith(str(conftest._TEST_HOME))


def test_set_key_commands_write_only_into_the_temp_home(monkeypatch):
    """Without mocking _set_env_key: the real code path must land in the temp .env."""
    from typer.testing import CliRunner

    import cli.main as main

    env_file = conftest._TEST_HOME / ".mailaccess" / ".env"
    before = env_file.read_text() if env_file.exists() else ""
    runner = CliRunner()
    for command in ("whoisfreaks", "netlas", "ipgeo"):
        result = runner.invoke(main.app, [command, "set-key", f"isolation-test-{command}"])
        assert result.exit_code == 0, (command, result.output)
    text = env_file.read_text()
    for name in ("WHOISFREAKS_API_KEY", "NETLAS_API_KEY", "IPGEOLOCATION_API_KEY"):
        assert f"{name}=" in text
    assert Path(main.ENV_FILE).resolve() == env_file.resolve()
    assert not (conftest._REAL_HOME / ".mailaccess" / ".env").read_text().count("isolation-test") \
        if (conftest._REAL_HOME / ".mailaccess" / ".env").exists() else True
    env_file.write_text(before)  # leave the temp home as found for later tests


def test_concurrent_runs_never_share_a_home():
    """Sentinel: each pytest process writes its own marker into its temp home and must see
    no marker from any other process, and none may appear under the real ~/.mailaccess.
    Run two suites at once to prove isolation; either one failing means homes are shared."""
    import time

    home = conftest._TEST_HOME / ".mailaccess"
    mine = home / f"isolation-sentinel-{os.getpid()}"
    mine.write_text(str(os.getpid()))
    try:
        time.sleep(0.5)  # widen the window in which a concurrent run could collide
        others = [p.name for p in home.glob("isolation-sentinel-*") if p != mine]
        assert others == [], f"another test process shares this home: {others}"
        real = conftest._REAL_HOME / ".mailaccess"
        assert not list(real.glob("isolation-sentinel-*")) if real.is_dir() else True
    finally:
        mine.unlink(missing_ok=True)
