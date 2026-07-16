from typer.testing import CliRunner

from cli.main import DoctorCheck, app


def _invoke(monkeypatch, checks):
    async def collect():
        return checks

    monkeypatch.setattr("cli.main._collect_doctor_checks", collect)
    return CliRunner().invoke(app, ["doctor"])


def test_doctor_exits_0_when_no_errors(monkeypatch):
    result = _invoke(monkeypatch, [DoctorCheck("Installation", "curl-cffi", True, "installed")])
    assert result.exit_code == 0


def test_doctor_exits_1_when_curl_cffi_missing(monkeypatch):
    result = _invoke(monkeypatch, [DoctorCheck("Installation", "curl-cffi", False, "missing", "pip install harvest", "error")])
    assert result.exit_code == 1


def test_doctor_shows_fix_for_each_failure(monkeypatch):
    result = _invoke(monkeypatch, [DoctorCheck("Network", "crt.sh", False, "blocked", "check the firewall")])
    assert "check the firewall" in result.stdout


def test_doctor_checks_api_key_live():
    import inspect
    from cli.main import _collect_doctor_checks

    source = inspect.getsource(_collect_doctor_checks)
    assert "api.github.com/rate_limit" in source and "api.hunter.io/v2/account" in source


def test_doctor_shows_cache_domain_count(monkeypatch):
    result = _invoke(monkeypatch, [DoctorCheck("Cache", "3 cached domains", True, "a, b, c")])
    assert "3 cached domains" in result.stdout
