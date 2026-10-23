from __future__ import annotations

import pytest

import cli.main as cli_main
from backend.api.routes import investigations as investigation_routes
from backend.exporters import EXPORTERS
from backend.exporters.html_exporter import HtmlExporter
from cli.main import _EXPORT_FORMATS, _EXT_TO_FORMAT


def _report(**overrides: object) -> dict:
    data: dict = {
        "email": "analyst@example.com",
        "created_at": "2026-10-23T12:00:00+00:00",
        "exposure_score": 42,
        "risk_level": "medium",
        "credential_risk_score": 11,
        "credential_risk_band": "LOW",
        "summary": "Two modules ran.",
        "defenders_brief": {
            "risk_level": "MEDIUM",
            "risk_summary": "Mailbox showed up in one breach.",
            "top_findings": [
                {
                    "title": "Adobe 2013",
                    "severity": "high",
                    "detail": "Email in a credential dump.",
                    "remediation": "Rotate the password.",
                }
            ],
            "next_action": "Confirm the password has been changed.",
        },
        "findings": [
            {
                "module_name": "hibp",
                "data": {
                    "platform": "HaveIBeenPwned",
                    "url": "https://haveibeenpwned.com/PwnedWebsites#Adobe",
                    "confidence": "high",
                    "metadata": {"name": "Adobe", "breach_date": "2013-10-04"},
                },
            }
        ],
        "findings_by_module": {
            "hibp": [
                {
                    "platform": "HaveIBeenPwned",
                    "url": "https://haveibeenpwned.com/PwnedWebsites#Adobe",
                    "confidence": "high",
                    "metadata": {"name": "Adobe", "breach_date": "2013-10-04"},
                }
            ]
        },
        "module_runs": [
            {
                "module_name": "hibp",
                "status": "success",
                "duration_ms": 120,
                "error": None,
            }
        ],
        "timeline": {
            "first_seen_date": "2013-10-04",
            "most_recent_date": "2013-10-04",
            "active_risk_count": 0,
            "events": [
                {
                    "date": "2013-10-04",
                    "event_type": "breach",
                    "title": "Adobe",
                    "source_module": "hibp",
                    "is_active_risk": False,
                }
            ],
        },
        "email_credibility": {"provider_family": "google"},
    }
    data.update(overrides)
    return data


def test_html_registered_as_export_format() -> None:
    assert "html" in EXPORTERS
    exporter = EXPORTERS["html"]()
    assert exporter.format_name == "html"
    assert "html" in exporter.content_type


def test_html_report_contains_sections_and_nav() -> None:
    html = HtmlExporter().export("inv-1", _report()).decode("utf-8")

    assert html.startswith("<!DOCTYPE html>")
    assert 'name="viewport"' in html
    assert "<title>MailAccess report — analyst@example.com</title>" in html
    assert "analyst@example.com" in html
    assert "42" in html
    assert "Defender's Brief" in html
    assert "Adobe 2013" in html
    assert "HaveIBeenPwned" in html
    assert 'nav class="toc"' in html
    assert 'id="defender-s-brief"' in html
    assert 'href="#defender-s-brief"' in html
    assert "Exposure Timeline" in html
    assert "Findings by Module" in html


def test_html_finding_urls_are_links() -> None:
    html = HtmlExporter().export("inv-1", _report()).decode("utf-8")
    assert 'href="https://haveibeenpwned.com/PwnedWebsites#Adobe"' in html
    assert "<a href=" in html


def test_html_escapes_untrusted_values() -> None:
    html = (
        HtmlExporter()
        .export(
            "inv-1",
            _report(
                email="<script>alert(1)</script>@example.com",
                findings_by_module={
                    "hibp": [
                        {
                            "platform": "<img src=x onerror=alert(1)>",
                            "url": "https://example.com/ok",
                            "confidence": "high",
                            "metadata": {"name": "<b>Adobe</b>"},
                        }
                    ]
                },
            ),
        )
        .decode("utf-8")
    )

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "&lt;b&gt;Adobe&lt;/b&gt;" in html


def test_html_export_does_not_import_weasyprint() -> None:
    import sys

    sys.modules.pop("weasyprint", None)
    HtmlExporter().export("inv-1", _report())
    assert "weasyprint" not in sys.modules


def test_cli_maps_html_extensions() -> None:
    assert ".html" in _EXPORT_FORMATS
    assert ".htm" in _EXPORT_FORMATS
    assert _EXT_TO_FORMAT[".html"] == "html"
    assert _EXT_TO_FORMAT[".htm"] == "html"


def test_auto_report_format_falls_back_to_html(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "_pdf_available", lambda: False)
    assert cli_main._auto_report_format() == ("html", "html", "HTML")
    monkeypatch.setattr(cli_main, "_pdf_available", lambda: True)
    assert cli_main._auto_report_format() == ("pdf", "pdf", "PDF")


@pytest.mark.asyncio
async def test_html_export_route(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Service:
        def __init__(self, _session) -> None:
            pass

        async def get_investigation(self, _investigation_id: str) -> dict:
            return _report()

    monkeypatch.setattr(investigation_routes, "InvestigationService", _Service)
    monkeypatch.setattr(investigation_routes, "enrich_report", lambda data: data)

    response = await investigation_routes.export_report(
        "investigation-id", session=object(), format="html"
    )

    assert response.status_code == 200
    assert "text/html" in response.media_type
    body = bytes(response.body).decode("utf-8")
    assert body.startswith("<!DOCTYPE html>")
    assert "analyst@example.com" in body
    disposition = response.headers["content-disposition"]
    assert disposition.endswith('.html"') or ".html" in disposition


def test_export_filename_ext_html() -> None:
    assert investigation_routes._export_filename_ext("html") == "html"
    assert investigation_routes._export_filename_ext("json") == "json"
    assert investigation_routes._export_filename_ext("stix") == "stix.json"
