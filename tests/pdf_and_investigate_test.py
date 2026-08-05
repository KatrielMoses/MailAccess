from __future__ import annotations

import io
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from rich.console import Console

import cli.main as cli_main
from backend.api.routes import investigations as investigation_routes
from backend.exporters.pdf_exporter import PdfExporter


class _Response:
    def __init__(self, *, status_code: int = 200, content: bytes = b"", payload=None) -> None:
        self.status_code = status_code
        self.content = content
        self._payload = payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class _ExportClient:
    def __init__(self, response: _Response) -> None:
        self.response = response

    async def get(self, *_args, **_kwargs) -> _Response:
        return self.response


@pytest.mark.asyncio
async def test_pdf_export_422_on_missing_weasyprint(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Service:
        def __init__(self, _session) -> None:
            pass

        async def get_investigation(self, _investigation_id: str) -> dict:
            return {"email": "user@example.com"}

    monkeypatch.setattr(investigation_routes, "InvestigationService", _Service)
    monkeypatch.setattr(investigation_routes, "enrich_report", lambda data: data)

    async def _missing_pdf(_self, _investigation_id: str, _data: dict) -> bytes:
        raise ImportError("weasyprint unavailable")

    monkeypatch.setattr(PdfExporter, "generate", _missing_pdf)

    response = await investigation_routes.export_report(
        "investigation-id", session=object(), format="pdf"
    )

    assert response.status_code == 422
    assert json.loads(response.body) == {
        "error": "PDF export requires weasyprint.",
        "install": "pip install mailaccess[pdf]",
    }


@pytest.mark.asyncio
async def test_pdf_export_success_writes_file() -> None:
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
        output = Path(temp_dir) / "report.pdf"
        stream = io.StringIO()
        out = Console(file=stream, markup=True)

        await cli_main._save_investigate_export(
            _ExportClient(_Response(content=b"%PDF-test")),
            "investigation-id",
            "pdf",
            str(output),
            out,
        )

        assert output.read_bytes() == b"%PDF-test"
        assert "Report saved" in stream.getvalue()


@pytest.mark.asyncio
async def test_pdf_export_422_skips_without_writing_file() -> None:
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
        output = Path(temp_dir) / "report.pdf"
        stream = io.StringIO()
        out = Console(file=stream, markup=True)

        await cli_main._save_investigate_export(
            _ExportClient(_Response(status_code=422, payload={"error": "missing PDF support"})),
            "investigation-id",
            "pdf",
            str(output),
            out,
        )

        assert not output.exists()
        assert "PDF export skipped" in stream.getvalue()
        assert "pip install mailaccess[pdf]" in stream.getvalue().replace("\n", "")


class _InvestigationClient:
    async def __aenter__(self) -> _InvestigationClient:
        return self

    async def __aexit__(self, *_args) -> None:
        return None

    async def post(self, *_args, **_kwargs) -> _Response:
        return _Response(
            status_code=202,
            payload={
                "id": "investigation-id",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "cached": True,
            },
        )

    async def get(self, url: str, **_kwargs) -> _Response:
        assert url == "/api/report/investigation-id"
        return _Response(
            payload={
                "status": "complete",
                "findings": [{"module_name": "partial_module", "source": "example"}],
                "findings_by_module": {},
            }
        )


@pytest.mark.asyncio
async def test_investigate_exits_0_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main.httpx, "AsyncClient", lambda **_kwargs: _InvestigationClient())

    result = await cli_main._investigate_run(
        "user@example.com",
        "json",
        None,
        30,
        None,
    )

    assert result == 0


@pytest.mark.asyncio
async def test_investigate_exits_3_when_server_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "get_backend_url", lambda: "http://localhost:8000")
    monkeypatch.setattr(cli_main, "_ensure_server_running", AsyncMock(return_value=None))

    class _OfflineClient:
        async def __aenter__(self) -> _OfflineClient:
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def get(self, *_args, **_kwargs):
            raise RuntimeError("offline")

    monkeypatch.setattr(cli_main.httpx, "AsyncClient", lambda **_kwargs: _OfflineClient())

    result = await cli_main._investigate("user@example.com", "json", None, 30, None)

    assert result == 3
