from __future__ import annotations

from collections import deque
from unittest.mock import AsyncMock

import pytest
from typer.testing import CliRunner

from backend.config import settings
from backend.core.mx_resolver import MXRecord
from backend.core.smtp_verifier import SMTPVerifier
from cli.main import app


class Transport:
    def __init__(self, replies: list[str]) -> None:
        self.replies = deque(replies)
        self.commands: list[str] = []

    async def send(self, host: str, port: int, command: str) -> str:
        self.commands.append(command)
        return self.replies.popleft()


def conversation(code: int) -> list[str]:
    return ["220 ready", "250 hello", "250 sender", f"{code} recipient", "250 reset", "221 bye"]


def test_smtp_verify_on_by_default() -> None:
    assert settings.smtp_verify_default is True
    assert settings.smtp_verify_max_probes == 10


def test_no_verify_flag_disables_smtp(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_run(**kwargs):
        captured.update(kwargs)
        return 0

    monkeypatch.setattr("cli.main.run_harvest_emails", fake_run)
    result = CliRunner().invoke(app, ["harvest-emails", "--domain", "example.com", "--no-verify"])
    assert result.exit_code == 0
    assert captured["no_verify"] is True


@pytest.mark.asyncio
async def test_catch_all_detection_stops_probing() -> None:
    transport = Transport(conversation(250))
    verifier = SMTPVerifier(
        [MXRecord("mx.example.com", 10)], probe_delay_seconds=0, transport=transport
    )
    batch = await verifier.verify_batch(
        "example.com", ["one@example.com", "two@example.com"], max_probes=10
    )
    assert batch.is_catchall is True
    assert sum(command.startswith("RCPT TO") for command in transport.commands) == 1


@pytest.mark.asyncio
async def test_greylist_retry_after_30s(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(
        "backend.core.smtp_verifier.asyncio.sleep",
        AsyncMock(side_effect=lambda delay: sleeps.append(delay)),
    )
    transport = Transport(conversation(451) + conversation(451))
    verifier = SMTPVerifier(
        [MXRecord("mx.example.com", 10)],
        probe_delay_seconds=0,
        greylist_retry_delay=30,
        transport=transport,
    )
    result = await verifier.verify_single("one@example.com")
    assert 30 in sleeps
    assert result.verification_status == "inconclusive"


@pytest.mark.asyncio
async def test_max_10_probes_per_domain() -> None:
    replies = conversation(550) + conversation(550) * 10
    verifier = SMTPVerifier(
        [MXRecord("mx.example.com", 10)], probe_delay_seconds=0, transport=Transport(replies)
    )
    batch = await verifier.verify_batch(
        "example.com", [f"u{i}@example.com" for i in range(20)], max_probes=500
    )
    assert batch.probes_attempted == 10


@pytest.mark.asyncio
async def test_250_response_marks_confirmed() -> None:
    verifier = SMTPVerifier(
        [MXRecord("mx.example.com", 10)],
        probe_delay_seconds=0,
        transport=Transport(conversation(250)),
    )
    assert (await verifier.verify_single("one@example.com")).exists is True


@pytest.mark.asyncio
async def test_550_response_marks_not_found() -> None:
    verifier = SMTPVerifier(
        [MXRecord("mx.example.com", 10)],
        probe_delay_seconds=0,
        transport=Transport(conversation(550)),
    )
    result = await verifier.verify_single("one@example.com")
    assert result.exists is False
    assert result.verification_status == "not_found"
