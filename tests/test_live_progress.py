from __future__ import annotations

import time

import pytest

from backend.core.signal_pool import AsyncSignalPool, Signal
from cli.harvest_emails import LiveHarvestDisplay, calculate_eta


def test_progress_callback_called_during_module_execution(tmp_path) -> None:
    display = LiveHarvestDisplay(["pattern_and_verify"], time.monotonic(), tmp_path / "live.log")
    display.progress("pattern_and_verify", "SMTP probing a@example.com...")
    assert display.states["pattern_and_verify"]["action"].startswith("SMTP probing")


@pytest.mark.asyncio
async def test_live_ticker_updates_on_signal_pool_emit(tmp_path) -> None:
    display = LiveHarvestDisplay(["pgp"], time.monotonic(), tmp_path / "live.log")
    pool = AsyncSignalPool(export_threshold=0)
    pool.register_display_subscriber(display.signal)
    await pool.publish(
        Signal(
            source="pgp", kind="email", value="a@example.com", metadata={"email": "a@example.com"}
        )
    )
    await pool.close()
    assert display.counts["email"] == 1


def test_eta_calculation_based_on_elapsed_per_module() -> None:
    assert calculate_eta(120, 2, 5) == "~3m00s"
    assert calculate_eta(1, 0, 5) == "calculating..."


def test_live_log_file_written_to_results_dir(tmp_path) -> None:
    path = tmp_path / "results" / "example_live.log"
    display = LiveHarvestDisplay(["module"], time.monotonic(), path)
    display.progress("module", "working")
    assert "[MODULE] working" in path.read_text(encoding="utf-8")


def test_latest_finds_shows_last_5_only(tmp_path) -> None:
    display = LiveHarvestDisplay(["module"], time.monotonic(), tmp_path / "live.log")
    for index in range(7):
        display.signal(
            Signal(source="module", kind="email", value=f"u{index}@example.com", metadata={})
        )
    assert len(display.latest_finds) == 5
    assert display.latest_finds[0][1] == "u2@example.com"
