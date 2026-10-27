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


def test_eta_line_shows_progress_count_and_left_suffix(tmp_path) -> None:
    display = LiveHarvestDisplay(["m"], time.monotonic(), tmp_path / "live.log")
    line = display._eta_line(100.0, 60.0, 40.0, [], 3, 10)
    assert line == "~40s left  (3/10 modules)"


def test_eta_line_calculating_before_first_module(tmp_path) -> None:
    display = LiveHarvestDisplay(["m"], time.monotonic(), tmp_path / "live.log")
    line = display._eta_line(1000.0, 5.0, None, [], 0, 83)
    assert "calculating" in line and "(0/83 modules)" in line


def test_eta_line_never_jumps_up(tmp_path) -> None:
    display = LiveHarvestDisplay(["m"], time.monotonic(), tmp_path / "live.log")
    display._eta_line(1000.0, 60.0, 50.0, [], 3, 10)
    first = display._eta_shown
    # Raw estimate spikes to 80s on the next render; the shown value must not increase.
    display._eta_line(1005.0, 65.0, 80.0, [], 3, 10)
    assert display._eta_shown is not None and display._eta_shown <= first


def test_eta_line_floors_at_longest_in_flight_module(tmp_path) -> None:
    display = LiveHarvestDisplay(["m"], time.monotonic(), tmp_path / "live.log")
    # Raw estimate has collapsed to 5s, but a module has been running 80s — the floor
    # (half of 80 = 40s) keeps the figure honest instead of a misleading "~5s".
    line = display._eta_line(1000.0, 200.0, 5.0, [80.0], 70, 83)
    assert "40s left" in line and "(70/83 modules)" in line


def test_eta_line_finishing_up_on_tail(tmp_path) -> None:
    display = LiveHarvestDisplay(["m"], time.monotonic(), tmp_path / "live.log")
    line = display._eta_line(1000.0, 200.0, 30.0, [], 82, 83)
    assert "finishing up" in line and "(82/83 modules)" in line


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
