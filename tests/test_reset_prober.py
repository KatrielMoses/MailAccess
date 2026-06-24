from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from backend.core import reset_prober


@pytest.fixture(autouse=True)
def _clear_signal_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reset_prober, "_SIGNAL_CORPUS", None)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Check your email", "EN"),
        ("Проверьте почту", "RU"),
        ("未找到账户", "ZH"),
        ("ひらがな", "JA"),
        ("계정을 확인하세요", "KO"),
        ("تحقق من بريدك", "AR"),
        ("अपना ईमेल जांचें", "HI"),
        ("English and Русский", "RU"),
    ],
)
def test_detect_language(text: str, expected: str) -> None:
    assert reset_prober.detect_language(text) == expected


def test_classify_text_uses_non_english_signals() -> None:
    assert reset_prober._classify_text("Аккаунт не найден", "RU") is False
    assert reset_prober._classify_text("Письмо отправлено", "RU") is True


def test_classify_text_decodes_html_entities() -> None:
    assert reset_prober._classify_text("doesn&#39;t exist") is False


def test_classify_text_decodes_url_encoding_and_plus() -> None:
    assert reset_prober._classify_text("no+user+found") is False


def test_load_signal_corpus_from_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus_path = tmp_path / "reset_signals.json"
    corpus_path.write_text(
        json.dumps(
            {
                "EN": {"success": ["sent"], "failure": ["missing"]},
                "ES": {"success": ["enviado"], "failure": ["inexistente"]},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(reset_prober, "_SIGNAL_CORPUS_PATH", corpus_path)

    corpus = reset_prober._load_signal_corpus()

    assert corpus["ES"]["success"] == ["enviado"]


@pytest.mark.parametrize("contents", [None, "{not valid json"])
def test_load_signal_corpus_falls_back_to_english(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, contents: str | None
) -> None:
    corpus_path = tmp_path / "reset_signals.json"
    if contents is not None:
        corpus_path.write_text(contents, encoding="utf-8")
    monkeypatch.setattr(reset_prober, "_SIGNAL_CORPUS_PATH", corpus_path)

    corpus = reset_prober._load_signal_corpus()

    assert corpus == reset_prober._english_signal_defaults()


async def test_probe_uses_first_definitive_result_and_cancels_pending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started: list[str] = []
    cancelled: list[str] = []
    all_started = asyncio.Event()

    async def fake_probe_endpoint(
        url: str,
        email: str,
        client: httpx.AsyncClient,
        language: reset_prober._ProbeLanguage,
    ) -> reset_prober._ProbeResult:
        started.append(url)
        if len(started) == len(reset_prober._ENDPOINT_PATTERNS):
            all_started.set()
        if url == "https://example.com/forgot-password":
            await all_started.wait()
            return reset_prober._ProbeResult(True, responded=True)
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.append(url)
            raise
        raise AssertionError("pending endpoint was not cancelled")

    monkeypatch.setattr(reset_prober, "_probe_endpoint", fake_probe_endpoint)

    async with httpx.AsyncClient() as client:
        result = await reset_prober.probe("example.com", "user@example.com", client)

    assert result is True
    assert len(started) == len(reset_prober._ENDPOINT_PATTERNS)
    assert len(cancelled) == len(reset_prober._ENDPOINT_PATTERNS) - 1
