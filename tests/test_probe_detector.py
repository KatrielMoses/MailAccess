from __future__ import annotations

import asyncio

import httpx
import pytest

from backend.core.probe_detector import _detect_message, detect_hit, probe_platform


async def _probe(defn: dict[str, object], body: str) -> tuple[str, str | None]:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        outcome, detail, _profile = await probe_platform(
            client,
            asyncio.Semaphore(1),
            "Example",
            defn,
            "missing-user",
        )
        return outcome, detail


@pytest.mark.asyncio
async def test_status_code_absence_marker_overrides_200() -> None:
    defn = {
        "checkType": "status_code",
        "url": "https://example.test/{username}",
        "absenceStrs": ["User not found"],
    }

    assert await _probe(defn, "<html>User not found</html>") == ("miss", None)


@pytest.mark.asyncio
async def test_status_code_short_200_body_is_inconclusive() -> None:
    defn = {
        "checkType": "status_code",
        "url": "https://example.test/{username}",
    }

    verdict, detail = await _probe(defn, "x" * 499)

    assert verdict == "inconclusive"
    assert detail == "Example: 200"


@pytest.mark.asyncio
async def test_status_code_200_at_default_threshold_is_hit() -> None:
    defn = {
        "checkType": "status_code",
        "url": "https://example.test/{username}",
    }

    verdict, _ = await _probe(defn, "x" * 500)

    assert verdict == "hit"


@pytest.mark.asyncio
async def test_status_code_min_response_bytes_override_relaxes_threshold() -> None:
    defn = {
        "checkType": "status_code",
        "url": "https://example.test/{username}",
        "min_response_bytes": 50,
    }

    verdict, _ = await _probe(defn, "x" * 100)

    assert verdict == "hit"


@pytest.mark.asyncio
async def test_status_code_min_response_bytes_override_strict_threshold() -> None:
    defn = {
        "checkType": "status_code",
        "url": "https://example.test/{username}",
        "min_response_bytes": 2000,
    }

    verdict, detail = await _probe(defn, "x" * 500)

    assert verdict == "inconclusive"
    assert detail == "Example: 200"


@pytest.mark.asyncio
async def test_status_code_invalid_min_response_bytes_falls_back_to_default() -> None:
    defn = {
        "checkType": "status_code",
        "url": "https://example.test/{username}",
        "min_response_bytes": "not-a-number",
    }

    verdict, _ = await _probe(defn, "x" * 499)

    assert verdict == "inconclusive"


@pytest.mark.asyncio
async def test_status_code_unescapes_html_entities_before_absence_match() -> None:
    defn = {
        "checkType": "status_code",
        "url": "https://example.test/{username}",
        "absenceStrs": ["doesn't exist"],
    }

    assert await _probe(defn, "This user doesn&#39;t exist") == ("miss", None)


def test_detect_message_unescapes_html_entities_defensively() -> None:
    defn = {
        "checkType": "message",
        "absenceStrs": ["doesn't exist"],
        "presenseStrs": ["profile-card"],
    }

    assert _detect_message(defn, "This user doesn&#39;t exist") == "miss"


# ── WAF guard + templated errorUrl substitution ──


@pytest.mark.asyncio
async def test_waf_challenge_body_is_inconclusive_not_a_hit() -> None:
    # A 200 bot-wall challenge page must not be counted as a profile hit.
    defn = {
        "checkType": "status_code",
        "url": "https://example.test/{username}",
    }
    body = '<span id="challenge-error-text">' + "x" * 600

    assert await _probe(defn, body) == ("inconclusive", "waf_blocked")


def test_two_marker_existence_decides_hit_independently() -> None:
    # Two-marker detection (schema contract, mailaccess-sites-schema.md:66-68): EXISTS and
    # NOT-EXISTS are INDEPENDENT conditions. The existence rule (status == e_code AND
    # e_string present) decides a hit on its own; the absence marker is never AND-ed in.
    defn = {"e_code": 200, "e_string": "profile-card", "m_code": 404, "m_string": "not found"}
    # existence present -> hit
    assert detect_hit(defn, "<div class='profile-card'>jane</div>", 200, "") == "hit"
    # existence present is STILL a hit even if the absence marker also appears in the body
    # (a live profile page can legitimately contain the "not found" substring elsewhere).
    assert detect_hit(defn, "profile-card ... not found", 200, "") == "hit"
    # absence code+string, no existence signal -> miss
    assert detect_hit(defn, "not found", 404, "") == "miss"
    # neither existence nor absence satisfied -> inconclusive
    assert detect_hit(defn, "something else", 500, "") == "inconclusive"


def test_two_marker_empty_strings_behave_as_status_only() -> None:
    # Empty markers (e.g. the github_username row) impose no presence/absence requirement, so the
    # row behaves as a pure status-code check and is unaffected by the two-marker tightening.
    defn = {"e_code": 200, "e_string": "", "m_code": 404, "m_string": ""}
    assert detect_hit(defn, "x" * 10, 200, "") == "hit"
    assert detect_hit(defn, "x" * 10, 404, "") == "miss"


@pytest.mark.asyncio
async def test_strip_bad_char_removes_chars_before_probe() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200, text="x" * 600, request=request)

    defn = {
        "checkType": "status_code",
        "uri_check": "https://example.test/{username}",
        "url": "https://example.test/{username}",
        "strip_bad_char": ".",
    }
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await probe_platform(client, asyncio.Semaphore(1), "Example", defn, "ja.ne.doe")
    # The "." characters are stripped from the username before substitution.
    assert captured["url"] == "https://example.test/janedoe"


@pytest.mark.asyncio
async def test_response_url_error_url_username_is_substituted() -> None:
    # errorUrl carries a ``{username}`` template; it must be baked in before the substring match
    # against the final URL, otherwise the literal placeholder can never match (silent false hit).
    defn = {
        "checkType": "response_url",
        "url": "https://example.test/search?q={username}",
        "errorUrl": "https://example.test/search?q={username}",
    }

    # final_url == probe_url (no redirect) == the substituted errorUrl → miss.
    assert await _probe(defn, "x" * 600) == ("miss", None)
