"""DarkEye exposure lookup: HaveIBeenRansom and Breach House in one module.

Data provided by DarkEye (https://darkeye.io): HaveIBeenRansom
(https://haveibeenransom.com) indexes ransomware leaks and data breaches, and Breach
House (https://breach.house) lists ransomware victims, breaches, leads and stealer logs.
Each product has its own optional key; a product without a key is not queried, and with
neither key the module reports skipped and sends nothing.

Only listing metadata is read (title, website, group, country, date). HaveIBeenRansom's
stealer endpoint is not used because it returns saved credentials, and no password or
credential field is read from any response.
"""

from __future__ import annotations

import asyncio
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import httpx

from ..config import settings
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

HIBR = "haveibeenransom"
BH = "breach_house"
_PRODUCT_LABELS = {HIBR: "HaveIBeenRansom", BH: "Breach House"}

_HIBR_URL = "https://haveibeenransom.com/api/metadata"
_BH_URL = "https://breach.house/api/v1/search"

_HIBR_KEY_ENV = "DARKEYE_HIBR_API_KEY"
_BH_KEY_ENV = "DARKEYE_BREACHHOUSE_API_KEY"

_HIBR_CATEGORIES = {"ransomware_leak": "ransomware", "traditional_breach": "breach"}
_BH_CATEGORIES = {
    "ransomware": "ransomware",
    "breaches": "breach",
    "leads": "lead",
    "stealers": "stealer",
}

_REQUEST_TIMEOUT = 10.0
# Each product gets its own deadline so both finish inside MODULE_TIMEOUT_SECONDS (30 s)
# and the records read before a slow page are kept.
_PRODUCT_DEADLINE = 25.0
_MAX_PAGES = 5  # HaveIBeenRansom pages (20 records each, one daily-quota call per page)
_BH_LIMIT = 25  # Breach House results requested per source
_MAX_RECORDS = 100  # records kept per product
_MAX_TEXT = 256
_MATCH_TEXT = 4000
_MAX_EMAIL = 320


class _ProductError(Exception):
    """A product lookup failed. The message is safe to show."""


@dataclass
class _Outcome:
    product: str
    queried: bool = False
    skipped: str = ""
    error: str = ""
    truncated: bool = False
    records: list[dict[str, str]] = field(default_factory=list)

    @property
    def label(self) -> str:
        return _PRODUCT_LABELS[self.product]


def _usable_key(raw: Any) -> str | None:
    """The key, or None when it is unset or holds anything but visible ASCII."""
    if not isinstance(raw, str):
        return None
    key = raw.strip()
    if not key or any(ord(ch) < 33 or ord(ch) > 126 for ch in key):
        return None
    return key


def _text(value: Any, limit: int = _MAX_TEXT) -> str:
    """Single-line printable text, or "" for anything that is not text or a number."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return ""
    normalized = unicodedata.normalize("NFKC", str(value))
    printable = "".join(
        " " if ch.isspace() else ch
        for ch in normalized
        if ch.isspace() or unicodedata.category(ch)[0] != "C"
    )
    return " ".join(printable.split())[:limit]


def _valid_email(email: Any) -> bool:
    if not isinstance(email, str) or not email or len(email) > _MAX_EMAIL or "@" not in email:
        return False
    return not any(ch.isspace() or unicodedata.category(ch)[0] == "C" for ch in email)


def _mentions(texts: list[str], email: str) -> bool:
    # Boundary match: "bob@example.com" must not match "bob@example.com.au" or "xbob@...".
    pattern = r"(?<![\w.+%@-])" + re.escape(email) + r"(?![\w@+-]|\.\w)"
    return any(re.search(pattern, text, re.IGNORECASE) for text in texts)


async def _get_json(
    client: httpx.AsyncClient, url: str, key: str, params: dict[str, Any] | None = None
) -> dict[str, Any]:
    try:
        response = await client.get(
            url,
            params=params,
            headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
        )
    except httpx.TimeoutException:
        raise _ProductError("request timed out") from None
    except Exception as exc:
        raise _ProductError(f"request failed ({type(exc).__name__})") from None

    code = response.status_code
    if code in (401, 403):
        raise _ProductError(f"HTTP {code} (check the API key and plan)")
    if code == 429:
        raise _ProductError("HTTP 429 (daily limit reached)")
    if code != 200:
        raise _ProductError(f"HTTP {code}")
    try:
        data = response.json()
    except ValueError:
        raise _ProductError("invalid JSON response") from None
    if not isinstance(data, dict) or data.get("success") is False or "error" in data:
        raise _ProductError("unexpected response")
    return data


def _record(product: str, category: str, item: dict[str, Any]) -> dict[str, str]:
    """Listing metadata only; nothing else in the item is read."""
    return {
        "product": product,
        "category": category,
        "id": _text(item.get("id_source") or item.get("victim_id") or item.get("id")),
        "title": _text(item.get("post_title") or item.get("name")),
        "website": _text(item.get("website")),
        "group": _text(item.get("group_name")),
        "country": _text(item.get("country")),
        "discovered": _text(item.get("discovered"))[:10],
    }


async def _query_hibr(client: httpx.AsyncClient, email: str, key: str, out: _Outcome) -> None:
    """HaveIBeenRansom metadata search by email (ransomware leaks and data breaches)."""
    base = f"{_HIBR_URL}/email/{quote(email, safe='')}"
    seen: set[str] = set()
    for page in range(1, _MAX_PAGES + 1):
        data = await _get_json(client, base if page == 1 else f"{base}/{page}", key)
        items = data.get("results") if "results" in data else data.get("sources")
        pagination = data.get("pagination")
        has_next = data.get("has_next")
        if has_next is None and isinstance(pagination, dict):
            has_next = pagination.get("has_next")
        if (
            not isinstance(items, list)
            or not isinstance(has_next, bool)
            or any(not isinstance(item, dict) for item in items)
        ):
            raise _ProductError("unexpected response")
        for item in items:
            category = _HIBR_CATEGORIES.get(_text(item.get("leak_type")), "leak")
            record = _record(HIBR, category, item)
            if not any(record[k] for k in ("id", "title", "website")):
                raise _ProductError("unexpected response")
            identity = record["id"] or json.dumps(record, sort_keys=True)
            if identity in seen:
                continue
            seen.add(identity)
            if len(out.records) >= _MAX_RECORDS:
                out.truncated = True
                return
            out.records.append(record)
        if not has_next:
            return
    out.truncated = True


async def _query_bh(client: httpx.AsyncClient, email: str, key: str, out: _Outcome) -> None:
    """Breach House search. It is free text over victim and listing fields, so a record
    is kept only when the exact address appears in one of its text fields."""
    data = await _get_json(client, _BH_URL, key, params={"q": email, "limit": _BH_LIMIT})
    seen: set[tuple[str, str]] = set()
    for source, category in _BH_CATEGORIES.items():
        section = data.get(source)
        total = None
        if isinstance(section, dict):
            total, section = section.get("total"), section.get("results")
        if not isinstance(section, list) or any(not isinstance(i, dict) for i in section):
            raise _ProductError("unexpected response")
        if isinstance(total, int) and not isinstance(total, bool):
            out.truncated |= total > len(section)
        else:
            out.truncated |= len(section) >= _BH_LIMIT
        for item in section:
            texts = [
                _text(item.get(k), _MATCH_TEXT)
                for k in ("post_title", "name", "website", "description", "meta_description")
            ]
            if not _mentions(texts, email):
                continue
            record = _record(BH, category, item)
            identity = (category, record["id"] or json.dumps(record, sort_keys=True))
            if identity in seen:
                continue
            seen.add(identity)
            if len(out.records) >= _MAX_RECORDS:
                out.truncated = True
                return
            out.records.append(record)


async def _run_product(email: str, key: str, out: _Outcome) -> None:
    out.queried = True
    try:
        # One client per product so a key is only ever sent to its own host. Redirects
        # stay off for the same reason: the Authorization header must not leave the host.
        async with build_client(timeout=_REQUEST_TIMEOUT, follow_redirects=False) as client:
            work = (
                _query_hibr(client, email, key, out)
                if out.product == HIBR
                else _query_bh(client, email, key, out)
            )
            await asyncio.wait_for(work, timeout=_PRODUCT_DEADLINE)
    except _ProductError as exc:
        out.error = str(exc)
    except asyncio.TimeoutError:
        out.error = "request timed out"
    except Exception as exc:
        out.error = f"unexpected error ({type(exc).__name__})"


def _finding(rec: dict[str, str]) -> dict[str, Any]:
    category = rec["category"]
    label = _PRODUCT_LABELS[rec["product"]]
    title = rec["title"] or "Unknown"
    metadata: dict[str, Any] = {
        "product": rec["product"],
        "category": category,
        "title": title,
        "summary": f"{label} ({category}): {title}",
    }
    for key, name in (
        ("id", "record_id"),
        ("website", "website"),
        ("group", "group"),
        ("country", "country"),
        ("discovered", "discovered"),
    ):
        if rec[key]:
            metadata[name] = rec[key]
    return {
        "platform": rec["product"],
        "product": rec["product"],
        "category": category,
        "source": "darkeye",
        "confidence": "medium",
        "severity": "low" if category == "lead" else "medium",
        "metadata": metadata,
    }


class DarkEyeModule(BaseModule):
    name = "darkeye"
    email_linked = True
    description = (
        "Look the email up in DarkEye's HaveIBeenRansom and Breach House "
        "(ransomware, breach, leak, stealer and lead listings)."
    )
    requires_key = True

    async def run(self, email: str) -> ModuleResult:
        try:
            return await self._run(email)
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"DarkEye lookup failed ({type(exc).__name__})"],
            )

    async def _run(self, email: str) -> ModuleResult:
        hibr = _Outcome(HIBR)
        bh = _Outcome(BH)
        keys: dict[str, str | None] = {}
        for outcome, env, raw in (
            (hibr, _HIBR_KEY_ENV, settings.darkeye_hibr_api_key),
            (bh, _BH_KEY_ENV, settings.darkeye_breachhouse_api_key),
        ):
            keys[outcome.product] = _usable_key(raw)
            if not raw or not str(raw).strip():
                outcome.skipped = f"{env} not set"
            elif keys[outcome.product] is None:
                outcome.skipped = f"{env} has whitespace or non-printable characters"

        outcomes = [hibr, bh]
        if not any(keys.values()):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata=self._metadata(outcomes),
                errors=[f"{o.label}: not queried, {o.skipped}" for o in outcomes],
            )
        if not _valid_email(email):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata=self._metadata(outcomes),
                errors=["DarkEye: not a valid email address, nothing was sent"],
            )

        await asyncio.gather(
            *(_run_product(email, keys[o.product] or "", o) for o in outcomes if keys[o.product])
        )

        queried = [o for o in outcomes if o.queried]
        records = [r for o in outcomes for r in o.records]
        errors = [f"{o.label}: {o.error}" for o in queried if o.error]
        if all(o.error for o in queried) and not records:
            status = ModuleStatus.FAILED
        elif any(o.error or o.truncated for o in queried):
            status = ModuleStatus.PARTIAL
        else:
            status = ModuleStatus.SUCCESS
        if any(o.truncated for o in queried):
            errors.append("DarkEye: a record limit was reached, results may be incomplete")

        return ModuleResult(
            status=status,
            findings=[_finding(r) for r in records],
            metadata=self._metadata(outcomes, records),
            errors=errors,
        )

    @staticmethod
    def _metadata(
        outcomes: list[_Outcome], records: list[dict[str, str]] | None = None
    ) -> dict[str, Any]:
        products: dict[str, dict[str, Any]] = {}
        for o in outcomes:
            if o.skipped:
                info: dict[str, Any] = {"status": "skipped", "reason": o.skipped}
            elif o.error:
                info = {"status": "error", "reason": o.error, "records": len(o.records)}
            else:
                info = {"status": "ok", "records": len(o.records), "truncated": o.truncated}
            products[o.product] = info
        by_category: dict[str, int] = {}
        for rec in records or []:
            by_category[rec["category"]] = by_category.get(rec["category"], 0) + 1
        return {
            "source": "DarkEye (https://darkeye.io): HaveIBeenRansom and Breach House",
            "products": products,
            "records_by_category": by_category,
        }
