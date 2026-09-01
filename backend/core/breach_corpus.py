from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import httpx

from .domain_validation import is_public_clearnet_domain

_LOG = logging.getLogger(__name__)

_HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
_CACHE_PATH = Path(__file__).resolve().parents[2] / "data" / "cache" / "breach_corpus.json"
_CACHE_TTL_SECONDS = 86_400


@dataclass(frozen=True)
class BreachSite:
    domain: str
    breach_name: str
    breach_date: str
    pwn_count: int
    data_classes: list[str]
    severity_score: float
    severity_label: str


def _severity_score(pwn_count: int, data_classes: list[str]) -> float:
    classes = {c.lower() for c in data_classes}
    multiplier = 1.0
    if "passwords" in classes:
        multiplier *= 3
    if "credit cards" in classes:
        multiplier *= 2
    if "financial data" in classes:
        multiplier *= 2
    if "phone numbers" in classes:
        multiplier *= 1.5
    return float(pwn_count) * multiplier


def _severity_label(score: float) -> str:
    if score >= 300_000_000:
        return "critical"
    if score >= 10_000_000:
        return "high"
    return "medium"


def _site_from_hibp(raw: dict[str, Any]) -> BreachSite | None:
    domain = str(raw.get("Domain") or "").strip().lower()
    breach_name = str(raw.get("Name") or "").strip()
    if not domain and not breach_name:
        return None
    if not is_public_clearnet_domain(domain):
        _LOG.debug("Skipping non-clearnet breach domain: %s", domain)
        return None
    breach_date = str(raw.get("BreachDate") or "").strip()
    try:
        pwn_count = int(raw.get("PwnCount") or 0)
    except (TypeError, ValueError):
        pwn_count = 0
    raw_classes = raw.get("DataClasses") or []
    data_classes = [str(c) for c in raw_classes if c]
    score = _severity_score(pwn_count, data_classes)
    return BreachSite(
        domain=domain,
        breach_name=breach_name,
        breach_date=breach_date,
        pwn_count=pwn_count,
        data_classes=data_classes,
        severity_score=score,
        severity_label=_severity_label(score),
    )


class BreachCorpus:
    """Cached HIBP breach corpus ranked by account-impact severity."""

    def __init__(self, cache_path: Path = _CACHE_PATH) -> None:
        self.cache_path = cache_path
        self._all: list[BreachSite] | None = None

    def load(self) -> list[BreachSite]:
        if self._all is not None:
            return list(self._all)

        payload = self._read_cache()
        if payload is None:
            payload = self._fetch()
            self._write_cache(payload)

        sites: list[BreachSite] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            site = _site_from_hibp(item)
            if site is not None:
                sites.append(site)

        sites.sort(key=lambda s: (s.severity_score, s.pwn_count, s.breach_name), reverse=True)
        self._all = sites
        return list(sites)

    def get_top(self, n: int = 100) -> list[BreachSite]:
        return [site for site in self.load() if site.domain][:n]

    def get_all(self) -> list[BreachSite]:
        return self.load()

    def by_domain(self, domain: str) -> BreachSite | None:
        needle = domain.strip().lower()
        for site in self.load():
            if site.domain == needle:
                return site
        return None

    def as_jsonable(self) -> list[dict[str, Any]]:
        return [asdict(site) for site in self.load()]

    def _read_cache(self) -> list[dict[str, Any]] | None:
        if not self.cache_path.exists():
            return None
        age = time.time() - self.cache_path.stat().st_mtime
        if age >= _CACHE_TTL_SECONDS:
            return None
        try:
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception as exc:
            _LOG.debug("breach corpus cache read failed: %s", exc)
            return None
        if not isinstance(payload, list):
            return None
        return [item for item in payload if isinstance(item, dict)]

    def _write_cache(self, payload: list[dict[str, Any]]) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(payload), encoding="utf-8")
        except Exception as exc:
            _LOG.debug("breach corpus cache write failed: %s", exc)

    def _fetch(self) -> list[dict[str, Any]]:
        headers = {"User-Agent": "MailAccess OSINT Tool"}
        with httpx.Client(timeout=30.0, follow_redirects=True, headers=headers) as client:
            resp = client.get(_HIBP_BREACHES_URL)
            resp.raise_for_status()
            payload = resp.json()
        if not isinstance(payload, list):
            raise ValueError("HIBP breach corpus response was not a list")
        return [item for item in payload if isinstance(item, dict)]
