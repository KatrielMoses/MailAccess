from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any

from .breach_normalizer import resolve_breach_identity


_EVENT_TYPES = frozenset(
    {
        "first_seen",
        "breach",
        "stealer_log",
        "paste",
        "account_created",
        "archive_snapshot",
        "commit",
    }
)
_CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
_BREACH_MODULES = frozenset(
    {"hibp", "haveibeenpwned", "breachdirectory", "breach_deep", "xposedornot", "leakcheck"}
)
_RECENT_DAYS = 90


@dataclass
class TimelineEvent:
    date: str
    year: int
    event_type: str
    title: str
    source_module: str
    confidence: str
    detail: str | None
    is_recent: bool
    is_active_risk: bool


@dataclass
class Timeline:
    events: list[TimelineEvent]
    first_seen_date: str | None
    first_seen_source: str | None
    most_recent_date: str | None
    most_recent_event: str | None
    most_recent_is_active_risk: bool
    established_identity: bool
    identity_age_years: int | None
    active_risk_count: int
    timeline_span_years: int | None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _ParsedDate:
    normalized: str
    sort_date: date
    year: int


@dataclass
class _Candidate:
    event: TimelineEvent
    sort_date: date
    sources: list[str]
    dedupe_key: tuple[str, str] | None = None
    count: int = 1


def _normalize_name(value: Any) -> str:
    return "".join(ch.lower() for ch in str(value or "") if ch.isalnum())


_KNOWN_BREACH_DATE_RAW: dict[str, str] = {
    "123RF": "2020-03",
    "500px": "2018-07",
    "8fit": "2018-07",
    "Adobe": "2013-10",
    "AdultFriendFinder": "2016-10",
    "Apollo": "2018-07",
    "Armor Games": "2019-01",
    "Ashley Madison": "2015-07",
    "Badoo": "2013-06",
    "Bitly": "2014-05",
    "BlankMediaGames": "2018-12",
    "Canva": "2019-05",
    "Chegg": "2018-04",
    "Cit0day": "2020-11",
    "Collection 1": "2019-01",
    "DailyMotion": "2016-10",
    "Disqus": "2012-07",
    "Dropbox": "2012-07",
    "Dubsmash": "2018-12",
    "Edmodo": "2017-05",
    "Equifax": "2017-05",
    "Evite": "2019-04",
    "Exploit.In": "2016-10",
    "Facebook": "2019-08",
    "Gawker": "2010-12",
    "HauteLook": "2018-08",
    "Houzz": "2018-07",
    "Imgur": "2014-09",
    "Kickstarter": "2014-02",
    "Last.fm": "2012-03",
    "LinkedIn": "2012-06",
    "LinkedIn Scrape": "2021-04",
    "Mate1": "2016-02",
    "MyFitnessPal": "2018-02",
    "MyHeritage": "2017-10",
    "MySpace": "2008-07",
    "Neopets": "2016-05",
    "Onliner Spambot": "2017-08",
    "Patreon": "2015-10",
    "Poshmark": "2018-05",
    "Quora": "2018-11",
    "Reddit": "2018-06",
    "River City Media": "2017-01",
    "RockYou": "2009-12",
    "RockYou2021": "2021-06",
    "RockYou2024": "2024-01",
    "ShareThis": "2018-07",
    "Shein": "2018-06",
    "Stratfor": "2011-12",
    "Ticketfly": "2018-05",
    "Tumblr": "2013-02",
    "Twitter": "2021-01",
    "Verifications.io": "2019-02",
    "VK": "2012-01",
    "Wattpad": "2020-06",
    "Yahoo": "2013-08",
    "Yahoo 2014": "2014-01",
    "Zynga": "2019-09",
}
_KNOWN_BREACH_DATES = {
    _normalize_name(name): value for name, value in _KNOWN_BREACH_DATE_RAW.items()
}


def _safe_date(year: int, month: int = 1, day: int = 1) -> date | None:
    try:
        return date(year, month, day)
    except ValueError:
        return None


def _coerce_date(value: Any) -> _ParsedDate | None:
    if value is None:
        return None

    if isinstance(value, datetime):
        value = value.astimezone(timezone.utc) if value.tzinfo else value
        sort_date = value.date()
        return _ParsedDate(sort_date.isoformat(), sort_date, sort_date.year)

    if isinstance(value, date):
        return _ParsedDate(value.isoformat(), value, value.year)

    if isinstance(value, int):
        if 1900 <= value <= 2100:
            sort_date = date(value, 1, 1)
            return _ParsedDate(f"{value:04d}-01", sort_date, value)
        return None

    text = str(value).strip()
    if not text or text.lower() in {"none", "null", "unknown", "n/a", "never"}:
        return None

    if re.fullmatch(r"\d{14}", text):
        try:
            parsed = datetime.strptime(text, "%Y%m%d%H%M%S").date()
            return _ParsedDate(parsed.isoformat(), parsed, parsed.year)
        except ValueError:
            return None

    iso_text = text.replace("Z", "+00:00")
    try:
        parsed_dt = datetime.fromisoformat(iso_text)
        if isinstance(parsed_dt, datetime):
            parsed_dt = parsed_dt.astimezone(timezone.utc) if parsed_dt.tzinfo else parsed_dt
            parsed_date = parsed_dt.date()
            return _ParsedDate(parsed_date.isoformat(), parsed_date, parsed_date.year)
    except ValueError:
        pass

    match = re.search(r"\b((?:19|20)\d{2})[-/](\d{1,2})[-/](\d{1,2})\b", text)
    if match:
        year, month, day = (int(part) for part in match.groups())
        parsed = _safe_date(year, month, day)
        if parsed is not None:
            return _ParsedDate(parsed.isoformat(), parsed, year)

    match = re.search(r"\b((?:19|20)\d{2})[-/](\d{1,2})\b", text)
    if match:
        year, month = (int(part) for part in match.groups())
        parsed = _safe_date(year, month)
        if parsed is not None:
            return _ParsedDate(f"{year:04d}-{month:02d}", parsed, year)

    for fmt in ("%b %Y", "%B %Y", "%d %b %Y", "%d %B %Y"):
        try:
            parsed_dt = datetime.strptime(text, fmt).date()
            normalized = (
                parsed_dt.isoformat()
                if "%d" in fmt
                else f"{parsed_dt.year:04d}-{parsed_dt.month:02d}"
            )
            sort_date = (
                parsed_dt.replace(day=1)
                if "%d" not in fmt
                else parsed_dt
            )
            return _ParsedDate(normalized, sort_date, parsed_dt.year)
        except ValueError:
            continue

    match = re.search(r"\b((?:19|20)\d{2})\b", text)
    if match:
        year = int(match.group(1))
        parsed = date(year, 1, 1)
        return _ParsedDate(f"{year:04d}-01", parsed, year)

    return None


def _payload_from_row(row: Any) -> tuple[str, dict[str, Any]]:
    if hasattr(row, "module_name") and hasattr(row, "data"):
        data = getattr(row, "data")
        payload = data if isinstance(data, dict) else {}
        return str(getattr(row, "module_name") or ""), payload

    if isinstance(row, dict):
        raw_data = row.get("data")
        if isinstance(raw_data, dict):
            module_name = str(row.get("module_name") or raw_data.get("source") or "")
            return module_name, raw_data
        module_name = str(row.get("module_name") or row.get("source") or "")
        return module_name, row

    return "", {}


def _metadata(payload: dict[str, Any]) -> dict[str, Any]:
    meta = payload.get("metadata")
    return meta if isinstance(meta, dict) else {}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple | set):
        return list(value)
    return [value]


def _string_list(value: Any) -> list[str]:
    items: list[str] = []
    for item in _as_list(value):
        if item is None:
            continue
        text = str(item).strip()
        if text:
            items.append(text)
    return items


def _sources(module_name: str, payload: dict[str, Any]) -> list[str]:
    meta = _metadata(payload)
    seen: list[str] = []

    def add(value: Any) -> None:
        for item in _string_list(value):
            if item and item not in seen:
                seen.append(item)

    add(module_name)
    add(meta.get("source_modules"))
    add(meta.get("sources"))
    add(payload.get("sources"))
    add(meta.get("source_module"))
    if not seen:
        add(payload.get("source"))
    return seen or ["unknown"]


def _source_text(sources: list[str]) -> str:
    return ", ".join(sources)


def _detail_join(parts: list[Any]) -> str | None:
    text_parts = [str(part).strip() for part in parts if part is not None and str(part).strip()]
    return "; ".join(text_parts) if text_parts else None


def _count_text(value: Any) -> str | None:
    try:
        count = int(value or 0)
    except (TypeError, ValueError):
        return None
    if count <= 0:
        return None
    if count >= 1_000_000_000:
        return f"{count / 1_000_000_000:.1f}B records"
    if count >= 1_000_000:
        return f"{round(count / 1_000_000):.0f}M records"
    if count >= 1_000:
        return f"{round(count / 1_000):.0f}K records"
    return f"{count} records"


def _data_classes(payload: dict[str, Any]) -> list[str]:
    meta = _metadata(payload)
    values: list[str] = []
    for key in ("data_classes", "exposed_data", "all_data_classes"):
        values.extend(_string_list(payload.get(key)))
        values.extend(_string_list(meta.get(key)))
    deduped: list[str] = []
    for value in values:
        if value not in deduped:
            deduped.append(value)
    return deduped


def _has_password_data(payload: dict[str, Any]) -> bool:
    meta = _metadata(payload)
    for item in _data_classes(payload):
        if "password" in item.lower():
            return True
    if payload.get("password_risk") or meta.get("password_risk"):
        return True
    if payload.get("has_password_hash") or meta.get("has_password_hash"):
        return True
    if payload.get("password_hint") or meta.get("password_hint"):
        return True
    if payload.get("credentials_leaked") or meta.get("credentials_leaked"):
        return True
    return False


def _breach_name(payload: dict[str, Any]) -> str | None:
    meta = _metadata(payload)
    for key in ("canonical_breach_name", "breach_name", "name", "title", "breach_id"):
        value = meta.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for key in ("breach_name", "name", "title", "breach_id", "platform"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _known_breach_date(name: str | None) -> str | None:
    normalized = _normalize_name(name)
    if not normalized:
        return None
    exact = _KNOWN_BREACH_DATES.get(normalized)
    if exact:
        return exact
    for key, value in _KNOWN_BREACH_DATES.items():
        if key and (normalized.startswith(key) or key in normalized):
            return value
    return None


def _breach_date(payload: dict[str, Any], module_name: str) -> _ParsedDate | None:
    meta = _metadata(payload)
    candidates = [
        payload.get("breach_date"),
        payload.get("breached_date"),
        payload.get("breachedDate"),
        payload.get("xposed_date"),
        meta.get("breach_date"),
        meta.get("breached_date"),
        meta.get("breachedDate"),
        meta.get("xposed_date"),
        meta.get("source_date"),
        meta.get("date"),
        payload.get("date"),
        payload.get("source_date"),
        meta.get("year"),
        payload.get("year"),
    ]
    for candidate in candidates:
        parsed = _coerce_date(candidate)
        if parsed is not None:
            return parsed

    if module_name in {"leakcheck", "breachdirectory"}:
        known = _known_breach_date(_breach_name(payload))
        return _coerce_date(known)

    return None


def _breach_dedupe_key(payload: dict[str, Any], module_name: str) -> tuple[str, str] | None:
    try:
        identity = resolve_breach_identity(payload, module_name)
    except Exception:
        identity = None
    if identity is not None:
        return ("breach", identity.canonical_id)
    name = _breach_name(payload)
    normalized = _normalize_name(name)
    if normalized:
        return ("breach", normalized)
    return None


def _confidence(value: Any, default: str = "medium") -> str:
    text = str(value or default).strip().lower()
    return text if text in _CONFIDENCE_RANK else default


def _higher_confidence(left: str, right: str) -> str:
    return left if _CONFIDENCE_RANK.get(left, 0) >= _CONFIDENCE_RANK.get(right, 0) else right


def _summary_event_name(event: TimelineEvent) -> str:
    title = event.title.strip()
    if event.event_type == "breach" and title.lower().endswith(" breach"):
        title = title[: -len(" breach")]
    return f"{event.event_type}: {title}"


def _age_years(first_seen: date, as_of: date) -> int:
    years = as_of.year - first_seen.year
    if (as_of.month, as_of.day) < (first_seen.month, first_seen.day):
        years -= 1
    return max(years, 0)


def _span_years(first_seen: date, most_recent: date) -> int:
    return max(int((most_recent - first_seen).days // 365), 0)


class TimelineBuilder:
    def __init__(self, *, as_of: datetime | None = None) -> None:
        self.as_of = as_of or datetime.now(timezone.utc)
        self._metadata: dict[str, Any] = {}

    def build_timeline(self, findings: list[Any]) -> Timeline:
        candidates: list[_Candidate] = []
        for row in findings:
            module_name, payload = _payload_from_row(row)
            if not payload:
                continue
            try:
                candidates.extend(self._events_for_payload(module_name.lower(), payload))
            except Exception:
                continue

        events = self._dedupe(candidates)
        if not events:
            return Timeline(
                events=[],
                first_seen_date=None,
                first_seen_source=None,
                most_recent_date=None,
                most_recent_event=None,
                most_recent_is_active_risk=False,
                established_identity=False,
                identity_age_years=None,
                active_risk_count=0,
                timeline_span_years=None,
                metadata=self._metadata,
            )

        events.sort(key=lambda candidate: (candidate.sort_date, candidate.event.event_type))
        first = min(
            events,
            key=lambda candidate: (
                candidate.sort_date,
                -_CONFIDENCE_RANK.get(candidate.event.confidence, 0),
            ),
        )
        most_recent = max(events, key=lambda candidate: candidate.sort_date)
        age = _age_years(first.sort_date, self.as_of.date())
        active_risk_count = sum(1 for candidate in events if candidate.event.is_active_risk)

        return Timeline(
            events=[candidate.event for candidate in events],
            first_seen_date=first.event.date,
            first_seen_source=first.event.source_module,
            most_recent_date=most_recent.event.date,
            most_recent_event=_summary_event_name(most_recent.event),
            most_recent_is_active_risk=most_recent.event.is_active_risk,
            established_identity=age >= 3,
            identity_age_years=age,
            active_risk_count=active_risk_count,
            timeline_span_years=_span_years(first.sort_date, most_recent.sort_date),
            metadata=self._metadata,
        )

    def _events_for_payload(self, module_name: str, payload: dict[str, Any]) -> list[_Candidate]:
        if module_name == "github_commits":
            return self._github_events(module_name, payload)
        if module_name == "wayback":
            return self._wayback_events(module_name, payload)
        if module_name == "hudson_rock":
            return self._hudson_rock_events(module_name, payload)
        if module_name in {"emailrep", "email_credibility"}:
            return self._emailrep_events(module_name, payload)
        if module_name == "gravatar":
            return self._gravatar_events(module_name, payload)
        if module_name in _BREACH_MODULES:
            return self._breach_or_paste_events(module_name, payload)
        return []

    def _make_event(
        self,
        *,
        parsed: _ParsedDate,
        event_type: str,
        title: str,
        module_name: str,
        payload: dict[str, Any],
        confidence: str,
        detail: str | None,
        active_risk: bool = False,
        dedupe_key: tuple[str, str] | None = None,
    ) -> _Candidate | None:
        if event_type not in _EVENT_TYPES:
            return None
        sources = _sources(module_name, payload)
        days_old = (self.as_of.date() - parsed.sort_date).days
        event = TimelineEvent(
            date=parsed.normalized,
            year=parsed.year,
            event_type=event_type,
            title=title,
            source_module=_source_text(sources),
            confidence=confidence,
            detail=detail,
            is_recent=0 <= days_old <= _RECENT_DAYS,
            is_active_risk=active_risk,
        )
        return _Candidate(
            event=event,
            sort_date=parsed.sort_date,
            sources=sources,
            dedupe_key=dedupe_key,
        )

    def _github_events(self, module_name: str, payload: dict[str, Any]) -> list[_Candidate]:
        meta = _metadata(payload)
        parsed = _coerce_date(meta.get("commit_date") or payload.get("commit_date"))
        if parsed is None:
            return []

        repo = str(meta.get("repo") or "").strip()
        sha = str(meta.get("commit_sha") or "").strip()
        message = str(meta.get("commit_message") or "").strip()
        detail = _detail_join([sha, message]) or message or sha or None
        title = repo or "GitHub commit"
        event = self._make_event(
            parsed=parsed,
            event_type="commit",
            title=title,
            module_name=module_name,
            payload=payload,
            confidence="high",
            detail=detail,
        )
        return [event] if event else []

    def _wayback_events(self, module_name: str, payload: dict[str, Any]) -> list[_Candidate]:
        meta = _metadata(payload)
        parsed = _coerce_date(meta.get("archive_date") or payload.get("archive_date"))
        if parsed is None:
            return []

        domain = str(meta.get("original_domain") or "").strip()
        original_url = str(
            meta.get("original_url")
            or payload.get("url")
            or payload.get("profile_url")
            or ""
        ).strip()
        title = "Wayback archive snapshot" if not domain else f"Wayback snapshot ({domain})"
        detail = _detail_join([original_url, meta.get("page_title")])
        event = self._make_event(
            parsed=parsed,
            event_type="archive_snapshot",
            title=title,
            module_name=module_name,
            payload=payload,
            confidence="high",
            detail=detail,
        )
        return [event] if event else []

    def _hudson_rock_events(self, module_name: str, payload: dict[str, Any]) -> list[_Candidate]:
        meta = _metadata(payload)
        date_value = (
            meta.get("last_compromised")
            or payload.get("last_compromised")
            or meta.get("date_compromised")
            or meta.get("last_seen")
            or meta.get("first_seen")
        )
        parsed = _coerce_date(date_value)
        if parsed is None:
            return []

        platform = str(payload.get("platform") or "").strip()
        families = ", ".join(_string_list(meta.get("stealer_families")))
        credential_type = str(meta.get("credential_type") or "").strip()
        detail = _detail_join(
            [platform if platform != "hudson_rock" else None, families, credential_type]
        )
        title = "Hudson Rock infostealer log"
        event = self._make_event(
            parsed=parsed,
            event_type="stealer_log",
            title=title,
            module_name=module_name,
            payload=payload,
            confidence="high",
            detail=detail,
            active_risk=True,
        )
        return [event] if event else []

    def _emailrep_events(self, module_name: str, payload: dict[str, Any]) -> list[_Candidate]:
        meta = _metadata(payload)
        if meta.get("last_seen"):
            self._metadata["emailrep_last_seen"] = str(meta.get("last_seen"))

        parsed = _coerce_date(meta.get("first_seen") or payload.get("first_seen"))
        if parsed is None:
            return []

        detail = _detail_join(
            [
                "EmailRep estimate",
                f"last_seen={meta.get('last_seen')}" if meta.get("last_seen") else None,
            ]
        )
        event = self._make_event(
            parsed=parsed,
            event_type="first_seen",
            title="EmailRep first seen",
            module_name=module_name,
            payload=payload,
            confidence="medium",
            detail=detail,
        )
        return [event] if event else []

    def _gravatar_events(self, module_name: str, payload: dict[str, Any]) -> list[_Candidate]:
        meta = _metadata(payload)
        date_value = None
        for key in (
            "joined",
            "joined_at",
            "join_date",
            "created",
            "created_at",
            "profile_created",
            "account_created",
        ):
            date_value = meta.get(key) or payload.get(key)
            if date_value:
                break
        parsed = _coerce_date(date_value)
        if parsed is None:
            return []

        event = self._make_event(
            parsed=parsed,
            event_type="account_created",
            title="Gravatar account created",
            module_name=module_name,
            payload=payload,
            confidence=_confidence(payload.get("confidence"), "medium"),
            detail=str(payload.get("url") or meta.get("profile_url") or "") or None,
        )
        return [event] if event else []

    def _breach_or_paste_events(
        self, module_name: str, payload: dict[str, Any]
    ) -> list[_Candidate]:
        meta = _metadata(payload)
        signal_type = str(payload.get("signal_type") or "").lower()
        if module_name == "xposedornot" and signal_type == "paste_exposure":
            parsed = _coerce_date(meta.get("date") or payload.get("date"))
            if parsed is None:
                return []
            title = str(meta.get("paste_source") or payload.get("platform") or "Paste exposure")
            event = self._make_event(
                parsed=parsed,
                event_type="paste",
                title=title,
                module_name=module_name,
                payload=payload,
                confidence=_confidence(payload.get("confidence"), "high"),
                detail=_detail_join([meta.get("email_count"), payload.get("url")]),
            )
            return [event] if event else []

        if module_name == "leakcheck" and signal_type == "stealer_signal":
            parsed = _coerce_date(
                meta.get("breach_date") or meta.get("date") or payload.get("date")
            )
            if parsed is None:
                return []
            event = self._make_event(
                parsed=parsed,
                event_type="stealer_log",
                title="LeakCheck stealer source",
                module_name=module_name,
                payload=payload,
                confidence=_confidence(payload.get("confidence"), "medium"),
                detail=str(payload.get("platform") or meta.get("source_category") or "") or None,
                active_risk=True,
            )
            return [event] if event else []

        if payload.get("source") == "breach_confirmed":
            return []

        parsed = _breach_date(payload, module_name)
        if parsed is None:
            return []

        name = _breach_name(payload) or "Unknown breach"
        classes = _data_classes(payload)
        records = _count_text(
            payload.get("pwn_count")
            or payload.get("exposed_records")
            or meta.get("pwn_count")
            or meta.get("exposed_records")
        )
        detail = _detail_join(
            [", ".join(classes), records, meta.get("domain") or payload.get("domain")]
        )
        active = parsed.year >= self.as_of.year - 2 and _has_password_data(payload)
        event = self._make_event(
            parsed=parsed,
            event_type="breach",
            title=f"{name} breach" if "breach" not in name.lower() else name,
            module_name=module_name,
            payload=payload,
            confidence="medium",
            detail=detail,
            active_risk=active,
            dedupe_key=_breach_dedupe_key(payload, module_name),
        )
        return [event] if event else []

    def _dedupe(self, candidates: list[_Candidate]) -> list[_Candidate]:
        merged_by_breach: dict[tuple[str, str], _Candidate] = {}
        passthrough: list[_Candidate] = []

        for candidate in candidates:
            if candidate.dedupe_key is None:
                passthrough.append(candidate)
                continue
            existing = merged_by_breach.get(candidate.dedupe_key)
            if existing is None:
                merged_by_breach[candidate.dedupe_key] = candidate
                continue
            self._merge_candidate(existing, candidate, prefer_earliest=True)

        grouped = passthrough + list(merged_by_breach.values())
        grouped.sort(key=lambda candidate: candidate.sort_date)

        collapsed: list[_Candidate] = []
        for candidate in grouped:
            if candidate.event.event_type == "commit":
                collapsed.append(candidate)
                continue
            match = next(
                (
                    existing
                    for existing in reversed(collapsed)
                    if existing.event.event_type == candidate.event.event_type
                    and existing.event.source_module == candidate.event.source_module
                    and abs((candidate.sort_date - existing.sort_date).days) <= 30
                ),
                None,
            )
            if match is None:
                collapsed.append(candidate)
                continue
            self._merge_candidate(match, candidate, prefer_earliest=True)

        return collapsed

    def _merge_candidate(
        self,
        target: _Candidate,
        incoming: _Candidate,
        *,
        prefer_earliest: bool,
    ) -> None:
        target.count += incoming.count
        for source in incoming.sources:
            if source not in target.sources:
                target.sources.append(source)
        target.event.source_module = _source_text(target.sources)
        target.event.confidence = _higher_confidence(
            target.event.confidence, incoming.event.confidence
        )
        target.event.is_active_risk = target.event.is_active_risk or incoming.event.is_active_risk
        target.event.is_recent = target.event.is_recent or incoming.event.is_recent

        details = [target.event.detail, incoming.event.detail]
        if target.count > 1 and "events collapsed" not in str(target.event.detail or ""):
            details.append(f"{target.count} events collapsed")
        target.event.detail = _detail_join(details)

        should_replace_date = (
            incoming.sort_date < target.sort_date
            if prefer_earliest
            else incoming.sort_date > target.sort_date
        )
        if should_replace_date:
            target.sort_date = incoming.sort_date
            target.event.date = incoming.event.date
            target.event.year = incoming.event.year


def build_timeline(findings: list[Any]) -> Timeline:
    return TimelineBuilder().build_timeline(findings)
