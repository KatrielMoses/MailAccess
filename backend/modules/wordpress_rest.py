from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx

from ..core.concurrent_fetch_cache import CachedFetch
from ..core.signal_pool import AsyncSignalPool, Signal
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

_MAX_PAGES = 20
_MAX_USERS = 2000
_PER_PAGE = 100
_WORDPRESS_USERS_PATH = "/wp-json/wp/v2/users"
_GRAVATAR_HASH_RE = re.compile(r"/avatar/([0-9a-f]{32})(?:[/?#]|$)", re.IGNORECASE)


def _normalize_target(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        return ""
    if "@" in raw and "://" not in raw:
        raw = raw.rsplit("@", 1)[-1].strip()
    if "://" in raw:
        parsed = urlsplit(raw)
        host = parsed.netloc.strip()
        if not host:
            return ""
        scheme = parsed.scheme or "https"
        return urlunsplit((scheme, host, "", "", "")).rstrip("/")
    return f"https://{raw.rstrip('/')}"


def _users_url(origin: str, page: int) -> str:
    query = urlencode({"per_page": _PER_PAGE, "page": page})
    return f"{origin.rstrip('/')}{_WORDPRESS_USERS_PATH}?{query}"


def _is_json_like(response: Any) -> bool:
    headers = getattr(response, "headers", {}) or {}
    content_type = ""
    if isinstance(headers, dict):
        content_type = str(headers.get("content-type") or headers.get("Content-Type") or "")
    else:
        try:
            content_type = str(headers.get("content-type") or headers.get("Content-Type") or "")
        except Exception:  # noqa: BLE001
            content_type = ""
    if "json" in content_type.lower():
        return True
    text = str(getattr(response, "text", "") or "").lstrip()
    return text.startswith("{") or text.startswith("[")


def _extract_avatar_hashes(avatar_urls: Any) -> list[str]:
    hashes: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for item in value.values():
                visit(item)
            return
        if isinstance(value, list):
            for item in value:
                visit(item)
            return
        if not isinstance(value, str):
            return
        for match in _GRAVATAR_HASH_RE.finditer(value):
            hashes.add(match.group(1).lower())

    visit(avatar_urls)
    return sorted(hashes)


def _first_string(value: Any) -> str:
    return str(value).strip() if isinstance(value, str) and value.strip() else ""


class WordPressRestModule(BaseModule):
    name = "wordpress_rest"
    description = "Enumerate public WordPress author data from wp-json users endpoints."
    requires_key = False
    default_enabled = False

    async def run(
        self,
        target: str,
        *,
        fetch: CachedFetch | None = None,
        pool: AsyncSignalPool | None = None,
        **_unused: Any,
    ) -> ModuleResult:  # type: ignore[override]
        origin = _normalize_target(target)
        if not origin:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["wordpress_rest: invalid target"],
                metadata={"target": target, "skip_reason": "invalid_target"},
            )

        try:
            if fetch is None:
                async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
                    return await self._run_with_fetch(origin, client, pool)
            else:
                return await self._run_with_fetch(origin, fetch, pool)
        except Exception as exc:  # noqa: BLE001
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                findings=[],
                errors=[f"wordpress_rest: unexpected error: {exc}"],
                metadata={"target": origin, "users_found": 0, "signals_published": 0},
            )

    async def _run_with_fetch(
        self,
        origin: str,
        fetch: Any,
        pool: AsyncSignalPool | None,
    ) -> ModuleResult:
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        total_users = 0
        signals_published = 0
        pages_fetched = 0

        for page in range(1, _MAX_PAGES + 1):
            if total_users >= _MAX_USERS:
                break
            url = _users_url(origin, page)
            try:
                response = await fetch.get(url)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"wordpress_rest: fetch failed on page {page}: {exc}")
                return ModuleResult(
                    status=ModuleStatus.PARTIAL,
                    findings=findings,
                    errors=errors,
                    metadata={
                        "target": origin,
                        "pages_fetched": pages_fetched,
                        "users_found": total_users,
                        "signals_published": signals_published,
                    },
                )

            pages_fetched += 1
            status = int(getattr(response, "status_code", 0) or 0)
            if status in (401, 403):
                errors.append(f"wordpress_rest: endpoint returned HTTP {status}")
                return ModuleResult(
                    status=ModuleStatus.PARTIAL,
                    findings=findings,
                    errors=errors,
                    metadata={
                        "target": origin,
                        "pages_fetched": pages_fetched,
                        "users_found": total_users,
                        "signals_published": signals_published,
                    },
                )
            if status == 404:
                break
            if status != 200:
                errors.append(f"wordpress_rest: endpoint returned HTTP {status}")
                break
            if not _is_json_like(response):
                errors.append("wordpress_rest: endpoint returned non-JSON content")
                return ModuleResult(
                    status=ModuleStatus.PARTIAL,
                    findings=findings,
                    errors=errors,
                    metadata={
                        "target": origin,
                        "pages_fetched": pages_fetched,
                        "users_found": total_users,
                        "signals_published": signals_published,
                    },
                )

            try:
                payload = json.loads(str(getattr(response, "text", "") or ""))
            except Exception:
                errors.append("wordpress_rest: endpoint returned invalid JSON")
                return ModuleResult(
                    status=ModuleStatus.PARTIAL,
                    findings=findings,
                    errors=errors,
                    metadata={
                        "target": origin,
                        "pages_fetched": pages_fetched,
                        "users_found": total_users,
                        "signals_published": signals_published,
                    },
                )

            if not isinstance(payload, list):
                errors.append("wordpress_rest: endpoint returned non-list JSON")
                return ModuleResult(
                    status=ModuleStatus.PARTIAL,
                    findings=findings,
                    errors=errors,
                    metadata={
                        "target": origin,
                        "pages_fetched": pages_fetched,
                        "users_found": total_users,
                        "signals_published": signals_published,
                    },
                )

            if not payload:
                break

            page_signals: list[Signal] = []
            for raw_user in payload:
                if not isinstance(raw_user, dict):
                    continue
                user = self._render_user(raw_user, origin, page)
                if user is None:
                    continue
                findings.append(user["finding"])
                page_signals.extend(user["signals"])
                total_users += 1
                if total_users >= _MAX_USERS:
                    break

            if pool is not None and page_signals:
                await pool.publish_many(page_signals)
            signals_published += len(page_signals)

            if len(payload) < _PER_PAGE:
                break

        return ModuleResult(
            status=ModuleStatus.PARTIAL if errors else ModuleStatus.SUCCESS,
            findings=findings,
            errors=errors,
            metadata={
                "target": origin,
                "pages_fetched": pages_fetched,
                "users_found": total_users,
                "signals_published": signals_published,
            },
        )

    def _render_user(
        self,
        user: dict[str, Any],
        origin: str,
        page: int,
    ) -> dict[str, Any] | None:
        name = _first_string(user.get("name"))
        slug = _first_string(user.get("slug"))
        link = _first_string(user.get("link"))
        description = _first_string(user.get("description"))
        email = _first_string(user.get("email"))
        avatar_urls = user.get("avatar_urls")
        avatar_hashes = _extract_avatar_hashes(avatar_urls)

        if not any((name, slug, link, description, email)):
            return None

        slug_or_email = email.split("@", 1)[0] if email and "@" in email else slug
        meta: dict[str, Any] = {
            "source": "wordpress_rest",
            "endpoint": f"{origin.rstrip('/')}{_WORDPRESS_USERS_PATH}",
            "page": page,
            "name": name or None,
            "slug": slug or None,
            "slug_or_email": slug_or_email or None,
            "link": link or None,
            "description": description or None,
            "avatar_urls": avatar_urls if isinstance(avatar_urls, dict) else avatar_urls or None,
            "avatar_hashes": avatar_hashes,
        }
        if email:
            meta["email"] = email

        signals: list[Signal] = []
        if name:
            signals.append(
                Signal(
                    source=self.name,
                    kind="name",
                    value=name,
                    metadata=meta,
                )
            )
        if email:
            signals.append(
                Signal(
                    source=self.name,
                    kind="email",
                    value=email,
                    metadata=meta,
                )
            )
        elif slug:
            signals.append(
                Signal(
                    source=self.name,
                    kind="slug",
                    value=slug,
                    metadata=meta,
                )
            )
        if name or slug or email:
            signals.append(
                Signal(
                    source=self.name,
                    kind="schema",
                    value=name or email or slug,
                    metadata=meta,
                )
            )

        finding: dict[str, Any] = {
            "platform": "wordpress_rest_user",
            "profile_url": link or "",
            "username": slug or (email.split("@", 1)[0] if email and "@" in email else ""),
            "confidence": "high",
            "metadata": meta,
        }
        return {"finding": finding, "signals": signals}
