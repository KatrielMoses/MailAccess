from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import httpx

from ..platforms.schema import PlatformCheck
from .user_agents import random_user_agent


def _split_alternatives(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split("|") if part.strip()]


def _substitute(value: str, context: dict[str, str]) -> str:
    result = value
    for key, replacement in context.items():
        result = result.replace(f"{{{key}}}", replacement)
    return result


def _substitute_deep(obj: Any, context: dict[str, str]) -> Any:
    if isinstance(obj, str):
        return _substitute(obj, context)
    if isinstance(obj, dict):
        return {k: _substitute_deep(v, context) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_substitute_deep(item, context) for item in obj]
    return obj


def _get_json_path(data: Any, path: str) -> Any:
    if not path:
        return data
    current = data
    for part in path.split("."):
        if current is None:
            return None
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (IndexError, ValueError, TypeError):
                return None
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _response_text(resp: httpx.Response) -> str:
    try:
        return resp.text
    except Exception:
        return resp.content.decode("utf-8", errors="ignore")


def _is_rate_limited(text: str, platform: PlatformCheck) -> bool:
    lowered = text.lower()
    for marker in platform.rate_limited_strings:
        if marker.lower() in lowered:
            return True
    return False


def _extract_from_source(
    source: Any, extract: dict[str, str], context: dict[str, str]
) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    for field, spec in extract.items():
        if spec.startswith("regex:"):
            pattern = spec[6:]
            text = source if isinstance(source, str) else json.dumps(source)
            match = re.search(pattern, text)
            if match:
                metadata[field] = match.group(1) if match.groups() else match.group(0)
        else:
            value = _get_json_path(source, spec)
            if value is not None:
                metadata[field] = value
    for key, value in list(metadata.items()):
        if isinstance(value, str):
            metadata[key] = _substitute(value, context)
    return {k: v for k, v in metadata.items() if v is not None}


def _finding(
    platform: PlatformCheck,
    *,
    profile_url: str | None = None,
    metadata: dict[str, Any] | None = None,
    platform_label: str | None = None,
) -> dict[str, Any]:
    meta: dict[str, Any] = dict(metadata or {})
    if platform.notes and "note" not in meta and "flag" not in meta:
        meta["note"] = platform.notes
    return {
        "platform": platform_label or platform.name,
        "profile_url": profile_url,
        "metadata": meta,
        "confidence": platform.confidence,
    }


class PlatformExecutor:
    async def check(
        self,
        platform: PlatformCheck,
        email: str,
        client: httpx.AsyncClient,
        *,
        gravatar_data: dict[str, Any] | None = None,
        username: str | None = None,
    ) -> dict[str, Any] | None:
        slug = platform.slug
        if slug == "gravatar_linked":
            return await self._check_gravatar_linked(platform, email, client, gravatar_data)
        if slug == "duolingo":
            return await self._check_duolingo(platform, email, client)
        if slug == "adobe":
            return await self._check_adobe(platform, email, client)
        return await self._check_generic(platform, email, client, username=username)

    async def _request(
        self,
        platform: PlatformCheck,
        email: str,
        client: httpx.AsyncClient,
        *,
        username: str | None = None,
        extra_context: dict[str, str] | None = None,
        url: str | None = None,
        method: str | None = None,
        headers: dict | None = None,
        body: dict | None = None,
    ) -> httpx.Response | None:
        email_clean = email.strip().lower()
        md5_hash = hashlib.md5(email_clean.encode("utf-8")).hexdigest()
        context: dict[str, str] = {
            "email": email,
            "username": username or email.split("@")[0],
            "md5": md5_hash,
        }
        if extra_context:
            context.update(extra_context)

        req_url = _substitute(url or platform.url, context)
        req_headers = {"User-Agent": random_user_agent(), **(platform.headers or {})}
        if headers:
            req_headers.update(headers)
        req_body = _substitute_deep(body if body is not None else platform.body, context)
        req_method = (method or platform.method).upper()

        try:
            if req_method == "GET":
                return await client.get(
                    req_url,
                    headers=req_headers,
                    timeout=platform.timeout,
                )
            content_type = req_headers.get("Content-Type", "")
            if "application/json" in content_type:
                return await client.post(
                    req_url,
                    headers=req_headers,
                    json=req_body,
                    timeout=platform.timeout,
                )
            return await client.post(
                req_url,
                headers=req_headers,
                data=req_body,
                timeout=platform.timeout,
            )
        except httpx.TimeoutException:
            return None
        except Exception:
            return None

    async def _check_generic(
        self,
        platform: PlatformCheck,
        email: str,
        client: httpx.AsyncClient,
        *,
        username: str | None = None,
    ) -> dict[str, Any] | None:
        slug = platform.slug
        try:
            try:
                extracted: dict[str, Any] = {}
                if platform.multi_step:
                    resp, extracted = await self._run_multi_step(
                        platform,
                        email,
                        client,
                        username=username,
                    )
                else:
                    resp = await self._request(platform, email, client, username=username)
            except Exception:
                if slug == "spotify":
                    return {"findings": []}
                raise

            if resp is None:
                if slug == "spotify":
                    return {"findings": []}
                if slug == "linkedin":
                    return {"rate_limited": True}
                return None

            if slug == "linkedin" and resp.status_code == 999:
                return {"rate_limited": True}
            if slug == "linkedin" and resp.status_code in (403, 429):
                return {"rate_limited": True}
            if slug == "patreon" and resp.status_code in (403, 429, 503):
                return {"findings": []}

            text = _response_text(resp)
            if _is_rate_limited(text, platform):
                return {"rate_limited": True}

            success = self._evaluate_success(platform, resp, text, slug)
            if not success:
                return None

            metadata = self._build_metadata(platform, slug)
            metadata.update(extracted)
            context = {"email": email, "username": username or email.split("@")[0]}

            if platform.extract and platform.check_type == "json_field":
                try:
                    metadata.update(
                        _extract_from_source(resp.json(), platform.extract, context)
                    )
                except Exception:
                    pass
            elif slug == "skype_microsoft" and resp.status_code == 200:
                try:
                    resp_data = resp.json()
                    if "DisplayName" in resp_data:
                        metadata["DisplayName"] = resp_data["DisplayName"]
                    if "MemberName" in resp_data:
                        metadata["MemberName"] = resp_data["MemberName"]
                except Exception:
                    pass

            profile_url: str | None = None
            if "profile_url" in metadata:
                profile_url = str(metadata.pop("profile_url"))

            platform_label = platform.name
            if slug in ("skype_microsoft", "zoom", "dropbox", "apple", "linkedin", "discord"):
                platform_label = slug

            return _finding(
                platform,
                profile_url=profile_url,
                metadata=metadata,
                platform_label=platform_label,
            )
        except httpx.TimeoutException:
            if slug == "linkedin":
                return {"rate_limited": True}
            return None
        except Exception as exc:
            err = repr(exc) if slug == "linkedin" and not str(exc) else str(exc)
            return {"error": f"{platform.name} failed: {err}"}

    async def _run_multi_step(
        self,
        platform: PlatformCheck,
        email: str,
        client: httpx.AsyncClient,
        *,
        username: str | None = None,
    ) -> tuple[httpx.Response | None, dict[str, Any]]:
        context: dict[str, str] = {}
        extracted: dict[str, Any] = {}
        response: httpx.Response | None = None

        for step in platform.multi_step or []:
            response = await self._request(
                platform,
                email,
                client,
                username=username,
                extra_context=context,
                url=step.url,
                method=step.method,
                headers=step.headers,
                body=step.body,
            )
            if response is None:
                return None, {}

            step_values = self._extract_step_fields(response, step.extract_fields)
            extracted.update(step_values)
            context.update({key: str(value) for key, value in step_values.items()})

        return response, extracted

    @staticmethod
    def _extract_step_fields(
        response: httpx.Response,
        extract_fields: dict[str, str],
    ) -> dict[str, Any]:
        extracted: dict[str, Any] = {}
        text = _response_text(response)
        json_data: Any = None
        json_loaded = False

        for field, spec in extract_fields.items():
            if spec.startswith("regex:"):
                match = re.search(spec[6:], text)
                if match:
                    extracted[field] = match.group(1) if match.groups() else match.group(0)
                continue

            if not json_loaded:
                json_loaded = True
                try:
                    json_data = response.json()
                except Exception:
                    json_data = None
            value = _get_json_path(json_data, spec)
            if value is not None:
                extracted[field] = value

        return extracted

    def _evaluate_success(
        self,
        platform: PlatformCheck,
        resp: httpx.Response,
        text: str,
        slug: str,
    ) -> bool:
        if slug == "linkedin":
            lowered = text.lower()
            unregistered = _split_alternatives(
                "could not find|don't recognize|not recognized|"
                "not associated|invalid|not found|please try again"
            )
            if any(marker.lower() in lowered for marker in unregistered):
                success = False
            else:
                success = resp.status_code in (200, 302)
        elif slug == "apple" and resp.status_code == 200:
            try:
                data = resp.json()
                success = any(
                    data.get(key) is True for key in ("used", "exists", "isUsed")
                )
            except Exception:
                success = False
        elif slug == "discord":
            try:
                data = resp.json()
                success = "email" in data.get("errors", {})
            except Exception:
                success = False
        elif platform.check_type == "status":
            success = resp.status_code == platform.success_status
        elif platform.check_type == "body_contains":
            lowered = text.lower()
            markers = _split_alternatives(platform.success_string)
            matches = sum(marker.lower() in lowered for marker in markers)
            if platform.presence_threshold > 0.0:
                success = bool(markers) and matches / len(markers) >= platform.presence_threshold
            else:
                success = not markers or matches > 0
        elif platform.check_type == "body_not_contains":
            lowered = text.lower()
            markers = _split_alternatives(platform.failure_string)
            success = not any(marker.lower() in lowered for marker in markers)
        elif resp.status_code != platform.success_status:
            success = False
        else:
            try:
                data = resp.json()
            except Exception:
                success = False
            else:
                if platform.json_success_path:
                    value = _get_json_path(data, platform.json_success_path)
                    if platform.json_success_value is None:
                        success = value == 0 if slug == "skype_microsoft" else bool(value)
                    else:
                        success = str(value) == str(platform.json_success_value)
                else:
                    success = bool(data)

        if not success:
            return False

        lowered = text.lower()
        if platform.absence_strings and any(
            marker.lower() in lowered for marker in platform.absence_strings
        ):
            return False
        if (
            platform.min_content_length is not None
            and len(resp.content) < platform.min_content_length
        ):
            return False
        return True

    def _build_metadata(self, platform: PlatformCheck, slug: str) -> dict[str, Any]:
        if not platform.notes:
            return {}
        if slug in ("spotify", "patreon", "zoom", "dropbox", "snapchat"):
            return {"note": platform.notes}
        if slug in ("apple", "discord"):
            return {"flag": platform.notes}
        if slug == "linkedin":
            return {
                "flag": platform.notes,
                "note": "LinkedIn aggressively blocks scrapers",
            }
        return {"note": platform.notes}

    async def _check_duolingo(
        self,
        platform: PlatformCheck,
        email: str,
        client: httpx.AsyncClient,
    ) -> dict[str, Any] | None:
        try:
            resp = await self._request(platform, email, client)
            if resp is None:
                return None
            if resp.status_code != 200:
                return {"error": f"Duolingo HTTP {resp.status_code}"}
            data = resp.json()
            users = data.get("users", [])
            findings: list[dict[str, Any]] = []
            for user in users:
                metadata: dict[str, Any] = {
                    "username": user.get("username"),
                    "display_name": user.get("name"),
                    "avatar_url": user.get("picture"),
                    "streak": user.get("streak"),
                    "joined_date": user.get("creationDate"),
                }
                learning: list[str] = []
                for course in user.get("courses", []):
                    lang = course.get("learningLanguage")
                    if lang:
                        learning.append(lang)
                if learning:
                    metadata["learning_languages"] = learning
                metadata = {k: v for k, v in metadata.items() if v is not None}
                username = user.get("username")
                findings.append(
                    _finding(
                        platform,
                        profile_url=(
                            f"https://www.duolingo.com/profile/{username}" if username else None
                        ),
                        metadata=metadata,
                    )
                )
            return {"findings": findings}
        except Exception as exc:
            return {"error": f"Duolingo failed: {exc!s}"}

    async def _check_adobe(
        self,
        platform: PlatformCheck,
        email: str,
        client: httpx.AsyncClient,
    ) -> dict[str, Any] | None:
        try:
            resp = await self._request(platform, email, client)
            if resp is None:
                return None
            exists_meta = {"note": "Account exists"}
            exists_finding = {"findings": [_finding(platform, metadata=exists_meta)]}
            if resp.status_code == 200:
                try:
                    resp_data = resp.json()
                    if isinstance(resp_data, list) and len(resp_data) > 0:
                        return exists_finding
                    if isinstance(resp_data, dict) and resp_data.get("users"):
                        return exists_finding
                except Exception:
                    if "not found" not in _response_text(resp).lower():
                        return exists_finding
            elif resp.status_code in (400, 404):
                return {"findings": []}
            return {"error": f"Adobe HTTP {resp.status_code}"}
        except Exception as exc:
            return {"error": f"Adobe failed: {exc!s}"}

    async def _check_gravatar_linked(
        self,
        platform: PlatformCheck,
        email: str,
        client: httpx.AsyncClient,
        gravatar_data: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        try:
            findings: list[dict[str, Any]] = []
            accounts: list[dict[str, Any]] = []

            if gravatar_data and "accounts" in gravatar_data:
                accounts = gravatar_data["accounts"]
            else:
                email_clean = email.strip().lower()
                md5_hash = hashlib.md5(email_clean.encode("utf-8")).hexdigest()
                url = f"https://www.gravatar.com/{md5_hash}.json"
                resp = await client.get(
                    url,
                    headers={"User-Agent": random_user_agent()},
                    timeout=platform.timeout,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("entry"):
                        entry = data["entry"][0]
                        accounts = entry.get("accounts", [])
                elif resp.status_code != 404:
                    return {"error": f"Gravatar HTTP {resp.status_code}"}

            for acc in accounts:
                shortname = acc.get("shortname", "Unknown")
                profile_url = acc.get("url")
                if not profile_url:
                    continue
                findings.append(
                    _finding(
                        platform,
                        profile_url=profile_url,
                        metadata=dict(acc),
                        platform_label=f"Gravatar Linked: {shortname.capitalize()}",
                    )
                )
            return {"findings": findings}
        except Exception as exc:
            return {"error": f"Gravatar check failed: {exc!s}"}
