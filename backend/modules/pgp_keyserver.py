from __future__ import annotations

import asyncio
import re
import shutil
from datetime import datetime
from typing import Any

import httpx

from ..core.http_client import build_client
from ..core.rate_limiter import rate_limiter
from .base import BaseModule, ModuleResult, ModuleStatus

_OPENPGP_BY_EMAIL = "https://keys.openpgp.org/vks/v1/by-email/{email}"
_OPENPGP_SEARCH = "https://keys.openpgp.org/search?q={email}"
_UBUNTU_LOOKUP = "https://keyserver.ubuntu.com/pks/lookup"
_ARMOR_RE = re.compile(r"(?s)-----BEGIN PGP.*?-----END PGP")
_UID_RE = re.compile(r"^(?:uid\s+)?(.+?)\s*<([^>]+)>", re.MULTILINE)
_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z'`.-]+(?:\s+[A-Za-z][A-Za-z'`.-]+)+$")


class PGPKeyserverModule(BaseModule):
    name = "pgp_keyserver"
    description = "Look up public PGP keys and extract real names from key UIDs."
    requires_key = False
    default_enabled = True

    async def run(self, email: str) -> ModuleResult:
        rate_limiter.set_delay("keys.openpgp.org", 1.0)
        rate_limiter.set_delay("keyserver.ubuntu.com", 1.0)

        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        async with build_client(timeout=10.0, follow_redirects=True) as client:
            armor, source, fetch_errors = await self._fetch_key(client, email)
            errors.extend(fetch_errors)

        if not armor:
            return ModuleResult(
                status=ModuleStatus.PARTIAL if errors else ModuleStatus.SUCCESS,
                findings=[],
                metadata={"keys_found": 0},
                errors=errors,
            )

        try:
            key_data = await self._parse_key(armor)
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[*errors, f"PGP key parse error: {exc}"],
                metadata={"keys_found": 1},
            )

        all_uids = key_data.get("all_uids", [])
        for uid in key_data.get("uids", []):
            uid_name = str(uid.get("name") or "").strip()
            uid_email = str(uid.get("email") or "").strip()
            if not _valid_name(uid_name):
                continue
            findings.append(
                {
                    "platform": "pgp_keyserver",
                    "profile_url": _OPENPGP_SEARCH.format(email=email),
                    "confidence": "high",
                    "metadata": {
                        "uid_name": uid_name,
                        "uid_email": uid_email,
                        "key_id": key_data.get("key_id") or "",
                        "key_fingerprint": key_data.get("key_fingerprint") or "",
                        "key_created": key_data.get("key_created") or "",
                        "key_algorithm": key_data.get("key_algorithm") or "",
                        "source": source,
                        "all_uids": all_uids,
                    },
                }
            )

        status = ModuleStatus.PARTIAL if errors else ModuleStatus.SUCCESS
        return ModuleResult(
            status=status,
            findings=findings,
            metadata={"keys_found": 1, "uids_found": len(all_uids)},
            errors=errors,
        )

    async def _fetch_key(
        self, client: httpx.AsyncClient, email: str
    ) -> tuple[str | None, str, list[str]]:
        errors: list[str] = []
        try:
            response = await client.get(_OPENPGP_BY_EMAIL.format(email=email))
        except httpx.TimeoutException:
            return None, "openpgp", ["OpenPGP key lookup timed out"]
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            return None, "openpgp", [f"OpenPGP key lookup network error: {exc}"]
        except Exception as exc:
            return None, "openpgp", [f"OpenPGP key lookup error: {exc}"]

        if response.status_code == 200 and response.text.strip():
            return response.text, "openpgp", errors
        if response.status_code != 404:
            errors.append(f"OpenPGP key lookup returned HTTP {response.status_code}")
            return None, "openpgp", errors

        try:
            fallback = await client.get(
                _UBUNTU_LOOKUP,
                params={"op": "get", "search": email, "options": "mr"},
            )
        except httpx.TimeoutException:
            return None, "ubuntu_keyserver", ["Ubuntu keyserver lookup timed out"]
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            return None, "ubuntu_keyserver", [f"Ubuntu keyserver network error: {exc}"]
        except Exception as exc:
            return None, "ubuntu_keyserver", [f"Ubuntu keyserver lookup error: {exc}"]

        if fallback.status_code in (404, 400):
            return None, "ubuntu_keyserver", []
        if fallback.status_code != 200:
            return None, "ubuntu_keyserver", [f"Ubuntu keyserver returned HTTP {fallback.status_code}"]
        match = _ARMOR_RE.search(fallback.text)
        return (match.group(0) if match else fallback.text), "ubuntu_keyserver", []

    async def _parse_key(self, armor: str) -> dict[str, Any]:
        parsed = self._parse_with_pgpy(armor)
        if parsed:
            return parsed

        parsed = await self._parse_with_gpg(armor)
        if parsed:
            return parsed

        uids = [{"name": m.group(1).strip(), "email": m.group(2).strip()} for m in _UID_RE.finditer(armor)]
        return {"uids": uids, "all_uids": [f"{u['name']} <{u['email']}>" for u in uids]}

    def _parse_with_pgpy(self, armor: str) -> dict[str, Any] | None:
        try:
            import pgpy  # type: ignore
        except Exception:
            return None

        key, _ = pgpy.PGPKey.from_blob(armor)
        fingerprint = str(getattr(key, "fingerprint", "") or "")
        created = getattr(key, "created", None)
        algorithm = str(getattr(getattr(key, "key_algorithm", None), "name", "") or getattr(key, "key_algorithm", "") or "")
        uids: list[dict[str, str]] = []
        all_uids: list[str] = []
        for user_id in getattr(key, "userids", []) or []:
            name = str(getattr(user_id, "name", "") or "").strip()
            email = str(getattr(user_id, "email", "") or "").strip()
            uid_text = f"{name} <{email}>" if email else name
            all_uids.append(uid_text)
            uids.append({"name": name, "email": email})
        return {
            "uids": uids,
            "all_uids": all_uids,
            "key_id": fingerprint[-16:] if fingerprint else "",
            "key_fingerprint": fingerprint,
            "key_created": _iso_date(created),
            "key_algorithm": algorithm,
        }

    async def _parse_with_gpg(self, armor: str) -> dict[str, Any] | None:
        if not shutil.which("gpg"):
            return None
        proc = await asyncio.create_subprocess_exec(
            "gpg",
            "--batch",
            "--with-colons",
            "--show-keys",
            "--import-options",
            "show-only",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate(armor.encode("utf-8", errors="ignore"))
        if proc.returncode not in (0, None):
            return None
        lines = stdout.decode("utf-8", errors="ignore").splitlines()
        uids: list[dict[str, str]] = []
        all_uids: list[str] = []
        key_id = ""
        fingerprint = ""
        created = ""
        algorithm = ""
        for line in lines:
            parts = line.split(":")
            if not parts:
                continue
            if parts[0] == "pub":
                algorithm = parts[3] if len(parts) > 3 else ""
                key_id = parts[4] if len(parts) > 4 else ""
                created = _unix_to_iso(parts[5] if len(parts) > 5 else "")
            elif parts[0] == "fpr" and len(parts) > 9 and not fingerprint:
                fingerprint = parts[9]
            elif parts[0] == "uid" and len(parts) > 9:
                uid_text = parts[9]
                all_uids.append(uid_text)
                match = _UID_RE.match(uid_text)
                if match:
                    uids.append({"name": match.group(1).strip(), "email": match.group(2).strip()})
        return {
            "uids": uids,
            "all_uids": all_uids,
            "key_id": key_id[-16:] if key_id else fingerprint[-16:],
            "key_fingerprint": fingerprint,
            "key_created": created,
            "key_algorithm": algorithm,
        }


def _valid_name(value: str) -> bool:
    value = " ".join(value.split())
    return bool(value and not any(ch.isdigit() for ch in value) and _NAME_RE.match(value))


def _iso_date(value: Any) -> str:
    if isinstance(value, datetime):
        return value.date().isoformat()
    return str(value or "")


def _unix_to_iso(value: str) -> str:
    try:
        return datetime.utcfromtimestamp(int(value)).date().isoformat()
    except Exception:
        return ""
