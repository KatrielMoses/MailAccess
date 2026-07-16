"""Versioned, atomic on-disk cache for domain harvest results."""

from __future__ import annotations

import json
import os
from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..config import APP_VERSION, settings
from ..modules.base import ModuleResult, ModuleStatus
from .domain_harvest_orchestrator import DomainHarvestResult, HarvestedEmail


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "value"):
        return _json_safe(value.value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _serialize_result(result: DomainHarvestResult) -> dict[str, Any]:
    payload = {
        field.name: getattr(result, field.name)
        for field in fields(DomainHarvestResult)
        if field.name not in {"from_cache", "cache_age_seconds", "cached_at"}
    }
    payload["unique_emails"] = [
        {field.name: getattr(email, field.name) for field in fields(HarvestedEmail)}
        for email in result.unique_emails
    ]
    payload["module_results"] = {
        name: {
            "status": module.status.value,
            "findings": module.findings,
            "metadata": module.metadata,
            "errors": module.errors,
        }
        for name, module in result.module_results.items()
    }
    return _json_safe(payload)


def _deserialize_result(payload: dict[str, Any]) -> DomainHarvestResult:
    email_fields = {field.name for field in fields(HarvestedEmail)}
    result_fields = {field.name for field in fields(DomainHarvestResult)}
    emails = [
        HarvestedEmail(**{key: value for key, value in row.items() if key in email_fields})
        for row in payload.get("unique_emails", [])
        if isinstance(row, dict)
    ]
    modules: dict[str, ModuleResult] = {}
    for name, row in (payload.get("module_results") or {}).items():
        if not isinstance(row, dict):
            continue
        try:
            status = ModuleStatus(str(row.get("status", "failed")))
        except ValueError:
            status = ModuleStatus.FAILED
        modules[str(name)] = ModuleResult(
            status=status,
            findings=list(row.get("findings") or []),
            metadata=dict(row.get("metadata") or {}),
            errors=list(row.get("errors") or []),
        )
    values = {key: value for key, value in payload.items() if key in result_fields}
    values["unique_emails"] = emails
    values["module_results"] = modules
    return DomainHarvestResult(**values)


class HarvestCache:
    """Store one full, version-bound harvest result per domain."""

    def __init__(
        self,
        cache_dir: Path | None = None,
        default_ttl: int | None = None,
    ) -> None:
        self.cache_dir = cache_dir or (Path.home() / ".mailaccess" / "cache")
        self.default_ttl = int(
            default_ttl
            if default_ttl is not None
            else getattr(settings, "harvest_cache_ttl_seconds", 3600)
        )

    def _path(self, domain: str) -> Path:
        cleaned = str(domain).strip().lower().rstrip(".")
        safe = "".join(char for char in cleaned if char.isalnum() or char in ".-")
        return self.cache_dir / f"{safe}.json"

    def _read_envelope(self, domain: str) -> dict[str, Any] | None:
        path = self._path(domain)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def get(self, domain: str) -> DomainHarvestResult | None:
        envelope = self._read_envelope(domain)
        if envelope is None or self._envelope_is_stale(envelope):
            return None
        result_payload = envelope.get("result")
        if not isinstance(result_payload, dict):
            return None
        try:
            result = _deserialize_result(result_payload)
            cached_at = str(envelope["cached_at"])
            result.from_cache = True
            result.cached_at = cached_at
            result.cache_age_seconds = max(
                0.0, (_utc_now() - _parse_timestamp(cached_at)).total_seconds()
            )
            return result
        except (KeyError, TypeError, ValueError):
            return None

    def set(self, domain: str, result: DomainHarvestResult) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.cache_dir.chmod(0o700)
        except OSError:
            pass
        path = self._path(domain)
        temporary = path.with_suffix(path.suffix + f".{os.getpid()}.{uuid4().hex}.tmp")
        envelope = {
            "domain": str(domain).strip().lower(),
            "cached_at": _utc_now().isoformat().replace("+00:00", "Z"),
            "ttl_seconds": self.default_ttl,
            "mailaccess_version": APP_VERSION,
            "result": _serialize_result(result),
        }
        try:
            temporary.write_text(
                json.dumps(envelope, ensure_ascii=False, separators=(",", ":")),
                encoding="utf-8",
            )
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink(missing_ok=True)

    def invalidate(self, domain: str) -> None:
        self._path(domain).unlink(missing_ok=True)

    def invalidate_all(self) -> None:
        if not self.cache_dir.exists():
            return
        for path in self.cache_dir.iterdir():
            if path.is_file():
                path.unlink(missing_ok=True)

    def is_stale(self, domain: str) -> bool:
        envelope = self._read_envelope(domain)
        return envelope is None or self._envelope_is_stale(envelope)

    @staticmethod
    def _envelope_is_stale(envelope: dict[str, Any]) -> bool:
        if envelope.get("mailaccess_version") != APP_VERSION:
            return True
        try:
            cached_at = _parse_timestamp(str(envelope["cached_at"]))
            ttl = int(envelope.get("ttl_seconds", 0))
        except (KeyError, TypeError, ValueError):
            return True
        return ttl <= 0 or (_utc_now() - cached_at).total_seconds() >= ttl


__all__ = ["HarvestCache"]
