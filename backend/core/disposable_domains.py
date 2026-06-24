"""Disposable email domain detection."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

_CORPUS_PATH = Path(__file__).resolve().parents[2] / "data" / "disposable_domains.json"
_disposable_domains: frozenset[str] | None = None

logger = logging.getLogger(__name__)


def _load_domains() -> frozenset[str]:
    global _disposable_domains

    if _disposable_domains is not None:
        return _disposable_domains

    domains: frozenset[str] = frozenset()
    try:
        payload: Any = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))
        if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
            raise ValueError("disposable-domains corpus must be a list of strings")
        domains = frozenset(item.strip().lower() for item in payload if item.strip())
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        logger.warning("Unable to load disposable domain corpus: %s", exc)

    _disposable_domains = domains
    return _disposable_domains


def extract_domain(email: str) -> str:
    """Return the normalized domain from a valid email-like value."""
    if not isinstance(email, str):
        return ""
    value = email.strip()
    if value.count("@") != 1:
        return ""
    local, domain = value.split("@", 1)
    if not local or not domain or local != local.strip() or domain != domain.strip():
        return ""
    return domain.lower()


def is_disposable_domain(domain: str) -> bool:
    """Return whether a domain is in the disposable-domain corpus."""
    if not isinstance(domain, str) or not domain.strip():
        return False
    return domain.strip().lower() in _load_domains()


def is_disposable_email(email: str) -> bool:
    """Return whether an email uses a known disposable domain."""
    domain = extract_domain(email)
    return bool(domain) and is_disposable_domain(domain)
