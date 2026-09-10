"""Username-URL site selection over the unified corpus.

There is **no runtime fetch** and no separate data file. Username-URL sites live in
``data/mailaccess_sites.json`` (see ``mailaccess_sites_loader``); this module selects
that paradigm and applies the wave / supported-site filtering the ``username_platforms``
module needs, returning ``(sites_dict, load_meta)`` keyed by the site ``name``.
"""

from __future__ import annotations

from typing import Any

from .mailaccess_sites_loader import load_mailaccess_sites

# Bot-protections that make a Wave-1 (fast, high-concurrency) probe unreliable. Sites
# carrying one are held for Wave-2 unless the caller opts in.
_WAVE1_BLOCKED_PROTECTIONS = {
    "cf_js_challenge",
    "tls_fingerprint",
    "ip_reputation",
    "custom_bot_protection",
}


def _protections(defn: dict[str, Any]) -> set[str]:
    value = defn.get("protection")
    if isinstance(value, list):
        return {str(item) for item in value}
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict):
        return {str(key) for key in value}
    return set()


def _is_supported_site(defn: dict[str, Any], include_wave2: bool) -> bool:
    if defn.get("disabled") is True:
        return False
    if not defn.get("uri_check") and not defn.get("url") and not defn.get("handler"):
        return False
    if _protections(defn) & _WAVE1_BLOCKED_PROTECTIONS and not include_wave2:
        return False
    return True


async def load_username_sites(
    include_wave2: bool = False,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Return ``(sites, meta)`` of live-viable ``username-url`` sites from the local corpus.

    Async to preserve the awaited call-site contract of the retired network loader, but it
    performs no I/O beyond the module-cached corpus read.
    """
    corpus, corpus_meta = load_mailaccess_sites()

    sites: dict[str, dict[str, Any]] = {}
    selected = 0
    for defn in corpus.values():
        if defn.get("check_type") != "username-url":
            continue
        selected += 1
        if not _is_supported_site(defn, include_wave2=include_wave2):
            continue
        name = str(defn.get("name") or defn.get("id"))
        sites[name] = defn

    meta = {
        "source": "mailaccess_sites",
        "partial": bool(corpus_meta.get("partial")),
        "username_sites": selected,
        "sites_loaded": len(sites),
        "schema_version": corpus_meta.get("schema_version"),
    }
    return sites, meta
