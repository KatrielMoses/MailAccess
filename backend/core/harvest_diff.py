"""Comparison of two completed harvest exports."""
from __future__ import annotations

from typing import Any


def _emails(export: dict[str, Any]) -> set[str]:
    return {str(row.get("email", "")).lower() for row in export.get("emails", []) if isinstance(row, dict) and row.get("email")}


def _names(export: dict[str, Any]) -> set[str]:
    return {str(row.get("name", "")).casefold() for row in export.get("discovered_names", []) if isinstance(row, dict) and row.get("name")}


def _subdomains(export: dict[str, Any]) -> set[str]:
    hosts: set[str] = set()
    for value in export.get("subdomains", []):
        if isinstance(value, dict):
            host = value.get("subdomain") or value.get("hostname") or value.get("host")
            if host:
                hosts.add(str(host).strip().lower())
        elif value:
            hosts.add(str(value).strip().lower())
    return hosts


def compare_harvest_exports(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Return additive, deterministic changes between two JSON exports."""
    old_emails, new_emails = _emails(previous), _emails(current)
    old_names, new_names = _names(previous), _names(current)
    old_hosts, new_hosts = _subdomains(previous), _subdomains(current)
    return {
        "previous_harvested_at": previous.get("harvested_at"),
        "current_harvested_at": current.get("harvested_at"),
        "emails": {"new": sorted(new_emails - old_emails), "removed": sorted(old_emails - new_emails), "unchanged": len(old_emails & new_emails)},
        "names": {"new": sorted(new_names - old_names), "removed": sorted(old_names - new_names), "unchanged": len(old_names & new_names)},
        "subdomains": {"new": sorted(new_hosts - old_hosts), "removed": sorted(old_hosts - new_hosts), "unchanged": len(old_hosts & new_hosts)},
    }
