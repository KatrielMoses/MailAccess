"""Placeholder-leak scanner for harvest-emails JSON exports.

Looks for known leak patterns in the JSON: HTML-entity-not-decoded
strings, image filenames mistaken for emails, placeholder domains,
unrelated third-party domains bleeding into the role-account bucket.

The harvest JSON has a different shape than the CLI output: the
displayed "role accounts" and "MEDIUM" emails live under different
keys.  We scan every email-like string in the file and check it
against the patterns.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


LEAK_PATTERNS = [
    ("image_filename", re.compile(r"\.(?:png|jpg|jpeg|gif|svg)@", re.IGNORECASE)),
    ("undecoded_entity", re.compile(r"u00[0-9a-fA-F]{2}")),
    ("logo_filename", re.compile(r"^[a-z0-9_-]*logo[a-z0-9_.-]*$", re.IGNORECASE)),
    ("placeholder_com", re.compile(r"placeholder\.com", re.IGNORECASE)),
    ("example_com", re.compile(r"@example\.com", re.IGNORECASE)),
    ("test_com", re.compile(r"@test\.com", re.IGNORECASE)),
    ("yourdomain", re.compile(r"yourdomain", re.IGNORECASE)),
    ("off_target_domain", re.compile(r"@(?!ine\.com|lavellenetworks\.com)([a-z0-9.-]+\.[a-z]{2,})", re.IGNORECASE)),
]

DOMAIN_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+")


def scan_file(path: Path) -> dict:
    if not path.exists():
        return {"exists": False}
    raw = path.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"exists": True, "valid_json": False, "error": str(exc)}

    emails = sorted(set(DOMAIN_RE.findall(raw)))
    leaks_by_pattern: dict[str, list[str]] = {}
    for email in emails:
        for name, pat in LEAK_PATTERNS:
            if pat.search(email):
                leaks_by_pattern.setdefault(name, []).append(email)
                break  # first match wins

    return {
        "exists": True,
        "valid_json": True,
        "size_bytes": len(raw),
        "findings_count": len(data.get("findings", [])) if isinstance(data, dict) else None,
        "total_email_strings": len(emails),
        "leaks_by_pattern": leaks_by_pattern,
        "sample_emails": emails[:20],
    }


if __name__ == "__main__":
    paths = [Path(p) for p in sys.argv[1:]] or [
        Path("results/bench_ine_0.11.3.json"),
        Path("results/bench_lavelle_0.11.3.json"),
    ]
    for p in paths:
        print(f"=== {p} ===")
        r = scan_file(p)
        if not r.get("exists"):
            print("  does not exist")
            continue
        if not r.get("valid_json"):
            print(f"  invalid JSON: {r.get('error')}")
            continue
        print(f"  size: {r['size_bytes']} bytes")
        if r.get("findings_count") is not None:
            print(f"  findings array: {r['findings_count']}")
        print(f"  total email strings: {r['total_email_strings']}")
        for pat_name, hits in r["leaks_by_pattern"].items():
            print(f"  LEAK [{pat_name}]: {len(hits)} hits")
            for h in hits[:5]:
                print(f"    -> {h}")
        if not r["leaks_by_pattern"]:
            print("  no placeholder leaks detected")
        if r.get("sample_emails"):
            print(f"  sample emails: {r['sample_emails'][:10]}")
