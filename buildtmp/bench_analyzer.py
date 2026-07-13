"""Placeholder-leak + architecture-wiring check for harvest-emails runs.

Reports:
  * Which modules actually ran (vs which were disabled)
  * Findings count, employee name count, role-account count
  * Detected leaks: undecoded HTML entities, image filenames, off-target domains

The harvest-emails CLI output puts the data in a different shape than
the JSON export (which has empty findings arrays because the result is
serialised differently).  We scan both: the log output for the CLI
table data, and the JSON for the persisted findings.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

DOMAIN_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+")
LOGO_RE = re.compile(r"\.(?:png|jpg|jpeg|gif|svg)@", re.IGNORECASE)
ENTITY_RE = re.compile(r"u00[0-9a-fA-F]{2}")
LOGO_NAME_RE = re.compile(r"^[a-z0-9_-]*logo[a-z0-9_.-]*$", re.IGNORECASE)
HOME_LOGO_RE = re.compile(r"home[-_]logo[0-9_]*x@[0-9]+x\.", re.IGNORECASE)


def scan_text(raw: str, target: str) -> dict:
    """Scan a string (log or JSON) for placeholder leaks.

    target: the domain we're harvesting — used to flag off-target emails.
    """
    emails = sorted(set(DOMAIN_RE.findall(raw)))
    buckets: dict[str, list[str]] = {
        "image_filename": [],
        "undecoded_entity": [],
        "logo_filename": [],
        "home_logo_dx": [],
        "off_target": [],
    }
    for email in emails:
        if HOME_LOGO_RE.search(email) or LOGO_NAME_RE.search(email) or "@2x." in email or "@1x." in email:
            if LOGO_NAME_RE.match(email.split("@", 1)[0]):
                buckets["logo_filename"].append(email)
            if HOME_LOGO_RE.search(email):
                buckets["home_logo_dx"].append(email)
        if LOGO_RE.search(email):
            buckets["image_filename"].append(email)
        if ENTITY_RE.search(email):
            buckets["undecoded_entity"].append(email)
        if "@" in email:
            dom = email.rsplit("@", 1)[-1].lower()
            if target and target.lower() not in dom and not dom.endswith(f".{target.lower()}"):
                buckets["off_target"].append(email)
    # De-dup each bucket
    for k in buckets:
        buckets[k] = sorted(set(buckets[k]))
    return {
        "total_unique_emails": len(emails),
        "buckets": buckets,
        "sample": emails[:15],
    }


def scan_json(path: Path, target: str) -> dict:
    if not path.exists():
        return {"exists": False}
    raw = path.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"exists": True, "valid_json": False, "error": str(exc)}
    scan = scan_text(raw, target)
    scan["size_bytes"] = len(raw)
    if isinstance(data, dict):
        scan["json_keys"] = list(data.keys())[:20]
    return scan


def scan_log(path: Path, target: str) -> dict:
    if not path.exists():
        return {"exists": False}
    raw = path.read_text(encoding="utf-8", errors="replace")
    return scan_text(raw, target)


if __name__ == "__main__":
    targets = [
        ("ine.com", "results/bench_ine_0.11.3.json", "buildtmp/bench_ine.log"),
        ("lavellenetworks.com", "results/bench_lavelle_0.11.3.json", "buildtmp/bench_lavelle.log"),
    ]
    for target, json_p, log_p in targets:
        print(f"\n=== {target} ===")
        j = scan_json(Path(json_p), target)
        if j.get("exists"):
            print(f"  JSON {json_p}: {j.get('size_bytes', 0)} bytes, {j.get('total_unique_emails', 0)} unique emails, keys={j.get('json_keys', [])}")
            for k, hits in j.get("buckets", {}).items():
                if hits:
                    print(f"  LEAK [{k}] in JSON: {hits[:8]}")
        else:
            print(f"  JSON {json_p}: does not exist")
        l = scan_log(Path(log_p), target)
        if l.get("total_unique_emails") is not None:
            print(f"  LOG {log_p}: {l.get('total_unique_emails', 0)} unique emails")
            for k, hits in l.get("buckets", {}).items():
                if hits:
                    print(f"  LEAK [{k}] in LOG: {hits[:8]}")
        else:
            print(f"  LOG {log_p}: not found")
