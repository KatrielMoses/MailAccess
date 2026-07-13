"""Run the leak scan with proper UTF-16 LE handling for PowerShell-Tee'd logs."""
from __future__ import annotations

import re
import sys
from pathlib import Path

DOMAIN_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+")
HOME_LOGO_RE = re.compile(r"home[-_]logo[0-9_]*x@[0-9]+x\.", re.IGNORECASE)
LOGO_NAME_RE = re.compile(r"^[a-z0-9_-]*logo[a-z0-9_.-]*$", re.IGNORECASE)
ENTITY_RE = re.compile(r"u00[0-9a-fA-F]{2}")


def read_any_encoding(path: Path) -> str:
    """Read a file regardless of UTF-8 / UTF-16 / BOM."""
    raw = path.read_bytes()
    # Try UTF-8 first, fall back to UTF-16 LE (PowerShell Tee-Object default).
    for enc in ("utf-8", "utf-16-le", "utf-16", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def bucketize(emails, target):
    buckets = {
        "image_filename": [],
        "undecoded_entity": [],
        "logo_filename": [],
        "home_logo_dx": [],
        "off_target": [],
    }
    for e in set(emails):
        local = e.split("@", 1)[0]
        if HOME_LOGO_RE.search(e):
            buckets["home_logo_dx"].append(e)
        if LOGO_NAME_RE.match(local):
            buckets["logo_filename"].append(e)
        if ENTITY_RE.search(e):
            buckets["undecoded_entity"].append(e)
        if "@" in e:
            dom = e.rsplit("@", 1)[-1].lower()
            if target and target.lower() not in dom:
                buckets["off_target"].append(e)
    for k in buckets:
        buckets[k] = sorted(set(buckets[k]))
    return buckets


def scan_log(path: Path, target: str) -> dict:
    if not path.exists():
        return {"exists": False}
    text = read_any_encoding(path)
    emails = DOMAIN_RE.findall(text)
    return {
        "exists": True,
        "size_bytes": path.stat().st_size,
        "total_emails": len(emails),
        "unique_emails": len(set(emails)),
        "buckets": bucketize(emails, target),
        "all_unique": sorted(set(emails)),
    }


if __name__ == "__main__":
    targets = [
        ("ine.com", "buildtmp/bench_ine.log"),
        ("lavellenetworks.com", "buildtmp/bench_lavelle.log"),
    ]
    for target, log_p in targets:
        print(f"\n=== {target} ({log_p}) ===")
        r = scan_log(Path(log_p), target)
        if not r.get("exists"):
            print("  log not found")
            continue
        print(f"  size: {r['size_bytes']} bytes")
        print(f"  total email-like strings: {r['total_emails']}, unique: {r['unique_emails']}")
        any_leak = False
        for k, hits in r["buckets"].items():
            if hits:
                any_leak = True
                print(f"  LEAK [{k}] ({len(hits)} hits): {hits[:8]}")
        if not any_leak:
            print("  no placeholder leaks detected")
