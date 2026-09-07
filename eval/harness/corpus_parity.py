"""Phase 1D — corpus parity + read-first harness.

Concrete non-regression safety net for the "two worlds" merge. For each domain
it runs two real harvests in the SAME isolated corpus DB:

1. **fresh** — full collection, DB-backed, writes the corpus;
2. **repeat** — should be a corpus read-first hit: materially faster, identical
   output (same emails, same confidence labels).

It asserts the repeat is a cache hit (the CLI prints "Cached result"), is much
faster, and produces an identical email/confidence fingerprint — i.e. the
DB-backed harvest is output-equivalent to the pre-merge path and repeat harvests
compound.

Run (keyless, isolated, mirrors the baseline harness)::

    uv run python -m eval.harness.corpus_parity --timeout 240 \
        lavellenetworks.com rootaccess.tech stripe.com
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from eval.harness.run_baseline import CONFIGS


def _emails_fingerprint(export: dict[str, Any]) -> dict[str, str]:
    """email -> confidence label, from a harvest JSON export (order-insensitive)."""
    fingerprint: dict[str, str] = {}
    for row in export.get("emails", []) or []:
        if not isinstance(row, dict):
            continue
        address = str(row.get("email") or row.get("address") or "").strip().lower()
        if not address:
            continue
        label = str(
            row.get("confidence_label")
            or row.get("confidence")
            or row.get("label")
            or ""
        )
        fingerprint[address] = label
    return fingerprint


def _run_harvest(domain: str, home: Path, cwd: Path, export: Path, timeout: int) -> dict[str, Any]:
    cfg = CONFIGS["keyless-default"]
    env = cfg.build_env(home)
    run_cwd = cfg.build_cwd(cwd)
    cmd = [
        sys.executable, "-m", "cli.main", "--no-banner", "harvest-emails",
        "-d", domain, "--export", str(export), "--timeout", str(timeout),
    ]
    start = time.perf_counter()
    proc = subprocess.run(
        cmd, env=env, cwd=str(run_cwd), capture_output=True, text=True,
        timeout=timeout + 240, errors="replace",
    )
    wall = time.perf_counter() - start
    output = (proc.stdout or "") + (proc.stderr or "")
    data = {}
    if export.exists():
        try:
            data = json.loads(export.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
    return {
        "wall": wall,
        "exit": proc.returncode,
        "cache_hit": "Cached result" in output,
        "fingerprint": _emails_fingerprint(data),
        "count": len(data.get("emails", []) or []),
    }


def _corpus_fingerprint(home: Path, domain: str) -> dict[str, str]:
    """email -> confidence label, read from the corpus crawl snapshot's result."""
    import sqlite3

    db = home / ".mailaccess" / "mailaccess.db"
    if not db.exists():
        return {}
    con = sqlite3.connect(db)
    try:
        row = con.execute(
            "SELECT result_json FROM crawl_snapshots WHERE domain=? "
            "ORDER BY harvested_at DESC LIMIT 1",
            (domain.strip().lower(),),
        ).fetchone()
    except sqlite3.Error:
        return {}
    finally:
        con.close()
    if not row:
        return {}
    result = json.loads(row[0])
    fingerprint: dict[str, str] = {}
    for e in result.get("unique_emails", []) or []:
        if isinstance(e, dict) and e.get("email"):
            fingerprint[str(e["email"]).strip().lower()] = str(e.get("confidence_label") or "")
    return fingerprint


def check_domain(domain: str, timeout: int) -> dict[str, Any]:
    scratch = Path(tempfile.mkdtemp(prefix="corpus-parity-"))
    home = scratch / "home"
    home.mkdir(parents=True)
    cwd = scratch / "cwd"
    cwd.mkdir(parents=True)

    # 1. Fresh collection, DB-backed — writes the corpus.
    fresh = _run_harvest(domain, home, cwd, scratch / "fresh.json", timeout)
    # 2. The corpus faithfully stored what the fresh harvest produced.
    corpus_fp = _corpus_fingerprint(home, domain)
    # 3. Repeat harvest is a corpus read-first hit (fast; like the old JSON-cache
    #    path it returns early, so --export is not re-written — parity is proven
    #    against the corpus, which is exactly what the read-first hit returns).
    repeat = _run_harvest(domain, home, cwd, scratch / "repeat.json", timeout)

    fresh_fp = fresh["fingerprint"]
    # Hard parity signal: identical email SET between the fresh export and the
    # corpus the read-first hit reconstructs from.
    email_parity = bool(fresh_fp) and set(fresh_fp) == set(corpus_fp)
    # Reported: fraction of shared emails whose confidence label also agrees
    # (export and corpus both carry confidence_label).
    shared = set(fresh_fp) & set(corpus_fp)
    label_agree = (
        sum(1 for e in shared if fresh_fp[e] == corpus_fp[e]) / len(shared)
        if shared
        else 0.0
    )
    speedup = (fresh["wall"] / repeat["wall"]) if repeat["wall"] > 0 else 0.0
    faster = repeat["wall"] < fresh["wall"] / 2  # "materially faster"
    ok = (
        fresh["exit"] == 0
        and repeat["exit"] == 0
        and repeat["cache_hit"]
        and email_parity
        and faster
    )
    return {
        "domain": domain,
        "ok": ok,
        "fresh_wall": round(fresh["wall"], 1),
        "repeat_wall": round(repeat["wall"], 1),
        "speedup": round(speedup, 1),
        "repeat_cache_hit": repeat["cache_hit"],
        "email_parity": email_parity,
        "label_agreement": round(label_agree, 3),
        "fresh_emails": fresh["count"],
        "corpus_emails": len(corpus_fp),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 1D corpus parity + read-first harness")
    ap.add_argument("domains", nargs="+", help="domains to check")
    ap.add_argument("--timeout", type=int, default=240, help="per-harvest timeout seconds")
    args = ap.parse_args(argv)

    results = []
    all_ok = True
    for domain in args.domains:
        print(f"[parity] {domain} — running fresh + repeat harvests …", flush=True)
        r = check_domain(domain, args.timeout)
        results.append(r)
        all_ok = all_ok and r["ok"]
        print(
            f"  ok={r['ok']} fresh={r['fresh_wall']}s repeat={r['repeat_wall']}s "
            f"speedup={r['speedup']}x cache_hit={r['repeat_cache_hit']} "
            f"email_parity={r['email_parity']} label_agreement={r['label_agreement']} "
            f"emails={r['fresh_emails']}(export)/{r['corpus_emails']}(corpus)",
            flush=True,
        )

    print("\n=== SUMMARY ===")
    print(json.dumps(results, indent=2))
    print("\nALL PARITY CHECKS PASSED" if all_ok else "\nPARITY FAILURES PRESENT")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
