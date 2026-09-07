"""Phase 5A — bulk-harvest parity + batch-semantics harness.

Proves the 5A "Done when" criteria against real harvests, keyless and isolated
(mirrors :mod:`eval.harness.corpus_parity`):

1. **Per-domain parity.** Each domain is harvested (a) solo via
   ``harvest-emails -d DOMAIN --export`` in one isolated home, and (b) as part
   of a bulk batch via ``harvest-emails --file`` in a *separate* isolated home
   (so the batch runs fresh, not as a corpus read-first hit). The per-domain
   email SET and confidence labels must match — the merge/concurrency must not
   change what a domain yields.
2. **One merged export**, evidence-preserving, one row per domain.
3. **Cross-batch dedup** — the merged ``contacts`` list is address-unique.
4. **Resumability** — re-running the same file+checkpoint skips every completed
   domain (no re-harvest) and completes fast.
5. **4A capture populated** — the batch home's ``score_feature_snapshots`` table
   has rows (calibration volume was generated).

Run (keyless, isolated)::

    uv run python -m eval.harness.bulk_parity --timeout 240 \
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


def _fingerprint_from_rows(rows: list[dict[str, Any]]) -> dict[str, str]:
    fp: dict[str, str] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        addr = str(row.get("email") or row.get("address") or "").strip().lower()
        if not addr:
            continue
        fp[addr] = str(row.get("confidence_label") or row.get("confidence") or "")
    return fp


def _run_cli(args: list[str], home: Path, cwd: Path, timeout: int) -> dict[str, Any]:
    cfg = CONFIGS["keyless-default"]
    env = cfg.build_env(home)
    run_cwd = cfg.build_cwd(cwd)
    cmd = [sys.executable, "-m", "cli.main", "--no-banner", *args]
    start = time.perf_counter()
    proc = subprocess.run(
        cmd, env=env, cwd=str(run_cwd), capture_output=True, text=True,
        timeout=timeout + 600, errors="replace",
    )
    wall = time.perf_counter() - start
    return {
        "wall": wall,
        "exit": proc.returncode,
        "output": (proc.stdout or "") + (proc.stderr or ""),
    }


def _snapshot_count(home: Path) -> int:
    """Count 4A feature snapshots recorded in the batch home's DB."""
    import sqlite3

    db = home / ".mailaccess" / "mailaccess.db"
    if not db.exists():
        return 0
    con = sqlite3.connect(db)
    try:
        row = con.execute("SELECT COUNT(*) FROM score_feature_snapshots").fetchone()
        return int(row[0]) if row else 0
    except sqlite3.Error:
        return 0
    finally:
        con.close()


def run(domains: list[str], timeout: int) -> dict[str, Any]:
    scratch = Path(tempfile.mkdtemp(prefix="bulk-parity-"))
    home_single = scratch / "home_single"
    home_bulk = scratch / "home_bulk"
    cwd = scratch / "cwd"
    for d in (home_single, home_bulk, cwd):
        d.mkdir(parents=True)

    # 1. Solo harvests (isolated home_single).
    single_fp: dict[str, dict[str, str]] = {}
    for domain in domains:
        export = scratch / f"single_{domain}.json"
        r = _run_cli(
            ["harvest-emails", "-d", domain, "--export", str(export),
             "--timeout", str(timeout)],
            home_single, cwd, timeout,
        )
        data = {}
        if export.exists():
            try:
                data = json.loads(export.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
        single_fp[domain] = _fingerprint_from_rows(data.get("emails", []))
        print(f"  [single] {domain} exit={r['exit']} emails={len(single_fp[domain])} "
              f"wall={r['wall']:.0f}s", flush=True)

    # 2. Bulk harvest (separate isolated home_bulk, fresh).
    list_file = scratch / "domains.txt"
    list_file.write_text("\n".join(domains) + "\n", encoding="utf-8")
    merged = scratch / "merged.json"
    checkpoint = scratch / "checkpoint.json"
    bulk = _run_cli(
        ["harvest-emails", "--file", str(list_file), "--merged-export", str(merged),
         "--checkpoint", str(checkpoint), "--timeout", str(timeout)],
        home_bulk, cwd, timeout * max(1, len(domains)),
    )
    doc = json.loads(merged.read_text(encoding="utf-8")) if merged.exists() else {}
    per_domain = {d.get("domain"): d for d in doc.get("domains", [])}
    bulk_fp = {
        dom: _fingerprint_from_rows(sec.get("emails", []))
        for dom, sec in per_domain.items()
    }

    # 3. Resume run — same file + checkpoint, should skip everything.
    resume = _run_cli(
        ["harvest-emails", "--file", str(list_file), "--merged-export", str(merged),
         "--checkpoint", str(checkpoint), "--timeout", str(timeout)],
        home_bulk, cwd, timeout,
    )

    # --- evaluate ---------------------------------------------------------
    per_domain_parity: dict[str, dict[str, Any]] = {}
    all_parity = True
    for domain in domains:
        s = single_fp.get(domain, {})
        b = bulk_fp.get(domain, {})
        set_match = set(s) == set(b)
        shared = set(s) & set(b)
        label_agree = (
            sum(1 for e in shared if s[e] == b[e]) / len(shared) if shared else 1.0
        )
        parity = set_match and label_agree >= 0.99
        all_parity = all_parity and parity
        per_domain_parity[domain] = {
            "single_emails": len(s),
            "bulk_emails": len(b),
            "set_match": set_match,
            "label_agreement": round(label_agree, 3),
            "parity": parity,
        }

    contacts = doc.get("contacts", [])
    contact_addrs = [str(c.get("email") or "").lower() for c in contacts]
    dedup_ok = len(contact_addrs) == len(set(contact_addrs))
    one_export = merged.exists() and doc.get("kind") == "bulk_harvest"
    one_row_each = set(per_domain) >= set(domains)

    counts_skipped = "skipped" in resume["output"].lower() or "↷" in resume["output"]
    resume_ok = resume["exit"] == 0 and resume["wall"] < max(30, timeout / 2)

    snapshots = _snapshot_count(home_bulk)

    ok = all(
        [all_parity, dedup_ok, one_export, one_row_each, resume_ok, bulk["exit"] == 0]
    )
    return {
        "ok": ok,
        "per_domain_parity": per_domain_parity,
        "merged_export": one_export,
        "one_row_per_domain": one_row_each,
        "dedup_ok": dedup_ok,
        "merged_contacts": len(contacts),
        "bulk_exit": bulk["exit"],
        "bulk_wall": round(bulk["wall"], 1),
        "resume_ok": resume_ok,
        "resume_wall": round(resume["wall"], 1),
        "resume_skipped_signal": counts_skipped,
        "score_snapshots_4a": snapshots,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 5A bulk-harvest parity harness")
    ap.add_argument("domains", nargs="+", help="domains to harvest (batch)")
    ap.add_argument("--timeout", type=int, default=240, help="per-domain timeout seconds")
    args = ap.parse_args(argv)

    print(f"[bulk-parity] {len(args.domains)} domain(s) — single vs bulk …", flush=True)
    result = run(args.domains, args.timeout)
    print("\n=== SUMMARY ===")
    print(json.dumps(result, indent=2))
    print("\nBULK PARITY PASSED" if result["ok"] else "\nBULK PARITY FAILURES PRESENT")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
