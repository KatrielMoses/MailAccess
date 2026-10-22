"""Live validation of username-url site checks and the UC2 core list.

Each site is probed twice through the normal ``probe_platform`` path: once with a
handle known to exist (``usernameClaimed``) and once with one that should not
(``usernameUnclaimed``, else a random control). A site *passes* a run when the first
is a hit and the second a miss. Per-host politeness is on, the timeout matches the
Wave-1 sweep, and challenges come back inconclusive like everywhere else.

    python -m backend.core.site_validation run --out v1.json        # all username sites
    python -m backend.core.site_validation core v1.json v2.json     # print the core list
    python -m backend.core.site_validation core v1.json v2.json --write

A site *passes* (``validated``) when it never gave a wrong answer in any run (known-found
read as missing, or the control read as found) and fully passed at least one run. A
control hit in any run marks it ``alwaysHit``: it can't tell "exists" from "doesn't",
so it leaves the default sweep. The ``core`` list is the top ``CORE_SIZE`` validated
sites by ``core_score`` (popularity, a high-value category, not a forum/wiki instance,
response time); the other validated sites form the optional tail. Selection never looks
at any test handle. This is the weekly health job's building block (UC7).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import date
from pathlib import Path
from typing import Any

CONTROL = "xq9vb2kt7wz4mp"
# Shorter controls for sites whose username rule rejects the long one.
_CONTROLS = (CONTROL, "xq9vb2kt7w", "xq9vb2k", "qzvbkxtwmpj", "qzvbkxtw")
# Common names tried, in order, for a site with no known-found handle. The control must
# still read as missing, so an always-hit site can't pass this way.
_CLAIMED_CANDIDATES = ("blue", "admin", "john")
TIMEOUT_S = 6.0
CONCURRENCY = 40
CORE_SIZE = 750

# Where people keep identity-bearing profiles vs per-instance forums and wikis.
_VALUE_TAGS = {
    "social", "coding", "dev", "tech", "hacking", "security", "education", "gaming",
    "music", "art", "photo", "design", "video", "streaming", "blog", "business",
    "freelance", "networking", "messaging", "sharing", "crypto", "finance", "sport",
}
_INSTANCE_TAGS = {"discussion", "forum", "wiki", "mastodon", "fediverse"}


async def _validate(sites: dict[str, dict[str, Any]]) -> dict[str, Any]:
    from . import host_politeness
    from .http_client import build_client
    from .probe_detector import probe_platform

    host_politeness.activate()
    sem = asyncio.Semaphore(CONCURRENCY)
    no_limit = asyncio.Semaphore(2**31)
    results: dict[str, Any] = {}
    done = 0

    async def probe(defn: dict[str, Any], handle: str, client: Any) -> dict[str, Any]:
        async with sem:
            t0 = time.perf_counter()
            outcome, detail, _profile = await probe_platform(
                client, no_limit, str(defn.get("name")), defn, handle, timeout=TIMEOUT_S
            )
            ms = int((time.perf_counter() - t0) * 1000)
        return {
            "handle": handle, "outcome": outcome, "ms": ms,
            "detail": None if outcome == "hit" else (str(detail)[:80] if detail else None),
        }

    async def one(site_id: str, defn: dict[str, Any], client: Any) -> None:
        nonlocal done
        from .probe_detector import username_matches_regex

        row: dict[str, Any] = {"name": defn.get("name")}
        claimed = defn.get("usernameClaimed")
        if claimed:
            row["claimed"] = await probe(defn, str(claimed), client)
        else:
            row["claimed"] = {"outcome": "untested"}
            for candidate in _CLAIMED_CANDIDATES:
                if not username_matches_regex(defn, candidate):
                    continue
                attempt = await probe(defn, candidate, client)
                if attempt["outcome"] == "hit":
                    row["claimed"] = {**attempt, "discovered": True}
                    break
        unclaimed = defn.get("usernameUnclaimed")
        if not unclaimed or not username_matches_regex(defn, str(unclaimed)):
            unclaimed = next((c for c in _CONTROLS if username_matches_regex(defn, c)), None)
        row["unclaimed"] = (
            await probe(defn, str(unclaimed), client) if unclaimed else {"outcome": "untested"}
        )
        results[site_id] = row
        done += 1
        if done % 250 == 0:
            print(f"  {done}/{len(sites)}", file=sys.stderr, flush=True)

    async with build_client(timeout=TIMEOUT_S) as client:
        await asyncio.gather(*(one(sid, d, client) for sid, d in sites.items()))
    return results


def username_sites() -> dict[str, dict[str, Any]]:
    from .mailaccess_sites_loader import load_mailaccess_sites

    corpus, _ = load_mailaccess_sites()
    return {
        sid: d for sid, d in corpus.items()
        if d.get("check_type") == "username-url" and not d.get("disabled")
        and (d.get("uri_check") or d.get("url"))
    }


def verdict(rows: list[dict[str, Any]]) -> str:
    """``pass`` | ``alwaysHit`` | ``fail`` | ``untested`` across validation runs."""
    if not rows:
        return "untested"
    claimed = [r.get("claimed", {}).get("outcome") for r in rows]
    unclaimed = [r.get("unclaimed", {}).get("outcome") for r in rows]
    if "hit" in unclaimed:
        return "alwaysHit"
    if all(c == "untested" for c in claimed):
        return "untested"
    if "miss" in claimed:
        return "fail"
    if any(c == "hit" and u == "miss" for c, u in zip(claimed, unclaimed)):
        return "pass"
    return "fail"


def core_score(defn: dict[str, Any], rows: list[dict[str, Any]]) -> tuple[float, float]:
    """Higher is better: (score, -slowest ms). Uses only the site itself."""
    try:
        rank = int(defn.get("alexaRank"))
    except (TypeError, ValueError):
        rank = None
    tags = {str(t).lower() for t in defn.get("tags") or []}
    if defn.get("category"):
        tags.add(str(defn["category"]).lower())
    primary = str((defn.get("tags") or [""])[0]).lower()
    slowest = max(
        int(r.get(role, {}).get("ms") or 0) for r in rows for role in ("claimed", "unclaimed")
    )
    score = 0.0
    if rank is not None:
        score += 3 if rank < 1_000 else 2 if rank < 10_000 else 1 if rank < 100_000 else 0.5
    if tags & _VALUE_TAGS:
        score += 2
    if primary in _INSTANCE_TAGS or (tags & _INSTANCE_TAGS and not tags & _VALUE_TAGS):
        score -= 3
    if slowest <= 1_500:
        score += 1
    elif slowest > 4_000:
        score -= 1
    if all(r.get("claimed", {}).get("outcome") == "hit" for r in rows):
        score += 0.5  # passed every run, not just one
    return score, -slowest


def build_core(paths: list[str]) -> dict[str, str]:
    """Per site: ``core`` | ``validated`` | ``alwaysHit`` | ``fail`` | ``untested``."""
    from .mailaccess_sites_loader import load_mailaccess_sites

    corpus, _ = load_mailaccess_sites()
    runs = [json.loads(Path(p).read_text())["results"] for p in paths]
    ids = set().union(*runs)
    rows = {sid: [run[sid] for run in runs if sid in run] for sid in ids}
    for sid, site_rows in rows.items():
        # A site whose only "missing" signal is a status we don't get (Instagram:
        # 404-only, bare page otherwise) may read the control as inconclusive.
        if (corpus.get(sid) or {}).get("validationMissingMayBeInconclusive"):
            rows[sid] = [
                {**r, "unclaimed": {**r.get("unclaimed", {}), "outcome": "miss"}}
                if (r.get("unclaimed") or {}).get("outcome") == "inconclusive" else r
                for r in site_rows
            ]
    verdicts = {sid: verdict(r) for sid, r in rows.items()}
    passing = [sid for sid, v in verdicts.items() if v == "pass" and sid in corpus]
    passing.sort(key=lambda sid: core_score(corpus[sid], rows[sid]), reverse=True)
    for sid in passing[:CORE_SIZE]:
        verdicts[sid] = "core"
    for sid in passing[CORE_SIZE:]:
        verdicts[sid] = "validated"
    return dict(sorted(verdicts.items()))


def discovered_claims(paths: list[str]) -> dict[str, str]:
    """Known-found handles the validator discovered for sites that had none."""
    out: dict[str, str] = {}
    for p in paths:
        for sid, row in json.loads(Path(p).read_text())["results"].items():
            claimed = row.get("claimed") or {}
            if claimed.get("discovered") and claimed.get("outcome") == "hit":
                out.setdefault(sid, str(claimed["handle"]))
    return out


def write_core(verdicts: dict[str, str], claims: dict[str, str] | None = None) -> None:
    from .mailaccess_sites_loader import _DATA_PATH

    data = json.loads(_DATA_PATH.read_text(encoding="utf-8"))
    today = date.today().isoformat()
    for sid, defn in data["sites"].items():
        if defn.get("check_type") != "username-url":
            continue
        for key in ("core", "validated", "alwaysHit"):
            defn.pop(key, None)
        v = verdicts.get(sid)
        if v in ("core", "validated"):
            defn["validated"] = today
            if v == "core":
                defn["core"] = True
        elif v == "alwaysHit":
            defn["alwaysHit"] = today
        if claims and sid in claims and not defn.get("usernameClaimed"):
            defn["usernameClaimed"] = claims[sid]
    _DATA_PATH.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run")
    run.add_argument("--out", required=True)
    run.add_argument("--only", help="comma-separated site ids")
    core = sub.add_parser("core")
    core.add_argument("runs", nargs="+")
    core.add_argument("--write", action="store_true")
    args = ap.parse_args()

    if args.cmd == "run":
        sites = username_sites()
        if args.only:
            wanted = set(args.only.split(","))
            sites = {k: v for k, v in sites.items() if k in wanted}
        t0 = time.time()
        results = asyncio.run(_validate(sites))
        Path(args.out).write_text(json.dumps(
            {"date": date.today().isoformat(), "seconds": round(time.time() - t0),
             "control": CONTROL, "results": results}, indent=1))
        print(f"validated {len(results)} sites in {time.time() - t0:.0f}s -> {args.out}")
    else:
        verdicts = build_core(args.runs)
        counts: dict[str, int] = {}
        for v in verdicts.values():
            counts[v] = counts.get(v, 0) + 1
        print(counts)
        if args.write:
            write_core(verdicts, discovered_claims(args.runs))
            print("core flags written to the corpus")


if __name__ == "__main__":
    main()
