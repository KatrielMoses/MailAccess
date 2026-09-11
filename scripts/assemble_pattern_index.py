#!/usr/bin/env python3
"""Phase 0 assembler (Root-C: true-denominator confidence).
Reads DuckDB aggregate CSVs and emits company_patterns.json[.gz] + QA report.

confidence = support_n / considered_n  where
  support_n     = count of the DOMINANT pattern (numerator)
  considered_n  = ALL qualifying verified personal mailboxes for the domain (denominator,
                  from `dedup` = matched + unmatched). This is the honest adherence rate.
Stdlib only."""

import argparse
import collections
import csv
import datetime
import gzip
import json
import os
import random

PATTERN_ENUM = [f"P{i:02d}" for i in range(1, 16)]


def dominant(tally):
    pat, n = max(tally.items(), key=lambda kv: (kv[1], kv[0]))  # ties -> highest id
    return pat, n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--indir", default="/root/out")
    ap.add_argument("--out", default="/root/out/company_patterns.json.gz")
    ap.add_argument("--qa", default="/root/out/qa_report.md")
    ap.add_argument("--min-considered", type=int, default=3)
    ap.add_argument("--min-dominant", type=int, default=2)
    ap.add_argument("--min-confidence", type=float, default=0.5)
    ap.add_argument("--role-min-considered", type=int, default=3)
    ap.add_argument("--role-min-confidence", type=float, default=0.6)
    ap.add_argument("--corpus-snapshot", default="")
    ap.add_argument(
        "--prev-emitted", type=int, default=0, help="prior index domain count for delta reporting"
    )
    ap.add_argument("--max-uncompressed-mb", type=float, default=50.0)
    a = ap.parse_args()
    csv.field_size_limit(10**7)

    dom_t = collections.defaultdict(dict)  # matched-pattern tallies
    with open(os.path.join(a.indir, "domain_pat.csv"), newline="") as fh:
        for r in csv.DictReader(fh):
            dom_t[r["dom"]][r["pattern"]] = int(r["n"])
    role_t = collections.defaultdict(lambda: collections.defaultdict(dict))
    with open(os.path.join(a.indir, "role_pat.csv"), newline="") as fh:
        for r in csv.DictReader(fh):
            role_t[r["dom"]][r["role"]][r["pattern"]] = int(r["n"])

    considered = {}  # TRUE denominators
    with open(os.path.join(a.indir, "considered_dom.csv"), newline="") as fh:
        for r in csv.DictReader(fh):
            considered[r["dom"]] = int(r["considered_n"])
    considered_role = collections.defaultdict(dict)
    with open(os.path.join(a.indir, "considered_role.csv"), newline="") as fh:
        for r in csv.DictReader(fh):
            considered_role[r["dom"]][r["role"]] = int(r["considered_n"])

    with open(os.path.join(a.indir, "funnel.csv"), newline="") as fh:
        funnel = {k: int(v) for k, v in next(csv.DictReader(fh)).items()}

    identity_path = os.path.join(a.indir, "build_identity.json")
    with open(identity_path, encoding="utf-8") as fh:
        build_identity = json.load(fh)
    if build_identity.get("normalization_version") != "norm/1":
        raise ValueError("aggregate normalization version must be norm/1")

    out = {}
    gpat = collections.Counter()
    conf_hist = collections.Counter()
    override_domains = 0

    for dom, tally in dom_t.items():
        cons = considered.get(dom, 0)
        if cons < a.min_considered:
            continue
        pat, dn = dominant(tally)  # dominant pattern + its count
        conf = dn / cons
        if not (dn >= a.min_dominant and conf >= a.min_confidence):
            continue
        rec = {"pattern": pat, "support_n": dn, "considered_n": cons, "confidence": round(conf, 4)}
        overrides = {}
        for role, rt in role_t.get(dom, {}).items():
            if role == "other":
                continue
            rcons = considered_role.get(dom, {}).get(role, 0)
            if rcons < a.role_min_considered:
                continue
            rpat, rdn = dominant(rt)
            rconf = rdn / rcons
            if rpat != pat and rconf >= a.role_min_confidence:
                overrides[role] = {
                    "pattern": rpat,
                    "support_n": rdn,
                    "considered_n": rcons,
                    "confidence": round(rconf, 4),
                }
        if overrides:
            rec["role_overrides"] = overrides
            override_domains += 1
        out[dom] = rec
        gpat[pat] += 1
        b = min(int(conf * 10), 9)
        conf_hist[f"{b / 10:.1f}-{(b + 1) / 10:.1f}"] += 1

    meta = {
        "schema": "company-patterns/1",
        "normalization_version": build_identity["normalization_version"],
        "pattern_enum": PATTERN_ENUM,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "corpus_snapshot": a.corpus_snapshot,
        "confidence_basis": "support_n / considered_n (all qualifying verified mailboxes)",
        "thresholds": {
            "min_considered": a.min_considered,
            "min_dominant": a.min_dominant,
            "min_confidence": a.min_confidence,
            "role_min_considered": a.role_min_considered,
            "role_min_confidence": a.role_min_confidence,
        },
        "rows_considered": funnel.get("rows_considered"),
        "pairs_resolved": funnel.get("pairs_resolved"),
        "domains_emitted": len(out),
    }

    full = {"_meta": meta}
    full.update(out)
    raw = json.dumps(full, separators=(",", ":"))
    unc_mb = len(raw.encode()) / 1e6
    out_path, fmt = a.out, "json"
    if unc_mb > a.max_uncompressed_mb:
        raise ValueError("artifact exceeds configured size limit; runtime requires JSON, not JSONL")
    with gzip.open(out_path, "wt", encoding="utf-8") as gz:
        gz.write(raw)

    L = []
    L.append("# Phase 0 — Company Email-Pattern Index — QA Report (Root-C true-denominator)\n")
    L.append(
        f"Generated: {meta['generated_at']}  ·  corpus: {a.corpus_snapshot or '(unlabeled)'}\n"
    )
    L.append(f"Output: `{os.path.basename(out_path)}` ({fmt}, ~{unc_mb:.1f} MB uncompressed)\n")
    L.append(
        "**Confidence = support_n / considered_n** "
        "(dominant count over all qualifying verified mailboxes).\n"
    )
    L.append("## Funnel\n")
    L.append(f"- verified rows (email+name+domain): **{funnel.get('verified_rows'):,}**")
    L.append(f"- after role/generic stoplist: **{funnel.get('after_stoplist'):,}**")
    L.append(f"- after name parse: **{funnel.get('after_name_parse'):,}**")
    L.append(
        "- rows considered (deduped per domain+localpart) = denominator population: "
        f"**{funnel.get('rows_considered'):,}**"
    )
    L.append(
        f"- pairs resolved (matched exactly one pattern): **{funnel.get('pairs_resolved'):,}**"
    )
    L.append(f"- **domains emitted (pre-MX): {len(out):,}**")
    if a.prev_emitted:
        d = len(out) - a.prev_emitted
        L.append(
            f"- delta vs previous index ({a.prev_emitted:,}): **{d:+,}** "
            f"({d / a.prev_emitted * 100:+.1f}%)"
        )
    L.append("")
    tot = max(len(out), 1)
    L.append("## Global pattern distribution (dominant per domain)\n")
    for p in PATTERN_ENUM:
        c = gpat.get(p, 0)
        L.append(f"- {p}: {c:>8,}  ({c / tot * 100:5.1f}%) {'#' * int(c / tot * 40)}")
    L.append("")
    L.append(
        f"## Role overrides\n- domains with >=1 override: **{override_domains:,}** "
        f"({override_domains / tot * 100:.1f}%)\n"
    )
    L.append("## Confidence histogram (true adherence — should span the range, not pile at 1.0)\n")
    for b in sorted(conf_hist):
        c = conf_hist[b]
        L.append(f"- {b}: {c:>8,}  {'#' * int(c / tot * 40)}")
    L.append("")
    L.append("## 20 random sample records (no personal data)\n")
    for d in sorted(random.sample(list(out.keys()), min(20, len(out)))):
        L.append(f"- `{d}` -> {json.dumps(out[d], separators=(',', ':'))}")
    L.append("")
    with open(a.qa, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))

    print(f"WROTE {out_path} ({fmt}, {unc_mb:.1f}MB) domains_emitted={len(out)}")


if __name__ == "__main__":
    main()
