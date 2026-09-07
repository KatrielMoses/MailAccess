"""Classify pytest failures into env-only / pre-existing-known / real buckets.

Parses a pytest run captured with ``-rfE`` (one ``FAILED/ERROR <nodeid> - <reason>``
line per failure) and applies transparent heuristics so the failure catalogue is
reproducible instead of hand-maintained. The heuristic is a *first pass* — a human
confirms the ``real`` bucket before trusting it.

Buckets:
  env-only            : timeouts, network/DNS/connection errors, missing optional
                        deps (spacy/weasyprint/ghunt) — noise from THIS environment,
                        not a code defect.
  pre-existing-known  : import/collection errors from known-broken modules, and
                        anything already in the committed baseline.
  real                : assertion/type/value failures in the tool's own logic —
                        candidate genuine failures a human should review.

Usage:
  python -m eval.harness.classify_failures <pytest_output.txt> [--md]
"""
from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

from eval.harness.gate import TEST_BASELINE, _read_lines

LINE_RE = re.compile(r"^(FAILED|ERROR)\s+(\S+?)(?:\s+-\s+(.*))?$")

ENV_SIGNALS = (
    "Timeout",
    "timeout",
    "ConnectionError",
    "ConnectTimeout",
    "ReadTimeout",
    "socket.gaierror",
    "getaddrinfo",
    "Failed to establish",
    "Max retries",
    "NameResolutionError",
    "httpx.ConnectError",
    "httpcore",
    "ssl.SSLError",
    "No module named 'spacy'",
    "No module named 'weasyprint'",
    "No module named 'ghunt'",
    "en_core_web",
    # Windows/filesystem environment artifacts (temp-dir perms, cleanup races).
    "PermissionError",
    "WinError",
    "Access is denied",
    "being used by another process",
    "BlockedNetworkError",
    "no_network",
)
PREEXISTING_SIGNALS = (
    "No module named 'backend.discovery'",  # test_domain_discovery.py known-broken import
    "ModuleNotFoundError",
    "ImportError",
    "collection",
)
REAL_SIGNALS = (
    "AssertionError",
    "TypeError",
    "ValueError",
    "KeyError",
    "AttributeError",
)


def classify_reason(reason: str) -> str:
    r = reason or ""
    if any(sig in r for sig in ENV_SIGNALS):
        return "env-only"
    if any(sig in r for sig in PREEXISTING_SIGNALS):
        return "pre-existing-known"
    if any(sig in r for sig in REAL_SIGNALS):
        return "real"
    return "unclassified"


def parse(path: Path) -> list[tuple[str, str, str]]:
    """Return list of (kind, nodeid, reason)."""
    out: list[tuple[str, str, str]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = LINE_RE.match(line.strip())
        if m:
            out.append((m.group(1), m.group(2), (m.group(3) or "").strip()))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("output", help="captured pytest -rfE output file")
    ap.add_argument("--md", action="store_true", help="emit a markdown table")
    args = ap.parse_args(argv)

    rows = parse(Path(args.output))
    baseline = _read_lines(TEST_BASELINE)
    buckets: Counter[str] = Counter()
    by_file: dict[str, Counter[str]] = {}
    classified: list[tuple[str, str, str, str]] = []
    for kind, nodeid, reason in rows:
        bucket = classify_reason(reason)
        if bucket == "unclassified" and nodeid in baseline:
            bucket = "pre-existing-known"
        buckets[bucket] += 1
        fname = nodeid.split("::", 1)[0]
        by_file.setdefault(fname, Counter())[bucket] += 1
        classified.append((bucket, kind, nodeid, reason[:120]))

    print(f"Total failing: {len(rows)}")
    for b in ("env-only", "pre-existing-known", "real", "unclassified"):
        print(f"  {b:20s} {buckets.get(b, 0)}")

    if args.md:
        print("\n### By bucket\n")
        print("| bucket | count |")
        print("|---|---|")
        for b in ("env-only", "pre-existing-known", "real", "unclassified"):
            print(f"| {b} | {buckets.get(b, 0)} |")
        print("\n### `real` + `unclassified` (human-review candidates)\n")
        print("| bucket | nodeid | reason |")
        print("|---|---|---|")
        for bucket, _kind, nodeid, reason in classified:
            if bucket in ("real", "unclassified"):
                safe_reason = reason.replace("|", "\\|")
                print(f"| {bucket} | `{nodeid}` | {safe_reason} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
