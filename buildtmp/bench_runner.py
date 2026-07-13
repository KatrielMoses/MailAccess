"""Tiny harness: run harvest-emails in-process, force the export, return JSON.

Wraps :func:`cli.harvest_emails.run_harvest_emails` directly so we can
call the export code path without re-running the harvest (which takes
15+ minutes and gets CAPTCHA'd on a re-run).  Reuses the persisted
result aggregator state from the in-process orchestrator.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path


async def main(domain: str, export_path: str) -> int:
    from backend.core.domain_harvest_orchestrator import run_domain_harvest
    from backend.core.domain_harvest_report import (
        format_harvest_cli_output,
        serialise_harvest_for_export,
    )

    print(f"Running harvest-emails on {domain} (lite + fast)...", flush=True)
    result = await run_domain_harvest(
        domain,
        enable_smtp=False,
        dork_lite_mode=True,  # --lite
        aggressive=False,
        use_proxies=False,
    )
    print(f"Harvest complete: status={result.status}", flush=True)

    payload = serialise_harvest_for_export(result)
    p = Path(export_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Exported to {p} ({p.stat().st_size} bytes)", flush=True)
    return 0


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "ine.com"
    export = sys.argv[2] if len(sys.argv) > 2 else f"results/bench_{domain.replace('.', '_')}_0.11.3.json"
    raise SystemExit(asyncio.run(main(domain, export)))
