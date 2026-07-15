"""Run the fixed harvest quality/yield benchmark."""
from __future__ import annotations
import argparse, asyncio, inspect, json
from datetime import datetime, timezone
from pathlib import Path
from backend.core.domain_harvest_orchestrator import run_domain_harvest
from backend.core.domain_harvest_report import format_harvest_json_export

async def _run(domains: list[str], timeout_per_domain: float) -> dict[str, object]:
    runs = []
    for domain in domains:
        kwargs = {"timeout_seconds": timeout_per_domain} if "timeout_seconds" in inspect.signature(run_domain_harvest).parameters else {}
        print(f"Starting {domain} (budget={timeout_per_domain:.0f}s)", flush=True)
        try:
            export = format_harvest_json_export(await run_domain_harvest(domain, **kwargs))
        except asyncio.TimeoutError:
            runs.append({"domain": domain, "quality_gates": {"passed": False, "failures": ["benchmark timeout"]}})
            print(f"{domain}: benchmark timeout", flush=True)
            continue
        metrics = export["summary"]["p0_p1_metrics"]
        failures = []
        if metrics["unique_emails"] != len(export["emails"]): failures.append("summary/email count mismatch")
        if metrics["unique_personal_emails"] + metrics["role_accounts"] != metrics["unique_emails"]: failures.append("personal/role count mismatch")
        if not metrics["pgp_quality"]["quality_pass"]: failures.append("PGP evidence contract failed")
        if metrics["module_errors"]:
            failures.append(f"module errors present ({metrics['module_errors']})")
        export["quality_gates"] = {"passed": not failures, "failures": failures}
        timings = export["summary"].get("module_timings", {})
        export["benchmark_telemetry"] = {
            "slowest_modules": sorted(timings.items(), key=lambda item: item[1], reverse=True)[:5],
            "skipped_modules": export["summary"].get("module_skip_reasons", {}),
        }
        runs.append(export)
        slowest = export["benchmark_telemetry"]["slowest_modules"]
        slowest_text = ", ".join(f"{name}={seconds:.1f}s" for name, seconds in slowest[:2])
        print(f"{domain}: unique={metrics['unique_emails']} personal={metrics['unique_personal_emails']} errors={metrics['module_errors']} slowest=[{slowest_text}] gates={'PASS' if not failures else 'FAIL'}", flush=True)
    return {"schema_version": 1, "benchmark_started_at": datetime.now(timezone.utc).isoformat(), "domains": domains, "runs": runs}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).parents[1] / "data" / "harvest_benchmark_domains.json")
    parser.add_argument("--output", type=Path, default=Path("results/harvest_p0_p1_baseline.json"))
    parser.add_argument("--timeout-per-domain", type=float, default=30.0)
    args = parser.parse_args()
    domains = json.loads(args.manifest.read_text(encoding="utf-8"))["domains"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(asyncio.run(_run(domains, args.timeout_per_domain)), indent=2, default=str) + "\n", encoding="utf-8")
    print(f"Wrote benchmark: {args.output}")
    return 0

if __name__ == "__main__": raise SystemExit(main())
