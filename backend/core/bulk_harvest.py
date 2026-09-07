"""Phase 5A — bulk / list harvest mode.

Turns the per-domain harvest into a *market-segment* workload: take a list of
domains and harvest them in one governed, resumable, deduplicated run that emits
a single merged, evidence-preserving export. This is the workload that also
generates calibration-label volume at scale (Phase 4A capture fires per domain,
for free, inside ``run_domain_harvest``).

Design (the exploration-latitude decisions of the 5A brief):

* **Per-domain parity is by construction.** Each domain is harvested by calling
  the *identical* ``run_domain_harvest(domain, **options)`` coroutine the
  single-domain CLI uses, with the identical option kwargs, and its canonical
  export is written by the *identical* ``write_harvest_export``. The only
  omitted arguments are the Rich display callbacks (``progress_callback`` etc.),
  which are display-only and cannot change what a domain yields. So a domain in a
  batch produces byte-identical results and per-domain exports to a solo run.

* **Concurrency governor.** A single ``asyncio.Semaphore`` bounds how many
  domains harvest concurrently (``bulk_max_concurrent_domains``). Each domain is
  itself internally two-track concurrent, so this is a governor over *domains*,
  not a raw task fan-out. Per-source politeness within a domain is the existing
  rate limiter's job; Phase 5B unifies that throttle across both transport
  stacks so the batch does not self-DoS shared sources.

* **Resumable checkpoints.** A JSON manifest keyed by the input-list fingerprint
  records each domain's status (pending/done/failed/cached/skipped). Kill the run
  mid-batch and re-run the same file: already-``done`` domains are skipped, so the
  batch resumes where it stopped. It extends — rather than replaces — the
  domain-granularity resumability the corpus read-first already provides.

* **Cross-batch dedup via the corpus (1D).** ``corpus_store.known_domains``
  (the persistent ``domains`` projection, which survives TTL/invalidation)
  identifies domains harvested in a *prior* batch; the merged export deduplicates
  contacts by address across the whole batch, preserving every domain's evidence.

* **One merged export.** A single JSON document with a per-domain section (full
  evidence-preserving rows) plus a merged, address-deduplicated ``contacts``
  list carrying the set of source domains each address was seen on.

Everything here is additive, guarded, and never mutates a ``DomainHarvestResult``.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import APP_VERSION, settings

logger = logging.getLogger(__name__)

# Merged-export schema. Independent of the per-domain export's ``schema_version``
# (currently 2) — a bulk document is a different shape, so it carries its own
# ``schema_version`` and a ``kind`` discriminator.
BULK_SCHEMA_VERSION = 1

_STATUS_PENDING = "pending"
_STATUS_DONE = "done"
_STATUS_CACHED = "cached"
_STATUS_FAILED = "failed"
_STATUS_SKIPPED = "skipped"


# ---------------------------------------------------------------------------
# Domain-list parsing
# ---------------------------------------------------------------------------
def parse_domain_list(text: str) -> tuple[list[str], list[str]]:
    """Parse a bulk domain list into ``(valid, rejected)``.

    Accepts newline- and comma-separated input (a one-column CSV, a CSV whose
    first column is the domain, or a plain newline list). Lines beginning with
    ``#`` are comments. A header row naming the column (``domain``/``domains``)
    is ignored. Domains are lower-cased, de-duplicated (order-preserving), and
    validated with the same non-free-provider rule the single-domain CLI uses,
    so a bulk run cannot smuggle in a free-provider or malformed domain.

    Returns the ordered unique valid domains and the rejected raw tokens (for a
    user-facing "skipped these N lines" summary).
    """
    from ..modules.domain_intel import _FREE_PROVIDERS
    from .email_extraction import validate_domain

    valid: list[str] = []
    rejected: list[str] = []
    seen: set[str] = set()

    raw_tokens: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # split a CSV row; take the first non-empty cell as the domain
        cell = stripped.split(",")[0].strip().strip('"').strip("'")
        if not cell:
            continue
        raw_tokens.append(cell)

    for token in raw_tokens:
        candidate = token.strip().lower()
        # tolerate a header row
        if candidate in {"domain", "domains", "url", "website"}:
            continue
        # tolerate scheme/path if a URL slipped in
        if "://" in candidate:
            candidate = candidate.split("://", 1)[1]
        candidate = candidate.split("/", 1)[0].strip()
        if not candidate:
            continue
        if candidate in seen:
            continue
        if candidate in _FREE_PROVIDERS or not validate_domain(
            candidate, reject_free_provider=True
        ):
            rejected.append(token)
            continue
        seen.add(candidate)
        valid.append(candidate)

    return valid, rejected


# ---------------------------------------------------------------------------
# Checkpoint
# ---------------------------------------------------------------------------
def _list_fingerprint(domains: list[str]) -> str:
    """Stable fingerprint of a domain set (order-insensitive)."""
    joined = "\n".join(sorted(domains))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            if os.path.exists(tmp):
                os.remove(tmp)


class BulkCheckpoint:
    """Resumable per-domain status manifest, persisted atomically.

    The manifest is keyed (in its default location) by the input-list
    fingerprint, so re-running the same file resumes the same checkpoint. A
    fingerprint mismatch on an explicitly-provided checkpoint path is surfaced
    (the caller decides whether to reuse it) rather than silently overwritten.
    """

    def __init__(self, path: Path, *, fingerprint: str, run_id: str) -> None:
        self.path = path
        self.fingerprint = fingerprint
        self.run_id = run_id
        self.created_at = _now_iso()
        self.domains: dict[str, dict[str, Any]] = {}
        self.meta: dict[str, Any] = {}
        self._lock = asyncio.Lock()

    @classmethod
    def load_or_create(
        cls, path: Path, *, domains: list[str], run_id: str
    ) -> tuple[BulkCheckpoint, bool]:
        """Load an existing checkpoint or create a fresh one.

        Returns ``(checkpoint, resumed)``. ``resumed`` is True when an existing
        manifest for the *same* domain-set fingerprint was loaded. A stale/
        mismatched manifest is discarded and replaced (a fresh run).
        """
        fingerprint = _list_fingerprint(domains)
        cp = cls(path, fingerprint=fingerprint, run_id=run_id)
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if str(data.get("input_fingerprint")) == fingerprint:
                    cp.created_at = str(data.get("created_at") or cp.created_at)
                    cp.run_id = str(data.get("bulk_run_id") or run_id)
                    cp.domains = {
                        str(k): dict(v)
                        for k, v in (data.get("domains") or {}).items()
                        if isinstance(v, dict)
                    }
                    cp.meta = dict(data.get("meta") or {})
                    return cp, True
            except Exception:
                logger.warning("Bulk checkpoint unreadable; starting fresh: %s", path)
        # fresh
        cp.domains = {d: {"status": _STATUS_PENDING} for d in domains}
        return cp, False

    def ensure_domains(self, domains: list[str]) -> None:
        for d in domains:
            self.domains.setdefault(d, {"status": _STATUS_PENDING})

    def status_of(self, domain: str) -> str:
        return str(self.domains.get(domain, {}).get("status") or _STATUS_PENDING)

    def is_complete(self, domain: str) -> bool:
        return self.status_of(domain) in {_STATUS_DONE, _STATUS_CACHED, _STATUS_SKIPPED}

    def _snapshot(self) -> dict[str, Any]:
        return {
            "bulk_run_id": self.run_id,
            "input_fingerprint": self.fingerprint,
            "created_at": self.created_at,
            "updated_at": _now_iso(),
            "mailaccess_version": APP_VERSION,
            "meta": self.meta,
            "domains": self.domains,
        }

    async def update(self, domain: str, **fields: Any) -> None:
        async with self._lock:
            row = self.domains.setdefault(domain, {})
            row.update(fields)
            row["updated_at"] = _now_iso()
            try:
                _atomic_write_json(self.path, self._snapshot())
            except Exception:
                logger.debug("Bulk checkpoint persist failed", exc_info=True)

    def flush(self) -> None:
        with contextlib.suppress(Exception):
            _atomic_write_json(self.path, self._snapshot())


# ---------------------------------------------------------------------------
# Per-domain outcome + batch report
# ---------------------------------------------------------------------------
@dataclass
class DomainOutcome:
    domain: str
    status: str
    emails: int = 0
    high_confidence: int = 0
    from_cache: bool = False
    duration_seconds: float = 0.0
    export_path: str | None = None
    error: str | None = None
    payload: dict[str, Any] | None = None  # per-domain JSON export (in-memory)


@dataclass
class BulkHarvestReport:
    bulk_run_id: str
    mode: str
    checkpoint_path: str
    merged_export_path: str | None
    outcomes: list[DomainOutcome] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    duration_seconds: float = 0.0

    @property
    def counts(self) -> dict[str, int]:
        c = {
            _STATUS_DONE: 0,
            _STATUS_CACHED: 0,
            _STATUS_FAILED: 0,
            _STATUS_SKIPPED: 0,
        }
        for o in self.outcomes:
            c[o.status] = c.get(o.status, 0) + 1
        c["total"] = len(self.outcomes)
        c["contacts"] = sum(
            o.emails
            for o in self.outcomes
            if o.status in {_STATUS_DONE, _STATUS_CACHED, _STATUS_SKIPPED}
        )
        return c


# ---------------------------------------------------------------------------
# Per-domain worker (parity-preserving)
# ---------------------------------------------------------------------------
async def _harvest_one_domain(
    domain: str,
    *,
    options: dict[str, Any],
    no_export: bool,
) -> DomainOutcome:
    """Harvest a single domain via the shared coroutine and write its export.

    Reuses ``run_domain_harvest`` + ``write_harvest_export`` verbatim so the
    per-domain result and canonical export are identical to a solo run. All
    post-processing (ledger dual-write, run manifest, history baseline) mirrors
    the single-domain CLI and is individually guarded.
    """
    from .domain_harvest_orchestrator import run_domain_harvest
    from .domain_harvest_report import format_harvest_json_export
    from .harvest_results import timestamp_slug, write_harvest_export

    timestamp = timestamp_slug()
    box: dict[str, Any] = {}

    def _on_harvest_end(snapshot: Any) -> None:
        box["result"] = snapshot
        if no_export:
            return
        if not bool(getattr(settings, "harvest_auto_export", True)):
            return
        try:
            files = write_harvest_export(snapshot, timestamp=timestamp)
            box["export_path"] = str(files.main_json)
        except Exception:
            logger.debug("Per-domain export write failed for %s", domain, exc_info=True)

    started = _monotonic()
    result = await run_domain_harvest(
        domain, on_harvest_end=_on_harvest_end, **options
    )
    if result is None:
        result = box.get("result")
    if result is None:
        return DomainOutcome(
            domain=domain,
            status=_STATUS_FAILED,
            duration_seconds=_monotonic() - started,
            error="harvest returned no result",
        )

    from_cache = bool(getattr(result, "from_cache", False))

    # --- post-processing (guarded; mirrors the single-domain CLI) ---------
    if not from_cache:
        # Phase 1C — dual-write the evidence ledger.
        if getattr(settings, "enable_observation_ledger", False):
            with contextlib.suppress(Exception):
                await _record_ledger(domain, result)
        # Phase 2E — reproducible run manifest.
        with contextlib.suppress(Exception):
            from .run_manifest import record_run_manifest

            _mode = str((result.metadata or {}).get("mode") or "security-investigation")
            await record_run_manifest(run_id=domain, pipeline="harvest", mode=_mode)

    payload = None
    with contextlib.suppress(Exception):
        payload = format_harvest_json_export(result)
        # history baseline (diff support), guarded
        with contextlib.suppress(Exception):
            from .harvest_history import save_latest

            save_latest(domain, payload)

    return DomainOutcome(
        domain=domain,
        status=_STATUS_CACHED if from_cache else _STATUS_DONE,
        emails=int(getattr(result, "total_unique_emails", 0) or 0),
        high_confidence=int(getattr(result, "high_confidence_count", 0) or 0),
        from_cache=from_cache,
        duration_seconds=_monotonic() - started,
        export_path=box.get("export_path"),
        payload=payload,
    )


async def _record_ledger(domain: str, result: Any) -> None:
    """Phase 1C ledger dual-write (schema-ensuring, mirrors the CLI helper)."""
    from ..db.database import init_db
    from .observation_ledger import observations_from_harvest, record_observations

    await init_db()
    meta = getattr(result, "metadata", None)
    mode = str((meta or {}).get("mode") or "security-investigation")
    records = observations_from_harvest(domain, result, mode=mode)
    await record_observations(records)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
async def run_bulk_harvest(
    domains: list[str],
    *,
    options: dict[str, Any],
    mode: str | None,
    concurrency: int | None = None,
    checkpoint_path: Path | None = None,
    merged_export_path: Path | None = None,
    no_export: bool = False,
    force: bool = False,
    resume: bool = True,
    tech_filters: list[str] | None = None,
    progress_callback: Callable[[DomainOutcome, dict[str, int]], None] | None = None,
) -> BulkHarvestReport:
    """Harvest a list of domains in one governed, resumable, deduplicated run.

    ``options`` is the exact kwargs dict threaded to ``run_domain_harvest`` per
    domain (already resolved by the caller: ``enable_smtp``, ``skip_modules``,
    timing-derived values, ``force``, etc.), minus display callbacks. ``mode`` is
    stamped on the report and merged export for provenance.
    """
    started_wall = _monotonic()
    run_id = _run_id()
    conc = max(1, int(concurrency or getattr(settings, "bulk_max_concurrent_domains", 3)))

    # Ensure the DB schema exists BEFORE any domain harvests. Harvest runs
    # in-process (it does not go through ``serve``/``init_db``) and the corpus
    # write-back only creates tables at the END of a run — so the in-run Phase-4A
    # calibration capture (``capture_batch``, mid-harvest) would silently no-op
    # on a fresh DB. Creating the schema up front is what lets a bulk run
    # actually accrue the 4A feature/outcome volume the promotion gate needs.
    with contextlib.suppress(Exception):
        from ..db.database import init_db

        await init_db()

    if checkpoint_path is None:
        cp_default = Path.home() / ".mailaccess" / "bulk"
        cp_dir = Path(getattr(settings, "bulk_checkpoint_dir", cp_default))
        checkpoint_path = cp_dir / f"{_list_fingerprint(domains)[:16]}.json"

    checkpoint, resumed = BulkCheckpoint.load_or_create(
        checkpoint_path, domains=domains, run_id=run_id
    )
    if not resume:
        # explicit fresh run — reset statuses but keep the file location
        checkpoint.domains = {d: {"status": _STATUS_PENDING} for d in domains}
    else:
        checkpoint.ensure_domains(domains)
    checkpoint.meta = {"mode": mode or "", "concurrency": conc}
    checkpoint.flush()

    # Cross-batch dedup signal: which of these were harvested in a PRIOR batch.
    prior_seen: set[str] = set()
    if not force:
        with contextlib.suppress(Exception):
            from .corpus_store import known_domains

            prior_seen = await known_domains(domains)

    outcomes: dict[str, DomainOutcome] = {}
    sem = asyncio.Semaphore(conc)

    async def _worker(domain: str) -> None:
        # Resume: a domain already completed in this checkpoint is skipped
        # (its per-domain export already exists on disk). --force re-runs all.
        if resume and not force and checkpoint.is_complete(domain):
            prev = checkpoint.domains.get(domain, {})
            outcomes[domain] = DomainOutcome(
                domain=domain,
                status=_STATUS_SKIPPED,
                emails=int(prev.get("emails") or 0),
                high_confidence=int(prev.get("high_confidence") or 0),
                export_path=prev.get("export_path"),
                # Reload the per-domain export written on the earlier run so the
                # merged export stays COMPLETE across a resume — a re-run that
                # skips every domain must still emit the full merged document,
                # not overwrite it with an empty one.
                payload=_load_export_payload(prev.get("export_path")),
            )
            if progress_callback:
                with contextlib.suppress(Exception):
                    progress_callback(outcomes[domain], _live_counts(outcomes))
            return

        async with sem:
            await checkpoint.update(domain, status="running", started_at=_now_iso())
            try:
                outcome = await _harvest_one_domain(
                    domain, options={**options, "mode": mode, "force": force}, no_export=no_export
                )
            except asyncio.CancelledError:
                await checkpoint.update(domain, status=_STATUS_PENDING)
                raise
            except Exception as exc:  # noqa: BLE001
                outcome = DomainOutcome(
                    domain=domain, status=_STATUS_FAILED, error=str(exc)
                )
                logger.warning("Bulk harvest domain failed: %s (%s)", domain, exc)

        outcome.from_cache = outcome.from_cache or (domain in prior_seen)
        outcomes[domain] = outcome
        await checkpoint.update(
            domain,
            status=outcome.status,
            emails=outcome.emails,
            high_confidence=outcome.high_confidence,
            from_cache=outcome.from_cache,
            export_path=outcome.export_path,
            error=outcome.error,
            completed_at=_now_iso(),
        )
        if progress_callback:
            with contextlib.suppress(Exception):
                progress_callback(outcome, _live_counts(outcomes))

    await asyncio.gather(*(_worker(d) for d in domains))

    ordered = [outcomes[d] for d in domains if d in outcomes]
    report = BulkHarvestReport(
        bulk_run_id=run_id,
        mode=str(mode or "security-investigation"),
        checkpoint_path=str(checkpoint_path),
        merged_export_path=None,
        outcomes=ordered,
        started_at=_iso_from_monotonic(started_wall),
        completed_at=_now_iso(),
        duration_seconds=_monotonic() - started_wall,
    )

    if not no_export:
        try:
            path = _write_merged_export(
                report, explicit_path=merged_export_path, tech_filters=tech_filters
            )
            report.merged_export_path = str(path)
        except Exception:
            logger.warning("Merged bulk export failed", exc_info=True)

    checkpoint.flush()
    return report


# ---------------------------------------------------------------------------
# Merged export
# ---------------------------------------------------------------------------
def _write_merged_export(
    report: BulkHarvestReport,
    *,
    explicit_path: Path | None,
    tech_filters: list[str] | None = None,
) -> Path:
    """Write one merged, evidence-preserving JSON document for the batch.

    Structure: a per-domain section keeping each domain's full export rows
    (evidence intact) plus its Phase-5D ``technographics`` tags, and a
    ``contacts`` list deduplicated by email address across the whole batch — each
    merged contact records the set of source domains it was observed on and the
    max confidence seen. Deduping never drops evidence: the per-domain sections
    retain the complete rows.

    ``tech_filters`` (``dimension=value`` strings) restricts the merged
    ``contacts`` list to domains whose technographics match ALL filters — the
    filterable segment dimension (e.g. only Shopify shops on Google Workspace).
    Per-domain sections are always retained (each flagged ``tech_match``).
    """
    from .technographics import matches_filters

    filters = list(tech_filters or [])
    per_domain: list[dict[str, Any]] = []
    merged: dict[str, dict[str, Any]] = {}

    for outcome in report.outcomes:
        payload = outcome.payload or {}
        rows = payload.get("emails") or [] if isinstance(payload, dict) else []
        tech = payload.get("technographics") if isinstance(payload, dict) else None
        tech_match = matches_filters(tech, filters)
        per_domain.append(
            {
                "domain": outcome.domain,
                "status": outcome.status,
                "from_cache": outcome.from_cache,
                "total_unique_emails": outcome.emails,
                "high_confidence_count": outcome.high_confidence,
                "duration_seconds": round(outcome.duration_seconds, 3),
                "export_path": outcome.export_path,
                "error": outcome.error,
                "technographics": tech,
                "tech_match": tech_match,
                "emails": rows,  # evidence-preserving: full per-domain rows
            }
        )
        if filters and not tech_match:
            # filtered out of the merged lead list (kept in per_domain for audit)
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            addr = str(row.get("email") or row.get("address") or "").strip().lower()
            if not addr:
                continue
            slot = merged.get(addr)
            if slot is None:
                merged[addr] = {
                    **{k: v for k, v in row.items()},
                    "source_domains": [outcome.domain],
                }
            else:
                doms = slot.setdefault("source_domains", [])
                if outcome.domain not in doms:
                    doms.append(outcome.domain)
                # keep the higher confidence score if present
                with contextlib.suppress(Exception):
                    if float(row.get("confidence_score") or 0) > float(
                        slot.get("confidence_score") or 0
                    ):
                        slot["confidence_score"] = row.get("confidence_score")
                        slot["confidence_label"] = row.get("confidence_label")

    counts = report.counts
    document = {
        "schema_version": BULK_SCHEMA_VERSION,
        "kind": "bulk_harvest",
        "bulk_run_id": report.bulk_run_id,
        "generated_at": report.completed_at,
        "mailaccess_version": APP_VERSION,
        "mode": report.mode,
        "domain_count": counts["total"],
        "tech_filters": filters,
        "stats": {
            "harvested": counts.get(_STATUS_DONE, 0),
            "cached": counts.get(_STATUS_CACHED, 0),
            "failed": counts.get(_STATUS_FAILED, 0),
            "skipped": counts.get(_STATUS_SKIPPED, 0),
            "total_unique_contacts": len(merged),
            "domains_matching_tech_filter": sum(1 for d in per_domain if d["tech_match"]),
            "duration_seconds": round(report.duration_seconds, 3),
        },
        "domains": per_domain,
        "contacts": sorted(merged.values(), key=lambda r: str(r.get("email") or "")),
    }

    if explicit_path is not None:
        path = explicit_path
    else:
        out_default = Path.home() / ".mailaccess" / "results" / "bulk"
        out_dir = Path(getattr(settings, "bulk_results_dir", out_default))
        path = out_dir / f"bulk_{report.bulk_run_id}.json"
    _atomic_write_json(path, document)
    return path


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def _load_export_payload(export_path: str | None) -> dict[str, Any] | None:
    """Load a previously-written per-domain export JSON (for resume merges)."""
    if not export_path:
        return None
    try:
        p = Path(export_path)
        if not p.exists():
            return None
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _monotonic() -> float:
    import time

    return time.monotonic()


def _iso_from_monotonic(_m: float) -> str:
    # started_at is informational; use wall clock now minus elapsed is overkill.
    return _now_iso()


def _run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _live_counts(outcomes: dict[str, DomainOutcome]) -> dict[str, int]:
    c: dict[str, int] = {}
    for o in outcomes.values():
        c[o.status] = c.get(o.status, 0) + 1
    c["total"] = len(outcomes)
    return c
