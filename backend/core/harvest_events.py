"""``--events-jsonl``: the harvest's run events, one JSON object per line.

Same event types as the investigation stream (``run_started``, ``module_start``,
``module_progress``, ``finding``, ``module_done``, ``run_done``...). Each line is
flushed as written so the file can be tailed while the harvest runs. Nothing is
saved to the database and keys are scrubbed exactly as in the investigation stream.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .run_events import RunEventEmitter
from .techniques import technique_for


CANDIDATE_MIN_INTERVAL = 0.25  # at most 4 candidate events a second per module and kind


class HarvestEvents:
    def __init__(self, path: str | Path, domain: str, planned_modules: list[str], mode: str = "") -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("w", encoding="utf-8")
        self.emitter = RunEventEmitter(f"harvest:{domain}", persist=False, sink=self._write)
        self.domain = domain
        self.planned = list(planned_modules)
        self._started: dict[str, float] = {}
        self._done: dict[str, int] = {}
        self._found: dict[str, int] = {}
        self._finding_id = 0
        self.candidates = 0
        self._pending: dict[tuple[str, str], int] = {}
        self._last_candidate: dict[tuple[str, str], float] = {}
        self._closed = False
        self.emitter.emit(
            "run_started",
            {
                "mode": mode,
                "planned_modules": [
                    {"module": m, "phase": "harvest", "technique_id": technique_for(m)[0]}
                    for m in self.planned
                ],
                "total_sources": len(self.planned),
                "unavailable": [],
            },
        )
        self.emitter.emit("phase_start", {"phase": "harvest", "modules": self.planned})
        self._t0 = time.monotonic()

    def _write(self, event: dict[str, Any]) -> None:
        """One line: the contract's wire object (fields at the top level plus ``seq`` and
        ``ts``) plus ``type``. A payload field already named ``type`` (an edge's type)
        is written as ``edge_type`` so it cannot clash with the event type."""
        fields = dict(event["payload"])
        if "type" in fields:
            fields["edge_type"] = fields.pop("type")
        line = {"seq": event["seq"], "ts": event["ts"], "type": event["type"], **fields}
        self._fh.write(json.dumps(line, separators=(",", ":"), default=str) + "\n")
        self._fh.flush()

    # callbacks handed to run_domain_harvest -------------------------------
    def progress(self, module: str, action: str) -> None:
        if self._closed:
            return
        if module not in self._started:
            self._started[module] = time.monotonic()
            tech_id, tech_line = technique_for(module)
            self.emitter.emit(
                "module_start",
                {"module": module, "phase": "harvest", "technique_id": tech_id,
                 "technique": tech_line},
            )
        total = max(len(self.planned), len(self._started))
        self.emitter.progress(module, len(self._done), total)

    def complete(self, module: str, status: str, errors: list[str] | None = None) -> None:
        if self._closed or module in self._done:
            return
        if module not in self._started:
            self.progress(module, "")
        started = self._started.get(module, time.monotonic())
        norm = str(status or "failed").lower()
        norm = {"success_empty": "empty"}.get(norm, norm)
        self._done[module] = norm
        text = " ".join(str(e) for e in (errors or [])).lower()
        reason = None
        if norm == "skipped":
            reason = "budget" if "budget" in text else "no_key" if "key" in text else "disabled"
        self.emitter.emit(
            "module_done",
            {
                "module": module,
                "status": norm,
                # Harvest findings are emitted only from the final result, so a module has
                # no findings of its own yet; what it returned so far is a candidate count.
                "findings_count": 0,
                "candidates": self._found.get(module, 0),
                "duration_ms": int((time.monotonic() - started) * 1000),
                "skipped_reason": reason,
            },
        )

    def signal(self, signal: Any) -> None:
        """A raw harvest signal is only a CANDIDATE: an email, name or subdomain a source
        returned that the final scoring and filtering may still drop (pattern guesses,
        other-domain addresses, placeholders). It streams as a ``candidate`` event with
        no value, throttled to 4 a second per module and kind. Results are the
        ``finding`` events emitted from the final export in :meth:`finalize`."""
        if self._closed:
            return
        source = str(getattr(signal, "source", "unknown"))
        kind = {"email": "email", "name": "name", "subdomain": "domain"}.get(
            str(getattr(signal, "kind", "") or ""), "other"
        )
        self._found[source] = self._found.get(source, 0) + 1
        key = (source, kind)
        self._pending[key] = self._pending.get(key, 0) + 1
        self.candidates += 1
        now = time.monotonic()
        if now - self._last_candidate.get(key, -1.0) >= CANDIDATE_MIN_INTERVAL:
            self._flush_candidates(key)

    def _flush_candidates(self, only: tuple[str, str] | None = None) -> None:
        for key in [only] if only else list(self._pending):
            count = self._pending.pop(key, 0)
            if count:
                self._last_candidate[key] = time.monotonic()
                self.emitter.emit("candidate", {"module": key[0], "kind": key[1], "count": count})

    # ------------------------------------------------------------ final result
    def _emit_final(self, module: str, kind: str, value: str, reason: str, signal: str) -> None:
        self._finding_id += 1
        tech_id, tech_line = technique_for(module)
        self.emitter.emit(
            "finding",
            {
                "finding_id": self._finding_id,
                "module": module,
                "kind": kind,
                "title": value,
                "value": value,
                "url": None,
                "label": None,
                "trace": {
                    "technique_id": tech_id,
                    "technique": tech_line,
                    "signal": signal,
                    "derived_from": {"type": "domain", "value": self.domain, "finding_id": None},
                    "corroborated_by": [],
                    "independent_signals": 0,
                    "reason": reason[:159],
                },
            },
        )

    def finalize(self, export: dict[str, Any] | None, status: str = "complete") -> None:
        """Emit one ``finding`` per email, name and subdomain in the exported result, in
        export order with the same values, then ``run_done`` with counts that match the
        export exactly. Nothing the export drops is ever emitted as a finding."""
        if self._closed:
            return
        self._flush_candidates()
        export = export or {}
        emails = [e for e in (export.get("emails") or []) if isinstance(e, dict) and e.get("email")]
        names = [n for n in (export.get("discovered_names") or []) if isinstance(n, dict) and n.get("name")]
        subs = [x for x in (export.get("subdomains") or []) if isinstance(x, dict) and x.get("subdomain")]
        for row in emails:
            mods = [str(m) for m in (row.get("found_by_modules") or []) if m]
            module = mods[0] if mods else "harvest"
            where = ", ".join(m.replace("_", " ") for m in mods[:3]) or "the harvest"
            label = str(row.get("confidence_label") or "").lower()
            self._emit_final(
                module, "email", str(row["email"]),
                f"Found by {where} for {self.domain}" + (f" ({label} confidence)." if label else "."),
                f"{where} returned this email address and it passed the final filter.",
            )
        for row in names:
            srcs = [str(x) for x in (row.get("sources") or []) if x]
            module = srcs[0] if srcs else "employee_name_discovery"
            where = ", ".join(x.replace("_", " ") for x in srcs[:3]) or "name discovery"
            self._emit_final(
                module, "name", str(row["name"]),
                f"A person named in {where} for {self.domain}.",
                f"{where} returned this name and it passed the final filter.",
            )
        for row in subs:
            methods = row.get("discovery_method") or []
            methods = [methods] if isinstance(methods, str) else [str(m) for m in methods]
            module = "subdomain_intel"
            where = ", ".join(m.replace("_", " ") for m in methods[:3]) or "subdomain discovery"
            self._emit_final(
                module, "domain", str(row["subdomain"]),
                f"A host under {self.domain}, found by {where}.",
                f"{where} found this host under the domain.",
            )
        self._close_run(status, emails=len(emails), names=len(names), subdomains=len(subs))

    def _close_run(self, status: str, *, emails: int, names: int, subdomains: int) -> None:
        for module in self._started:
            if module not in self._done:
                self.complete(module, "partial" if status == "complete" else "failed")
        self.emitter.emit(
            "phase_end", {"phase": "harvest", "duration_ms": int((time.monotonic() - self._t0) * 1000)}
        )
        checked = sum(1 for v in self._done.values() if v in ("success", "empty", "partial", "failed"))
        done = {
            "status": status,
            "sources_checked": checked,
            "total_sources": max(len(self.planned), len(self._started)),
            "findings": emails + names + subdomains,
            "exposure_score": None,
            "candidates": self.candidates,
            "emails": emails,
            "names": names,
            "subdomains": subdomains,
        }
        if status == "failed":
            done["error"] = "the harvest did not finish"
        self.emitter.emit("run_done", done)
        self._closed = True
        self._fh.close()

    def finish(self, status: str = "complete") -> None:
        """End the run without a result (the harvest failed before one existed)."""
        if self._closed:
            return
        self._flush_candidates()
        self._close_run(status, emails=0, names=0, subdomains=0)
