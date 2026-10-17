"""Glue between the engine and the run event log.

Turns module lifecycle and findings into small events (``module_start``,
``finding``, ``edge_added``, ``module_done``, ``finding_updated``...) on the run's
:class:`~backend.core.run_events.RunEventEmitter`. Every function is a no-op when no
run is being recorded, so modules and tests that run without an emitter are
unaffected.
"""

from __future__ import annotations

import logging
from typing import Any

from . import evidence
from .run_events import RunEventEmitter, current
from .techniques import technique_for

logger = logging.getLogger(__name__)

NODE_TYPES = ("email", "username", "account", "name", "domain", "breach", "phone")
_BREACH_MODULES = evidence._BREACH_MODULES
# Domains only count as part of the person's graph when they come from ownership records.
_DOMAIN_OWNER_MODULES = frozenset({"whoisfreaks_intel", "netlas_email_footprint"})
_MAX_VALUE = 200
_STATUS_MAP = {"success_empty": "empty"}
CHECKED_STATUSES = frozenset({"success", "empty", "partial", "failed"})


def _title_and_value(finding: dict[str, Any], module: str) -> tuple[str, str]:
    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    title = evidence.finding_title(module, finding)
    if finding.get("label") == evidence.USERNAME_MATCH:
        # The username itself (the URL goes in ``url``), so viewers can group the sites
        # where one username exists instead of treating every site as its own username.
        return title, evidence._username(finding)[:_MAX_VALUE]
    value = ""
    for candidate in (
        finding.get("profile_url"),
        finding.get("url"),
        finding.get("username"),
        meta.get("discovered_email"),
        meta.get("email"),
        meta.get("domain"),
        finding.get("domain"),
    ):
        if isinstance(candidate, str) and candidate.strip():
            value = candidate.strip()[:_MAX_VALUE]
            break
    return title, value


def finding_payload(
    emitter: RunEventEmitter, fid: int, module: str, finding: dict[str, Any]
) -> dict[str, Any]:
    trace = finding["trace"]
    title, value = _title_and_value(finding, module)
    label = finding.get("label")
    return {
        "finding_id": fid,
        "module": module,
        "kind": evidence.kind_for(module, finding, label),
        "title": title,
        "value": value,
        "url": evidence.finding_url(finding),
        "label": label,
        "trace": _public_trace(trace),
    }


def _public_trace(trace: dict[str, Any]) -> dict[str, Any]:
    keys = ("technique_id", "technique", "signal", "derived_from", "corroborated_by",
            "independent_signals", "reason")
    return {k: trace.get(k) for k in keys}


# ----------------------------------------------------------------------- graph nodes
def contract_node(
    node_type: str, label: str, value: str, module: str = "", *, allow_domain: bool = False,
    kind: str = "",
) -> dict[str, str] | None:
    """Map a saved-graph node to the contract's node vocabulary, or None to leave it
    out of the live graph. Only identity things appear: the email, usernames, accounts,
    names, breaches, phones, and domains from ownership records."""
    value = str(value or "").strip()
    label = str(label or value).strip()[:80]
    if not value:
        return None
    key = value.lower()
    if node_type == "email":
        return {"id": f"email:{key}", "type": "email", "label": label}
    if node_type == "username":
        return {"id": f"username:{key}", "type": "username", "label": label}
    if node_type == "site":  # a site where a username exists: shown as a username match
        return {"id": f"username:@{key}", "type": "username", "label": label}
    if node_type == "platform":
        ntype = "breach" if module in _BREACH_MODULES or kind == "breach" else (
            "name" if kind == "name" else "account"
        )
        return {"id": f"{ntype}:{label.lower()}", "type": ntype, "label": label}
    if node_type == "display_name":
        return {"id": f"name:{key}", "type": "name", "label": label}
    if node_type == "phone":
        return {"id": f"phone:{key}", "type": "phone", "label": label}
    if node_type == "domain" and allow_domain:
        return {"id": f"domain:{key}", "type": "domain", "label": label}
    return None  # photo_url and anything else


def _announce(emitter: RunEventEmitter, src: dict, tgt: dict, etype: str, reason: str,
              finding_id: int | None) -> None:
    key = (src["id"], tgt["id"], etype)
    if src["id"] == tgt["id"] or key in emitter.announced_edges:
        return
    emitter.announced_edges.add(key)
    emitter.announced_nodes.update((src["id"], tgt["id"]))
    emitter.emit(
        "edge_added",
        {"source": src, "target": tgt, "type": etype, "reason": str(reason or "")[:160],
         "finding_id": finding_id},
    )


def emit_edges(
    emitter: RunEventEmitter, module: str, finding: dict[str, Any], email: str, finding_id: int
) -> None:
    """Announce the graph edges this finding adds (email -> username -> account -> name).
    Only identity findings draw edges; records read directly (DNS, WHOIS...) never do."""
    if finding.get("label") is None:
        return
    try:
        from .identity_graph import IdentityGraph

        nodes, edges = IdentityGraph.edges_for_finding(email, module, finding)
    except Exception:
        logger.debug("edge emission failed for %s", module, exc_info=True)
        return
    allow = module in _DOMAIN_OWNER_MODULES
    for edge in edges:
        a, b = nodes.get(edge.source), nodes.get(edge.target)
        if a is None or b is None:
            continue
        src = contract_node(a.type, a.label, a.value, str(a.metadata.get("module") or module),
                            allow_domain=allow, kind=str(a.metadata.get("kind") or ""))
        tgt = contract_node(b.type, b.label, b.value, str(b.metadata.get("module") or module),
                            allow_domain=allow, kind=str(b.metadata.get("kind") or ""))
        if src and tgt:
            _announce(emitter, src, tgt, edge.type, edge.metadata.get("reason"), finding_id)


def emit_finding(
    emitter: RunEventEmitter, module: str, finding: dict[str, Any], email: str
) -> int | None:
    """Annotate (trace + label) and announce one finding. Idempotent per finding."""
    if not isinstance(finding, dict):
        return None
    fid, is_new = emitter.finding_id_for(finding)
    if not isinstance(finding.get("trace"), dict):
        evidence.build_trace(module, finding, email)
    if not is_new:
        return fid
    emitter.finding_count += 1
    emitter.finding_state[fid] = (str(finding.get("label")), str(finding["trace"].get("reason")))
    emitter.emit("finding", finding_payload(emitter, fid, module, finding))
    emit_edges(emitter, module, finding, email, fid)
    return fid


class EmittingSink(list):
    """The run-owned accumulator handed to modules that stream hits (``sink=``).

    Each hit is annotated and announced the instant the module appends it, so a
    username sweep shows findings as they land, not when the module finishes."""

    def __init__(self, module: str, emitter: RunEventEmitter, email: str) -> None:
        super().__init__()
        self._module = module
        self._emitter = emitter
        self._email = email

    def append(self, finding: Any) -> None:  # type: ignore[override]
        super().append(finding)
        try:
            emit_finding(self._emitter, self._module, finding, self._email)
        except Exception:
            logger.debug("streaming a finding failed", exc_info=True)


def make_sink(module: str, email: str) -> list:
    emitter = current()
    return EmittingSink(module, emitter, email) if emitter is not None else []


# -------------------------------------------------------------------- lifecycle
def module_started(module: str, phase: str | None = None, *, followup: bool = False) -> None:
    emitter = current()
    if emitter is None:
        return
    emitter.module_started(module)
    emitter.modules_started.add(module)
    tech_id, tech_line = technique_for(module)
    payload = {"module": module, "phase": phase or getattr(emitter, "phase", ""),
               "technique_id": tech_id, "technique": tech_line}
    if followup:
        payload["followup"] = True
    emitter.emit("module_start", payload)


def skipped_reason(result: Any) -> str | None:
    """``budget`` | ``no_key`` | ``disabled`` | None (the contract's closed set)."""
    status = getattr(getattr(result, "status", None), "value", getattr(result, "status", ""))
    if str(status) != "skipped":
        return None
    meta = getattr(result, "metadata", None) or {}
    errors = " ".join(str(e) for e in (getattr(result, "errors", None) or [])).lower()
    reason = str(meta.get("skip_reason") or "").lower()
    if meta.get("budget_truncated") or "budget" in errors:
        return "budget"
    if "api key" in errors or "api_key" in errors or "key not set" in errors or "_key" in errors \
            or "requires a key" in errors:
        return "no_key"
    return "disabled"


def module_finished(module: str, result: Any, email: str) -> None:
    emitter = current()
    if emitter is None:
        return
    for finding in getattr(result, "findings", None) or []:
        emit_finding(emitter, module, finding, email)
    duration_ms = emitter.module_finished(module)
    emitter.modules_done.add(module)
    raw = getattr(getattr(result, "status", None), "value", str(getattr(result, "status", "")))
    status = _STATUS_MAP.get(raw, raw)
    if status in CHECKED_STATUSES:
        emitter.modules_checked.add(module)
    emitter.emit(
        "module_done",
        {
            "module": module,
            "status": status,
            "findings_count": len(getattr(result, "findings", None) or []),
            "duration_ms": duration_ms,
            "skipped_reason": skipped_reason(result),
        },
    )


# --------------------------------------------------------------------- finalising
def finalize(
    emitter: RunEventEmitter,
    final: dict[str, Any],
    graph_data: dict | None,
    email: str,
) -> None:
    """After dedup/promotion: tell viewers about changed labels, then announce any
    graph edge (and its endpoints) that the live chain did not already show."""
    for module, result in final.items():
        for finding in getattr(result, "findings", None) or []:
            if not isinstance(finding, dict):
                continue
            if not isinstance(finding.get("trace"), dict):
                evidence.build_trace(module, finding, email)
            fid, is_new = emitter.finding_id_for(finding)
            trace = finding["trace"]
            if is_new:
                emitter.finding_count += 1
                emitter.emit("finding", finding_payload(emitter, fid, module, finding))
            else:
                state = (str(finding.get("label")), str(trace.get("reason")))
                if emitter.finding_state.get(fid) != state:
                    emitter.emit(
                        "finding_updated",
                        {"finding_id": fid, "label": finding.get("label"),
                         "trace": _public_trace(trace)},
                    )
            emitter.finding_state[fid] = (str(finding.get("label")), str(trace.get("reason")))
            meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
            for merged in meta.get("merged_finding_ids") or []:
                if merged in emitter.findings_by_id:
                    emitter.emit(
                        "finding_updated",
                        {
                            "finding_id": merged,
                            "label": emitter.findings_by_id[merged].get("label"),
                            "merged_into": fid,
                        },
                    )
    if not graph_data:
        return
    nodes = {n["id"]: n for n in graph_data.get("nodes", [])}

    def _map(node: dict[str, Any], module: str, allow: bool) -> dict[str, str] | None:
        owner = str((node.get("metadata") or {}).get("module") or module)
        return contract_node(node["type"], node["label"], node["value"], owner, allow_domain=allow,
                             kind=str((node.get("metadata") or {}).get("kind") or ""))

    for link in graph_data.get("links", []):
        a, b = nodes.get(link.get("source")), nodes.get(link.get("target"))
        if a is None or b is None:
            continue
        meta = link.get("metadata") or {}
        module = str(meta.get("module") or "")
        allow = module in _DOMAIN_OWNER_MODULES
        src, tgt = _map(a, module, allow), _map(b, module, allow)
        if src and tgt:
            _announce(emitter, src, tgt, str(link.get("type")), meta.get("reason"), meta.get("finding_id"))
