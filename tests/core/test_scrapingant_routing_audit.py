from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

ROUTING_TEST = Path(__file__).with_name("test_zone2_scrapingant_routing.py")
spec = importlib.util.spec_from_file_location("zone2_routing_table", ROUTING_TEST)
assert spec is not None
zone2_routing_table = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = zone2_routing_table
spec.loader.exec_module(zone2_routing_table)

REPO_ROOT = zone2_routing_table.REPO_ROOT
ZONE2_AUDITED_CALL_SITES = zone2_routing_table.ZONE2_AUDITED_CALL_SITES
Zone2AuditCallSite = zone2_routing_table.Zone2AuditCallSite

POLICY_DOC = REPO_ROOT / "docs" / "scrapingant-routing-policy.md"


def _policy_rows() -> set[tuple[str, str, int, str]]:
    rows: set[tuple[str, str, int, str]] = set()
    for raw_line in POLICY_DOC.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line.startswith("| backend/modules/"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 6:
            continue
        module_path, function_name, call_index, _pattern, decision, _reason = cells
        rows.add((module_path, function_name, int(call_index), decision))
    return rows


def _source(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def _tree(relative_path: str) -> ast.Module:
    return ast.parse(_source(relative_path), filename=relative_path)


def _function(relative_path: str, function_name: str) -> ast.AST:
    for node in ast.walk(_tree(relative_path)):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == function_name:
            return node
    raise AssertionError(f"{function_name} not found in {relative_path}")


def _build_client_calls(function: ast.AST) -> list[ast.Call]:
    calls: list[ast.Call] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "build_client":
            continue
        calls.append(node)
    return sorted(calls, key=lambda call: (call.lineno, call.col_offset))


def _scrapingant_zone(call: ast.Call) -> str | None:
    for keyword in call.keywords:
        if keyword.arg == "scrapingant_zone" and isinstance(keyword.value, ast.Constant):
            return keyword.value.value
    return None


def _call(call_site: Zone2AuditCallSite) -> ast.Call:
    calls = _build_client_calls(_function(call_site.module_path, call_site.function_name))
    assert len(calls) >= call_site.call_index, call_site
    return calls[call_site.call_index - 1]


def _has_scrapingant_comment(call_site: Zone2AuditCallSite, call: ast.Call) -> bool:
    lines = _source(call_site.module_path).splitlines()
    start = max(0, call.lineno - 4)
    return any("# scrapingant:" in line for line in lines[start : call.lineno])


def test_policy_doc_rows_match_zone2_audited_call_sites() -> None:
    doc_rows = _policy_rows()
    code_rows = {
        (call.module_path, call.function_name, call.call_index, call.decision)
        for call in ZONE2_AUDITED_CALL_SITES
    }
    assert doc_rows == code_rows


def test_kept_call_sites_still_carry_platforms_zone_and_comment() -> None:
    for call_site in ZONE2_AUDITED_CALL_SITES:
        if call_site.decision != "KEEP":
            continue
        call = _call(call_site)
        assert _scrapingant_zone(call) == "platforms", call_site
        assert _has_scrapingant_comment(call_site, call), call_site


def test_dropped_call_sites_still_have_no_scrapingant_zone_and_comment() -> None:
    for call_site in ZONE2_AUDITED_CALL_SITES:
        if call_site.decision != "DROP":
            continue
        call = _call(call_site)
        assert _scrapingant_zone(call) is None, call_site
        assert _has_scrapingant_comment(call_site, call), call_site
