from __future__ import annotations

from backend.core.aggregator import ResultAggregator
from backend.modules.base import ModuleResult, ModuleStatus


def _result(status: ModuleStatus, *findings: dict) -> ModuleResult:
    return ModuleResult(status=status, findings=list(findings))


def test_aggregator_starts_empty() -> None:
    aggregator = ResultAggregator()

    assert aggregator.summary["total_modules"] == 0
    assert aggregator.all_findings == []


def test_aggregator_add_increments_summary() -> None:
    aggregator = ResultAggregator()
    aggregator.add("x", _result(ModuleStatus.SUCCESS, {"id": 1}, {"id": 2}))

    assert aggregator.summary["total_modules"] == 1
    assert aggregator.summary["success"] == 1
    assert aggregator.summary["total_findings"] == 2


def test_aggregator_summary_counts_all_statuses() -> None:
    aggregator = ResultAggregator()
    for name, status in (
        ("success", ModuleStatus.SUCCESS),
        ("partial", ModuleStatus.PARTIAL),
        ("failed", ModuleStatus.FAILED),
        ("skipped", ModuleStatus.SKIPPED),
    ):
        aggregator.add(name, _result(status))

    assert aggregator.summary == {
        "total_modules": 4,
        "success": 1,
        "partial": 1,
        "failed": 1,
        "skipped": 1,
        "total_findings": 0,
    }


def test_aggregator_all_findings_includes_module_name() -> None:
    aggregator = ResultAggregator()
    aggregator.add("mod_a", _result(ModuleStatus.SUCCESS, {"id": "a"}))
    aggregator.add("mod_b", _result(ModuleStatus.SUCCESS, {"id": "b"}))

    assert aggregator.all_findings == [
        {"module": "mod_a", "id": "a"},
        {"module": "mod_b", "id": "b"},
    ]


def test_aggregator_all_findings_preserves_finding_fields() -> None:
    aggregator = ResultAggregator()
    aggregator.add(
        "mod",
        _result(ModuleStatus.SUCCESS, {"platform": "x", "confidence": "high"}),
    )

    assert aggregator.all_findings == [
        {"module": "mod", "platform": "x", "confidence": "high"}
    ]


def test_aggregator_results_returns_copy() -> None:
    aggregator = ResultAggregator()
    aggregator.add("x", _result(ModuleStatus.SUCCESS))

    first = aggregator.results
    second = aggregator.results
    first.clear()

    assert first is not second
    assert set(aggregator.results) == {"x"}


def test_aggregator_overwrites_same_module_name() -> None:
    aggregator = ResultAggregator()
    aggregator.add("x", _result(ModuleStatus.FAILED, {"old": True}))
    aggregator.add("x", _result(ModuleStatus.SUCCESS, {"new": True}))

    assert aggregator.summary["total_modules"] == 1
    assert aggregator.summary["success"] == 1
    assert aggregator.summary["failed"] == 0
    assert aggregator.summary["total_findings"] == 1


def test_aggregator_handles_zero_findings() -> None:
    aggregator = ResultAggregator()
    aggregator.add("x", _result(ModuleStatus.SUCCESS))

    assert aggregator.summary["total_findings"] == 0


def test_aggregator_summary_aggregates_across_modules() -> None:
    aggregator = ResultAggregator()
    aggregator.add("a", _result(ModuleStatus.SUCCESS, *({"id": i} for i in range(3))))
    aggregator.add("b", _result(ModuleStatus.SUCCESS, *({"id": i} for i in range(2))))

    assert aggregator.summary["total_findings"] == 5
