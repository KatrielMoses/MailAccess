from __future__ import annotations

import inspect

from backend.core.phases import (
    PHASE_DAG,
    CredibilityPhase,
    InvestigationPhase,
    PhonePhase,
    PivotPhase,
    PrimaryPhase,
)


def test_dag_is_tuple_of_thirteen_phases() -> None:
    # Phase 6B.1 added DomainClusterPhase (→9); the breach-aggregator work added
    # BreachAggregatorPhase (→10); 0.18.6 added the final IpIntelPhase (→11); 0.18.8
    # added the final WhoisFreaksPhase (→12); UC7.3a added AlternateEmailAnchorPhase (→13).
    assert isinstance(PHASE_DAG, tuple)
    assert len(PHASE_DAG) == 13


def test_dag_phase_names_unique() -> None:
    names = [phase.name for phase in PHASE_DAG]
    assert len(names) == len(set(names))


def test_dag_starts_with_credibility() -> None:
    assert PHASE_DAG[0].name == "email_credibility"


def test_dag_ends_with_ip_intel_then_whoisfreaks_after_phone() -> None:
    names = [phase.name for phase in PHASE_DAG]
    assert names[-1] == "whoisfreaks_intel"
    assert names[-2] == "ip_intel"
    assert names[-3] == "phone_intel"


def test_dag_dependency_graph_is_acyclic() -> None:
    graph = {phase.name: phase.dependencies for phase in PHASE_DAG}

    def visit(name: str, path: frozenset[str]) -> None:
        assert name not in path
        for dependency in graph.get(name, ()):
            visit(dependency, path | {name})

    for phase_name in graph:
        visit(phase_name, frozenset())


def test_primary_phase_dependencies_include_credibility() -> None:
    assert "email_credibility" in PrimaryPhase.dependencies


def test_pivot_phase_depends_on_primary() -> None:
    assert "primary" in PivotPhase.dependencies


def test_phone_phase_depends_on_profile() -> None:
    assert "profile" in PhonePhase.dependencies


def test_each_phase_has_nonempty_unique_name() -> None:
    classes = InvestigationPhase.__subclasses__()
    names = [cls.name for cls in classes]
    assert all(isinstance(name, str) and name for name in names)
    assert len(names) == len(set(names))
    assert CredibilityPhase in classes


def test_phase_run_is_async() -> None:
    for phase in PHASE_DAG:
        assert inspect.iscoroutinefunction(phase.run)
