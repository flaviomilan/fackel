"""Tests for the entity-driven pivot planner and the OSINT pivot loop."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fackel.agents.orchestrator import planner
from fackel.agents.orchestrator.nodes import osint as osint_node
from fackel.domain import (
    InformationCandidate,
    InformationType,
    ToolExecution,
    ToolExecutionStatus,
)
from fackel.persistence import bind_store_for_scan
from fackel.persistence.store import InformationStore


def _cand(info_type: InformationType, value: str) -> InformationCandidate:
    return InformationCandidate(
        type=info_type,
        normalized_value=value,
        original_value=value,
        source_execution_id="e",
        source_tool="hunter_email_search",
        phase="osint",
    )


def _exec(tool: str) -> ToolExecution:
    return ToolExecution(
        execution_id=tool,
        scan_id="s",
        phase="osint",
        tool_name=tool,
        status=ToolExecutionStatus.OK,
        started_at=datetime.now(UTC),
    )


class TestPlanOsintPivots:
    def test_emails_without_analysis_yield_directive(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        store.ingest([_cand(InformationType.EMAIL, "ann@example.com")], phase="osint")
        kinds = [d.kind for d in planner.plan_osint_pivots(store)]
        assert "analyze_emails" in kinds

    def test_org_without_repo_search_yields_directive(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        store.ingest([_cand(InformationType.ORGANIZATION, "Example Inc")], phase="osint")
        kinds = [d.kind for d in planner.plan_osint_pivots(store)]
        assert "expand_org" in kinds

    def test_directives_clear_once_tools_executed(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        store.ingest(
            [
                _cand(InformationType.EMAIL, "ann@example.com"),
                _cand(InformationType.ORGANIZATION, "Example Inc"),
            ],
            phase="osint",
        )
        assert planner.plan_osint_pivots(store)  # non-empty initially
        store.record_execution(_exec("analyze_email"))
        store.record_execution(_exec("github_repo_discovery"))
        assert planner.plan_osint_pivots(store) == []  # self-terminates

    def test_no_entities_no_directives(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        assert planner.plan_osint_pivots(store) == []

    def test_build_prompt_mentions_entities(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        store.ingest([_cand(InformationType.EMAIL, "ann@example.com")], phase="osint")
        prompt = planner.build_pivot_prompt("example.com", planner.plan_osint_pivots(store))
        assert "ann@example.com" in prompt
        assert "PIVOT" in prompt


class TestPivotLoop:
    def test_bounded_by_max_pivots(self, monkeypatch, tmp_path: Path) -> None:
        import fackel.agents.orchestrator.translators as translators_mod

        calls: list[int] = []
        monkeypatch.setattr(
            osint_node, "run_and_stream_agent", lambda *a, **k: calls.append(1) or []
        )
        # persist is a no-op → directives never clear → loop hits the budget.
        monkeypatch.setattr(translators_mod, "persist_phase", lambda *a, **k: None)

        with bind_store_for_scan("s", tmp_path) as store:
            store.ingest([_cand(InformationType.EMAIL, "a@example.com")], phase="osint")
            osint_node._run_pivot_loop(object(), "example.com", config={})

        assert len(calls) == 2  # FACKEL_MAX_PIVOTS default

    def test_terminates_when_entities_expanded(self, monkeypatch, tmp_path: Path) -> None:
        import fackel.agents.orchestrator.translators as translators_mod

        calls: list[int] = []
        monkeypatch.setattr(
            osint_node, "run_and_stream_agent", lambda *a, **k: calls.append(1) or []
        )

        with bind_store_for_scan("s", tmp_path) as store:
            store.ingest([_cand(InformationType.EMAIL, "a@example.com")], phase="osint")

            def _persist(_messages, *, phase, target):
                store.record_execution(_exec("analyze_email"))

            monkeypatch.setattr(translators_mod, "persist_phase", _persist)
            osint_node._run_pivot_loop(object(), "example.com", config={})

        assert len(calls) == 1  # one pivot, then the directive is satisfied

    def test_noop_without_store(self, monkeypatch) -> None:
        called = []
        monkeypatch.setattr(
            osint_node, "run_and_stream_agent", lambda *a, **k: called.append(1) or []
        )
        # No store bound → no pivots.
        assert osint_node._run_pivot_loop(object(), "example.com", config={}) == []
        assert called == []

    def test_disabled_when_max_pivots_zero(self, monkeypatch, tmp_path: Path) -> None:
        import fackel.settings as settings_mod

        monkeypatch.setenv("FACKEL_MAX_PIVOTS", "0")
        settings_mod.get_settings.cache_clear()
        called: list[int] = []
        monkeypatch.setattr(
            osint_node, "run_and_stream_agent", lambda *a, **k: called.append(1) or []
        )
        try:
            with bind_store_for_scan("s", tmp_path) as store:
                store.ingest([_cand(InformationType.EMAIL, "a@example.com")], phase="osint")
                assert osint_node._run_pivot_loop(object(), "example.com", config={}) == []
            assert called == []
        finally:
            settings_mod.get_settings.cache_clear()
