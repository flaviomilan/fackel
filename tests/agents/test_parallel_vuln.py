"""Tests for the parallel vuln-scan specialist fan-out (LangGraph ``Send``).

Vuln scanning is active, so the fan-out is gated behind ``FACKEL_VULN_SPECIALISTS``
and forced sequential under HITL approval; these tests cover the parallel path.
"""

from __future__ import annotations

import threading
import time

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from fackel.agents.orchestrator.nodes import vuln_scan as vuln_mod
from fackel.agents.orchestrator.state import ScanState
from fackel.agents.vuln_scan.specialists import VULN_SPECIALISTS


class TestDispatch:
    def test_emits_one_send_per_specialist(self) -> None:
        state = {"target": "example.com", "vuln_base_prompt": "ctx"}
        sends = vuln_mod.dispatch_vuln_specialists(state)
        assert len(sends) == len(VULN_SPECIALISTS)
        assert all(isinstance(s, Send) and s.node == "vuln_specialist" for s in sends)
        names = {s.arg["specialist"] for s in sends}
        assert names == {s.name for s in VULN_SPECIALISTS}
        assert all(s.arg["base_prompt"] == "ctx" for s in sends)
        assert all(s.arg["target"] == "example.com" for s in sends)


class TestSpecialistNode:
    def test_runs_one_specialist_and_returns_messages(self, monkeypatch) -> None:
        import fackel.agents.orchestrator.translators as translators_mod

        monkeypatch.setattr(
            "fackel.agents.vuln_scan.specialists.build_vuln_specialist",
            lambda spec, **kw: f"agent:{spec.name}",
        )
        monkeypatch.setattr(
            vuln_mod,
            "run_and_stream_agent",
            lambda agent, phase, task, config=None: [f"m:{agent}"],
        )
        persisted: list[int] = []
        monkeypatch.setattr(
            translators_mod, "persist_phase", lambda msgs, **kw: persisted.append(len(msgs))
        )

        out = vuln_mod.vuln_specialist_node(
            {"specialist": "tls", "target": "example.com", "base_prompt": "ctx"}, config={}
        )
        assert out == {"vuln_messages": ["m:agent:tls"]}
        assert persisted == [1]

    def test_skips_when_no_tools(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "fackel.agents.vuln_scan.specialists.build_vuln_specialist", lambda spec, **kw: None
        )
        out = vuln_mod.vuln_specialist_node(
            {"specialist": "tls", "target": "example.com", "base_prompt": ""}, config={}
        )
        assert out == {}


class TestParallelExecution:
    """The headline test: vuln specialists actually run concurrently on threads."""

    def test_specialists_run_in_parallel(self, monkeypatch) -> None:
        import fackel.agents.orchestrator.translators as translators_mod

        threads: list[int] = []

        def _fake_run(agent, phase, task, config=None):
            threads.append(threading.get_ident())
            time.sleep(0.3)  # simulate an I/O-bound scanning agent
            return [f"m:{agent}"]

        monkeypatch.setattr(
            "fackel.agents.vuln_scan.specialists.build_vuln_specialist",
            lambda spec, **kw: f"agent:{spec.name}",
        )
        monkeypatch.setattr(vuln_mod, "run_and_stream_agent", _fake_run)
        monkeypatch.setattr(translators_mod, "persist_phase", lambda *a, **k: None)

        g = StateGraph(ScanState)
        g.add_node("vuln_specialist", vuln_mod.vuln_specialist_node)
        g.add_conditional_edges(START, vuln_mod.dispatch_vuln_specialists, ["vuln_specialist"])
        g.add_edge("vuln_specialist", END)
        app = g.compile()

        t0 = time.perf_counter()
        result = app.invoke(
            {"target": "example.com", "vuln_base_prompt": "ctx", "vuln_messages": []}
        )
        elapsed = time.perf_counter() - t0

        n = len(VULN_SPECIALISTS)
        assert len(set(threads)) > 1, "specialists did not run on multiple threads"
        assert elapsed < 0.3 * n, f"ran sequentially ({elapsed:.2f}s for {n} x 0.3s)"
        assert len(result["vuln_messages"]) == n  # reducer fanned in every specialist


class TestDispatchNode:
    def test_builds_base_prompt_into_state(self, monkeypatch) -> None:
        monkeypatch.setattr(vuln_mod, "_build_vuln_scan_prompt", lambda *a, **k: "BASE")
        monkeypatch.setattr(vuln_mod, "prepare_scan_targets", lambda state: ([], []))
        out = vuln_mod.vuln_dispatch_node({"target": "example.com"}, config={})
        assert out == {"vuln_base_prompt": "BASE"}


class TestCollectNode:
    def test_builds_result_from_fanned_in_messages(self, monkeypatch) -> None:
        import fackel.agents.orchestrator.translators as translators_mod

        fake_eval = type(
            "E",
            (),
            {"model_dump": lambda self: {"phase": "vuln_scan"}},
        )()
        monkeypatch.setattr(vuln_mod.evaluator, "evaluate_phase", lambda *a, **k: fake_eval)
        monkeypatch.setattr(vuln_mod, "emit_evaluation", lambda *a, **k: None)
        monkeypatch.setattr(vuln_mod, "agent_summary", lambda msgs: "summary")
        monkeypatch.setattr(vuln_mod, "prepare_scan_targets", lambda state: ([], []))
        monkeypatch.setattr(translators_mod, "persist_phase", lambda *a, **k: None)

        result = vuln_mod.vuln_collect_node(
            {"target": "example.com", "vuln_messages": []}, config={}
        )
        assert "findings" in result
        assert result["phase_evaluations"] == [{"phase": "vuln_scan"}]
