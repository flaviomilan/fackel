"""Tests for the idiomatic parallel OSINT fan-out (LangGraph ``Send``)."""

from __future__ import annotations

import threading
import time

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from fackel.agents.orchestrator.nodes import osint as osint_mod
from fackel.agents.orchestrator.state import ScanState
from fackel.agents.osint.specialists import SPECIALISTS


class TestDispatch:
    def test_emits_one_send_per_specialist(self) -> None:
        sends = osint_mod.dispatch_osint_specialists({"target": "example.com"})
        assert len(sends) == len(SPECIALISTS)
        assert all(isinstance(s, Send) and s.node == "osint_specialist" for s in sends)
        names = {s.arg["specialist"] for s in sends}
        assert names == {s.name for s in SPECIALISTS}
        assert all(s.arg["target"] == "example.com" for s in sends)


class TestSpecialistNode:
    def test_runs_one_specialist_and_returns_messages(self, monkeypatch) -> None:
        import fackel.agents.orchestrator.translators as translators_mod

        monkeypatch.setattr(
            "fackel.agents.osint.specialists.build_specialist",
            lambda spec, **kw: f"agent:{spec.name}",
        )
        monkeypatch.setattr(
            osint_mod,
            "run_and_stream_agent",
            lambda agent, phase, task, config=None: [f"m:{agent}"],
        )
        persisted: list[int] = []
        monkeypatch.setattr(
            translators_mod, "persist_phase", lambda msgs, **kw: persisted.append(len(msgs))
        )

        out = osint_mod.osint_specialist_node(
            {"specialist": "dns_infra", "target": "example.com"}, config={}
        )
        assert out == {"osint_messages": ["m:agent:dns_infra"]}
        assert persisted == [1]

    def test_skips_when_no_tools(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "fackel.agents.osint.specialists.build_specialist", lambda spec, **kw: None
        )
        out = osint_mod.osint_specialist_node(
            {"specialist": "dns_infra", "target": "example.com"}, config={}
        )
        assert out == {}


class TestParallelExecution:
    """The headline test: specialists actually run concurrently on threads."""

    def test_specialists_run_in_parallel(self, monkeypatch) -> None:
        import fackel.agents.orchestrator.translators as translators_mod

        threads: list[int] = []

        def _fake_run(agent, phase, task, config=None):
            threads.append(threading.get_ident())
            time.sleep(0.3)  # simulate an I/O-bound LLM agent
            return [f"m:{agent}"]

        monkeypatch.setattr(
            "fackel.agents.osint.specialists.build_specialist",
            lambda spec, **kw: f"agent:{spec.name}",
        )
        monkeypatch.setattr(osint_mod, "run_and_stream_agent", _fake_run)
        monkeypatch.setattr(translators_mod, "persist_phase", lambda *a, **k: None)

        # Minimal graph: START -> dispatch (one Send per specialist) -> specialist -> END
        g = StateGraph(ScanState)
        g.add_node("osint_specialist", osint_mod.osint_specialist_node)
        g.add_conditional_edges(START, osint_mod.dispatch_osint_specialists, ["osint_specialist"])
        g.add_edge("osint_specialist", END)
        app = g.compile()

        t0 = time.perf_counter()
        result = app.invoke({"target": "example.com", "osint_messages": []})
        elapsed = time.perf_counter() - t0

        n = len(SPECIALISTS)
        assert len(set(threads)) > 1, "specialists did not run on multiple threads"
        assert elapsed < 0.3 * n, f"ran sequentially ({elapsed:.2f}s for {n} x 0.3s)"
        assert len(result["osint_messages"]) == n  # reducer fanned in every specialist


class TestCollectNode:
    def test_builds_result_from_fanned_in_messages(self, monkeypatch) -> None:
        fake_eval = type(
            "E",
            (),
            {"recommendation": "proceed", "model_dump": lambda self: {"phase": "osint"}},
        )()
        monkeypatch.setattr(osint_mod.evaluator, "evaluate_phase", lambda *a, **k: fake_eval)
        monkeypatch.setattr(osint_mod, "emit_evaluation", lambda *a, **k: None)
        monkeypatch.setattr(osint_mod, "_run_pivot_loop", lambda *a, **k: [])
        monkeypatch.setattr("fackel.agents.osint.agent.build", lambda *a, **k: object())

        result = osint_mod.osint_collect_node(
            {"target": "example.com", "osint_messages": []}, config={}
        )
        assert "findings" in result
        assert result["phase_evaluations"] == [{"phase": "osint"}]


class TestEmitThreadSafety:
    def test_concurrent_emit_delivers_all(self) -> None:
        import contextvars

        from fackel.agents.orchestrator import streaming

        received: list[tuple[str, str]] = []
        lock = threading.Lock()

        def _cb(phase, etype, data):
            with lock:
                received.append((phase, etype))

        streaming.set_event_callback(_cb)
        try:
            # LangGraph copies the parent context into each worker thread; mirror
            # that so the callback ContextVar is visible (one copy per thread, as a
            # Context can't be entered concurrently).
            ctxs = [contextvars.copy_context() for _ in range(20)]
            threads = [
                threading.Thread(
                    target=lambda i=i: ctxs[i].run(streaming.emit, "osint", f"e{i}", {})
                )
                for i in range(20)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert len(received) == 20  # all delivered under concurrent emit
        finally:
            streaming.set_event_callback(None)
