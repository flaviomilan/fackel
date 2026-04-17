"""Concurrency / cancellation stress tests for the interactive harness.

Covers the operational risk flagged in the architecture review: cooperative
cancel during a parallel fan-out, and ContextVar isolation between scans.
"""

from __future__ import annotations

import io
import threading

import pytest
from langgraph.graph import END, START, StateGraph
from rich.console import Console

from cli.harness import Harness
from fackel.agents.orchestrator import streaming as st
from fackel.agents.orchestrator.nodes import osint as osint_mod
from fackel.agents.orchestrator.state import ScanState
from fackel.agents.osint.specialists import SPECIALISTS


def _harness() -> Harness:
    return Harness(Console(file=io.StringIO(), force_terminal=False, width=100), verbose=False)


def _out(h: Harness) -> str:
    return h._console.file.getvalue()  # type: ignore[attr-defined]


class TestEmitCancel:
    def teardown_method(self) -> None:
        st.set_event_callback(None)

    def test_emit_raises_when_cancel_set(self) -> None:
        cancel = threading.Event()
        cancel.set()
        token = st.current_cancel.set(cancel)
        try:
            with pytest.raises(st.StreamCancelledError):
                st.emit("osint", "tool_call", {"tool": "x"})
        finally:
            st.current_cancel.reset(token)

    def test_emit_normal_when_not_cancelled(self) -> None:
        seen: list[tuple] = []
        st.set_event_callback(lambda p, e, d: seen.append((p, e, d)))
        st.emit("osint", "x", {})
        assert len(seen) == 1


class TestParallelCancelUnwinds:
    """The genuine stress test: cancel propagates through a Send fan-out.

    Cancel is bound before invoke; LangGraph copies the context into each
    specialist worker thread, so the first emit in any lane raises and unwinds
    the whole parallel super-step."""

    def test_cancel_propagates_into_parallel_specialists(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "fackel.agents.osint.specialists.build_specialist",
            lambda spec, **kw: f"agent:{spec.name}",
        )
        # run_and_stream should never be reached — lane_start emit raises first.
        monkeypatch.setattr(
            osint_mod,
            "run_and_stream_agent",
            lambda *a, **k: pytest.fail("specialist body ran despite cancel"),
        )

        g = StateGraph(ScanState)
        g.add_node("osint_specialist", osint_mod.osint_specialist_node)
        g.add_conditional_edges(START, osint_mod.dispatch_osint_specialists, ["osint_specialist"])
        g.add_edge("osint_specialist", END)
        app = g.compile()

        cancel = threading.Event()
        cancel.set()
        token = st.current_cancel.set(cancel)
        try:
            with pytest.raises(st.StreamCancelledError):
                app.invoke({"target": "example.com", "osint_messages": []})
        finally:
            st.current_cancel.reset(token)
        assert len(SPECIALISTS) >= 2  # this really was a fan-out


class TestHarnessCancelPath:
    def test_worker_self_cancel_reports_cancelled(self, monkeypatch) -> None:
        import fackel.agents.orchestrator as orch

        def fake_run(target, *, active_scan, approval_callback, install_signal_handlers):
            st.emit("osint", "lane_start", {"name": "dns", "lane": "dns"})
            # Trip the cooperative cancel the harness bound into this context.
            ev = st.current_cancel.get()
            assert ev is not None
            ev.set()
            st.emit("osint", "token", {"content": "x", "lane": "dns"})  # raises
            return {"scan_id": "never", "report": "x", "active_scan": active_scan}

        monkeypatch.setattr(orch, "run", fake_run)
        h = _harness()
        h._run_scan("example.com", active_scan=False, approve_tools=False)

        assert "cancelled" in _out(h)
        assert h._session.last is None  # cancelled scan is not remembered


class TestContextVarIsolation:
    def test_no_contextvar_leak_between_scans(self, monkeypatch) -> None:
        import fackel.agents.orchestrator as orch

        def fake_run(target, *, active_scan, approval_callback, install_signal_handlers):
            st.emit("osint", "lane_start", {"name": "dns", "lane": "dns"})
            st.emit("osint", "lane_end", {"name": "dns", "lane": "dns"})
            return {"scan_id": f"id-{target}", "report": "# R", "active_scan": active_scan}

        monkeypatch.setattr(orch, "run", fake_run)
        h = _harness()
        monkeypatch.setattr("cli.presenter.present_report", lambda *a, **k: None)

        h._run_scan("a.com", active_scan=False, approve_tools=False)
        h._run_scan("b.com", active_scan=False, approve_tools=False)

        # Main-thread context is clean after scans (worker bound them in a copy).
        assert st.current_cancel.get() is None
        assert st.current_lane.get() is None
        assert st.current_scan_id.get() is None
        assert st.is_tool_approval_enabled() is False
        # Both scans tracked independently.
        assert [s.scan_id for s in h._session.scans] == ["id-a.com", "id-b.com"]
