"""Tests for the interactive harness — dispatch + producer/consumer scan loop."""

from __future__ import annotations

import io

from rich.console import Console

from cli.harness import Harness


def _harness() -> Harness:
    return Harness(Console(file=io.StringIO(), force_terminal=False, width=100), verbose=False)


def _out(h: Harness) -> str:
    return h._console.file.getvalue()  # type: ignore[attr-defined]


class TestDispatch:
    def test_offline_commands_keep_loop_alive(self) -> None:
        h = _harness()
        for line in ["/help", "/agents", "/context", "/bogus", "/ask nothing", "/scan"]:
            assert h._dispatch(line) is True, line
        out = _out(h)
        assert "Specialist agents" in out  # /agents
        assert "unknown command" in out  # /bogus
        assert "no scan yet" in out  # /ask with no scan

    def test_quit_exits(self) -> None:
        h = _harness()
        assert h._dispatch("/quit") is False
        assert h._dispatch("/exit") is False

    def test_bare_text_routes_to_ask(self) -> None:
        h = _harness()
        h._dispatch("what resolves to cloudflare")
        assert "no scan yet" in _out(h)  # routed to /ask


class TestScanLoop:
    def test_done_path_drains_events_and_remembers(self, monkeypatch) -> None:
        import fackel.agents.orchestrator as orch
        from fackel.agents.orchestrator import streaming as st

        def fake_run(target, *, active_scan, approval_callback, install_signal_handlers):
            # Runs in the worker's copied context → emit sees the callback.
            st.emit("osint", "lane_start", {"name": "dns", "lane": "dns"})
            st.emit("osint", "token", {"content": "resolving hosts", "lane": "dns"})
            st.emit("osint", "lane_end", {"name": "dns", "lane": "dns"})
            return {"scan_id": "abc123", "report": "# R", "active_scan": active_scan}

        monkeypatch.setattr(orch, "run", fake_run)
        h = _harness()
        monkeypatch.setattr("cli.presenter.present_report", lambda *a, **k: None)  # skip file IO

        h._run_scan("example.com", active_scan=False, approve_tools=False)

        assert h._session.last is not None
        assert h._session.last.scan_id == "abc123"
        assert h._tracker.total > 0  # token content was counted

    def test_approval_handshake_across_threads(self, monkeypatch) -> None:
        import fackel.agents.orchestrator as orch
        from fackel.agents.orchestrator import streaming as st

        captured: dict[str, object] = {}

        def fake_run(target, *, active_scan, approval_callback, install_signal_handlers):
            captured["approved"] = approval_callback({"question": "proceed?"})
            st.emit("port_scan", "done", {})
            return {"scan_id": "s1", "report": "# R", "active_scan": active_scan}

        monkeypatch.setattr(orch, "run", fake_run)
        h = _harness()
        monkeypatch.setattr("cli.presenter.present_report", lambda *a, **k: None)

        # Auto-approve on the main thread (replaces the interactive prompt).
        def _auto(box):
            box.result = True
            box.event.set()

        monkeypatch.setattr(h, "_handle_approval", _auto)

        h._run_scan("example.com", active_scan=True, approve_tools=False)

        assert captured["approved"] is True  # worker received the main-thread answer

    def test_error_path_surfaces_and_survives(self, monkeypatch) -> None:
        import fackel.agents.orchestrator as orch

        def fake_run(target, **kwargs):
            raise RuntimeError("boom in scan")

        monkeypatch.setattr(orch, "run", fake_run)
        h = _harness()
        h._run_scan("example.com", active_scan=False, approve_tools=False)
        assert "boom in scan" in _out(h)
        # REPL still usable after a failed scan
        assert h._dispatch("/help") is True
