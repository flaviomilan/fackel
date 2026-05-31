"""Tests for the multi-lane EventRenderer (no cross-talk between parallel agents)."""

from __future__ import annotations

import io

from rich.console import Console

from cli.renderer import EventRenderer


def _renderer() -> tuple[EventRenderer, Console]:
    # Non-terminal console: Live is inert, console.print output lands in the buffer.
    console = Console(file=io.StringIO(), force_terminal=False, width=100)
    return EventRenderer(console, verbose=False), console


def _output(console: Console) -> str:
    return console.file.getvalue()  # type: ignore[attr-defined]


class TestLaneSeparation:
    def test_concurrent_lanes_do_not_share_buffers(self) -> None:
        r, _ = _renderer()
        r.handle("osint", "lane_start", {"lane": "dns_infra", "name": "dns_infra"})
        r.handle("osint", "lane_start", {"lane": "scan_dbs", "name": "scan_dbs"})

        # Interleave: a runs a tool, b thinks.
        r.handle("osint", "tool_call", {"lane": "dns_infra", "tool": "dns_resolve", "args": {}})
        r.handle("osint", "token", {"lane": "scan_dbs", "content": "pivoting on shodan org"})

        dns = r._lanes["dns_infra"]
        dbs = r._lanes["scan_dbs"]
        # dns_infra has the tool, no thinking; scan_dbs has thinking, no tool.
        assert [t["name"] for t in dns.tool_batch] == ["dns_resolve"]
        assert dns.thinking == ""
        assert dbs.tool_batch == []
        assert dbs.thinking == "pivoting on shodan org"

    def test_lane_end_persists_summary_and_drops_lane(self) -> None:
        r, console = _renderer()
        r.handle("osint", "lane_start", {"lane": "people", "name": "people"})
        r.handle(
            "osint", "tool_call", {"lane": "people", "tool": "hunter_email_search", "args": {}}
        )
        r.handle("osint", "tool_result", {"lane": "people", "tool": "hunter_email_search"})
        r.handle("osint", "lane_end", {"lane": "people", "name": "people"})

        assert "people" not in r._lanes  # dropped after finalizing
        assert "people" in _output(console)  # one-line summary persisted

    def test_error_lane_marked_and_persisted_as_failed(self) -> None:
        r, _ = _renderer()
        r.handle("vuln_scan", "lane_start", {"lane": "tls", "name": "tls"})
        r.handle("vuln_scan", "tool_call", {"lane": "tls", "tool": "testssl_scan", "args": {}})
        r.handle(
            "vuln_scan", "tool_error", {"lane": "tls", "tool": "testssl_scan", "error": "boom"}
        )
        # status flips to error before lane_end consumes it
        assert r._lanes["tls"].status == "error"
        r.handle("vuln_scan", "lane_end", {"lane": "tls", "name": "tls"})
        assert "tls" not in r._lanes


class TestPhaseFraming:
    def test_phase_header_printed_once_per_phase(self) -> None:
        r, console = _renderer()
        # Two parallel specialists in the same phase → single OSINT header.
        r.handle("osint", "lane_start", {"lane": "a", "name": "a"})
        r.handle("osint", "lane_start", {"lane": "b", "name": "b"})
        out = _output(console)
        # The phase header is the Rule line (contains the box-drawing rule char);
        # the pipeline stepper also names "OSINT" but carries no rule char.
        header_lines = [ln for ln in out.splitlines() if "OSINT" in ln and "─" in ln]
        assert len(header_lines) == 1

    def test_new_phase_resets_lanes(self) -> None:
        r, _ = _renderer()
        r.handle("osint", "lane_start", {"lane": "a", "name": "a"})
        r.handle("osint", "done", {})
        r.handle("port_scan", "tool_call", {"tool": "nmap", "args": {}})
        # main lane only, no stale "a" lane from the previous phase
        assert "a" not in r._lanes
        assert "main" in r._lanes

    def test_done_emits_complete_line(self) -> None:
        r, console = _renderer()
        r.handle("triage", "start", {})
        r.handle("triage", "done", {})
        assert "complete" in _output(console)


class TestMainLane:
    def test_sequential_phase_uses_main_lane(self) -> None:
        r, _ = _renderer()
        r.handle("report", "start", {})
        r.handle("report", "token", {"content": "writing the report"})
        assert r._lanes["main"].thinking == "writing the report"
        assert r._named_lanes() == []
