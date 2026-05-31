"""Tests for the live context/token tracker."""

from __future__ import annotations

from cli.context_tracker import ContextTracker, _human


class TestContextTracker:
    def test_counts_only_content_events(self) -> None:
        t = ContextTracker()
        t.add_event("osint", "token", {"content": "hello world " * 50})
        t.add_event("osint", "tool_call", {"tool": "x"})  # no content → ignored
        t.add_event("osint", "lane_start", {"name": "a"})  # ignored
        assert t.total > 0
        assert t.per_phase["osint"] == t.total

    def test_per_phase_and_per_lane_breakdown(self) -> None:
        t = ContextTracker()
        t.add_event("osint", "token", {"content": "a " * 100, "lane": "dns"})
        t.add_event("vuln_scan", "summary", {"content": "b " * 100, "lane": "tls"})
        assert set(t.per_phase) == {"osint", "vuln_scan"}
        assert set(t.per_lane) == {"dns", "tls"}
        assert t.total == sum(t.per_phase.values())

    def test_empty_content_ignored(self) -> None:
        t = ContextTracker()
        t.add_event("osint", "token", {"content": ""})
        t.add_event("osint", "summary", {})
        assert t.total == 0

    def test_meter_renders_bar_and_caps_at_window(self) -> None:
        t = ContextTracker()
        t.total = t.window * 2  # exceed the window
        meter = t.render_meter()
        assert "▓" * 10 in meter  # bar fully filled, capped
        assert "ctx" in meter

    def test_meter_color_thresholds(self) -> None:
        t = ContextTracker()
        t.total = int(t.window * 0.1)
        assert "green" in t.render_meter()
        t.total = int(t.window * 0.7)
        assert "yellow" in t.render_meter()
        t.total = int(t.window * 0.95)
        assert "red" in t.render_meter()

    def test_reset(self) -> None:
        t = ContextTracker()
        t.add_event("osint", "token", {"content": "x " * 100})
        t.reset()
        assert t.total == 0 and not t.per_phase and not t.per_lane


def test_human_format() -> None:
    assert _human(500) == "500"
    assert _human(12_300) == "12.3k"
