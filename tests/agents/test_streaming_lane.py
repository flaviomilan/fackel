"""Tests for per-agent lane tagging of streaming events."""

from __future__ import annotations

from fackel.agents.orchestrator import streaming


def _capture() -> tuple[list[tuple[str, str, dict]], None]:
    events: list[tuple[str, str, dict]] = []
    streaming.set_event_callback(lambda p, e, d: events.append((p, e, d)))
    return events, None


class TestLaneTagging:
    def teardown_method(self) -> None:
        streaming.set_event_callback(None)

    def test_event_inside_lane_carries_lane(self) -> None:
        events, _ = _capture()
        with streaming.lane("dns_infra"):
            streaming.emit("osint", "tool_call", {"tool": "dns_resolve"})
        assert events[0][2]["lane"] == "dns_infra"

    def test_event_outside_lane_has_no_lane(self) -> None:
        events, _ = _capture()
        streaming.emit("port_scan", "tool_call", {"tool": "nmap"})
        assert "lane" not in events[0][2]

    def test_lane_is_restored_after_block(self) -> None:
        events, _ = _capture()
        with streaming.lane("a"):
            streaming.emit("osint", "x", {})
        streaming.emit("osint", "y", {})
        assert events[0][2]["lane"] == "a"
        assert "lane" not in events[1][2]

    def test_nested_lanes_restore_outer(self) -> None:
        events, _ = _capture()
        with streaming.lane("outer"):
            with streaming.lane("inner"):
                streaming.emit("osint", "i", {})
            streaming.emit("osint", "o", {})
        assert events[0][2]["lane"] == "inner"
        assert events[1][2]["lane"] == "outer"

    def test_explicit_lane_in_data_is_not_overwritten(self) -> None:
        events, _ = _capture()
        with streaming.lane("ctx"):
            streaming.emit("osint", "x", {"lane": "explicit"})
        assert events[0][2]["lane"] == "explicit"
