"""Tests for per-phase operator guidance: gates, helpers, and interrupt dispatch."""

from __future__ import annotations

from unittest.mock import patch

from fackel.agents.orchestrator.main import _resolve_interrupt
from fackel.agents.orchestrator.nodes._helpers import append_guidance, get_phase_guidance
from fackel.agents.orchestrator.streaming import (
    is_guidance_enabled,
    set_guidance_enabled,
)

# ---------------------------------------------------------------------------
# streaming: guidance flag
# ---------------------------------------------------------------------------


class TestGuidanceFlag:
    """Verify the module-level guidance enabled/disabled flag."""

    def test_disabled_by_default(self):
        set_guidance_enabled(False)
        assert is_guidance_enabled() is False

    def test_enable_and_disable(self):
        set_guidance_enabled(True)
        assert is_guidance_enabled() is True
        set_guidance_enabled(False)
        assert is_guidance_enabled() is False


# ---------------------------------------------------------------------------
# _helpers: get_phase_guidance / append_guidance
# ---------------------------------------------------------------------------


class TestGetPhaseGuidance:
    """Verify guidance retrieval from state."""

    def test_returns_guidance_when_present(self):
        state = {"phase_guidance": {"osint": "focus on subdomains"}, "target": "x"}
        assert get_phase_guidance(state, "osint") == "focus on subdomains"

    def test_returns_empty_when_missing_phase(self):
        state = {"phase_guidance": {"osint": "focus"}, "target": "x"}
        assert get_phase_guidance(state, "port_scan") == ""

    def test_returns_empty_when_no_guidance_dict(self):
        state = {"target": "x"}
        assert get_phase_guidance(state, "osint") == ""

    def test_returns_empty_when_guidance_is_none(self):
        state = {"phase_guidance": None, "target": "x"}
        assert get_phase_guidance(state, "osint") == ""


class TestAppendGuidance:
    """Verify guidance injection into prompt parts."""

    def test_appends_when_non_empty(self):
        parts: list[str] = ["existing prompt"]
        append_guidance(parts, "scan port 443")
        assert len(parts) == 2
        assert "Operator Guidance" in parts[1]
        assert "scan port 443" in parts[1]

    def test_skips_when_empty(self):
        parts: list[str] = ["existing prompt"]
        append_guidance(parts, "")
        assert len(parts) == 1

    def test_skips_when_whitespace_only(self):
        parts: list[str] = ["prompt"]
        append_guidance(parts, "")
        assert len(parts) == 1


# ---------------------------------------------------------------------------
# _guidance gates (node functions)
# ---------------------------------------------------------------------------


class TestGuidanceGates:
    """Verify guidance gate nodes respect the enabled flag."""

    def test_returns_empty_when_disabled(self):
        from fackel.agents.orchestrator.nodes._guidance import osint_guidance

        set_guidance_enabled(False)
        state = {"phase_guidance": {}, "target": "x"}
        result = osint_guidance(state)
        assert result == {}

    def test_port_scan_returns_empty_when_disabled(self):
        from fackel.agents.orchestrator.nodes._guidance import port_scan_guidance

        set_guidance_enabled(False)
        state = {"phase_guidance": {}, "target": "x"}
        result = port_scan_guidance(state)
        assert result == {}

    def test_vuln_scan_returns_empty_when_disabled(self):
        from fackel.agents.orchestrator.nodes._guidance import vuln_scan_guidance

        set_guidance_enabled(False)
        state = {"phase_guidance": {}, "target": "x"}
        result = vuln_scan_guidance(state)
        assert result == {}

    def test_interrupt_called_when_enabled(self):
        from fackel.agents.orchestrator.nodes._guidance import osint_guidance

        set_guidance_enabled(True)
        state = {"phase_guidance": {}, "target": "x"}
        with patch(
            "fackel.agents.orchestrator.nodes._guidance.interrupt",
            return_value="focus on DNS",
        ):
            result = osint_guidance(state)
        set_guidance_enabled(False)

        assert result == {"phase_guidance": {"osint": "focus on DNS"}}

    def test_empty_guidance_not_stored(self):
        from fackel.agents.orchestrator.nodes._guidance import port_scan_guidance

        set_guidance_enabled(True)
        state = {"phase_guidance": {}, "target": "x"}
        with patch(
            "fackel.agents.orchestrator.nodes._guidance.interrupt",
            return_value="",
        ):
            result = port_scan_guidance(state)
        set_guidance_enabled(False)

        assert result == {"phase_guidance": {}}

    def test_preserves_existing_guidance(self):
        from fackel.agents.orchestrator.nodes._guidance import vuln_scan_guidance

        set_guidance_enabled(True)
        state = {"phase_guidance": {"osint": "focus on DNS"}, "target": "x"}
        with patch(
            "fackel.agents.orchestrator.nodes._guidance.interrupt",
            return_value="skip wpscan",
        ):
            result = vuln_scan_guidance(state)
        set_guidance_enabled(False)

        assert result == {"phase_guidance": {"osint": "focus on DNS", "vuln_scan": "skip wpscan"}}


# ---------------------------------------------------------------------------
# _resolve_interrupt dispatch
# ---------------------------------------------------------------------------


class TestResolveInterrupt:
    """Verify interrupt routing logic in the orchestrator."""

    def test_guidance_interrupt_calls_guidance_callback(self):
        data = {"type": "guidance", "phase": "osint", "description": "..."}
        result = _resolve_interrupt(
            data,
            approval_callback=None,
            guidance_callback=lambda d: "my guidance",
        )
        assert result == "my guidance"

    def test_guidance_interrupt_returns_empty_without_callback(self):
        data = {"type": "guidance", "phase": "osint"}
        result = _resolve_interrupt(
            data,
            approval_callback=None,
            guidance_callback=None,
        )
        assert result == ""

    def test_approval_interrupt_calls_approval_callback(self):
        data = {"type": "approval", "question": "proceed?"}
        result = _resolve_interrupt(
            data,
            approval_callback=lambda d: True,
            guidance_callback=None,
        )
        assert result is True

    def test_approval_interrupt_auto_approves_without_callback(self):
        data = {"type": "approval", "question": "proceed?"}
        result = _resolve_interrupt(
            data,
            approval_callback=None,
            guidance_callback=None,
        )
        assert result is True

    def test_unknown_type_treated_as_approval(self):
        data = {"something": "else"}
        result = _resolve_interrupt(
            data,
            approval_callback=lambda d: False,
            guidance_callback=None,
        )
        assert result is False

    def test_non_dict_interrupt_treated_as_approval(self):
        result = _resolve_interrupt(
            "legacy_string",
            approval_callback=lambda d: True,
            guidance_callback=None,
        )
        assert result is True
