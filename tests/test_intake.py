"""Tests for the interactive intake module."""

from __future__ import annotations

from unittest.mock import MagicMock

from cli.intake import ScanIntent, _fallback_parse, _show_intent_summary


class TestScanIntent:
    """Verify ScanIntent model defaults and structure."""

    def test_defaults(self):
        intent = ScanIntent()
        assert intent.target == ""
        assert intent.active_scan is True
        assert intent.guidance == ""

    def test_custom_values(self):
        intent = ScanIntent(target="example.com", active_scan=False, guidance="skip wpscan")
        assert intent.target == "example.com"
        assert intent.active_scan is False
        assert intent.guidance == "skip wpscan"


class TestFallbackParse:
    """Verify regex-based fallback extraction."""

    def test_extracts_domain(self):
        result = _fallback_parse("scan eversafe.info please")
        assert result.target == "eversafe.info"
        assert result.active_scan is True

    def test_extracts_ip(self):
        result = _fallback_parse("check 184.72.230.53")
        assert result.target == "184.72.230.53"

    def test_extracts_subdomain(self):
        result = _fallback_parse("quero analisar www.example.com")
        assert result.target == "www.example.com"

    def test_passive_keyword_portuguese(self):
        result = _fallback_parse("reconhecimento passivo no eversafe.info")
        assert result.target == "eversafe.info"
        assert result.active_scan is False

    def test_passive_keyword_english(self):
        result = _fallback_parse("passive scan on example.com")
        assert result.target == "example.com"
        assert result.active_scan is False

    def test_no_target_returns_empty(self):
        result = _fallback_parse("just do something")
        assert result.target == ""

    def test_active_by_default(self):
        result = _fallback_parse("scan example.com fully")
        assert result.active_scan is True


class TestShowIntentSummary:
    """Verify the summary panel renders without errors."""

    def test_renders_active_mode(self):
        console = MagicMock()
        intent = ScanIntent(target="example.com", active_scan=True, guidance="")
        _show_intent_summary(console, intent)
        assert console.print.called

    def test_renders_with_guidance(self):
        console = MagicMock()
        intent = ScanIntent(target="example.com", active_scan=False, guidance="focus on DNS")
        _show_intent_summary(console, intent)
        # Should have been called at least twice (empty line + panel)
        assert console.print.call_count >= 2


class TestInitialGuidanceInOrchestrator:
    """Verify initial_guidance pre-seeds phase_guidance in the orchestrator."""

    def test_initial_state_with_guidance(self):
        from fackel.agents.orchestrator.main import _initial_state

        state = _initial_state("example.com", True, initial_guidance="focus on subdomains")
        assert state["phase_guidance"] == {"osint": "focus on subdomains"}

    def test_initial_state_without_guidance(self):
        from fackel.agents.orchestrator.main import _initial_state

        state = _initial_state("example.com", True)
        assert state["phase_guidance"] == {}

    def test_initial_state_empty_guidance(self):
        from fackel.agents.orchestrator.main import _initial_state

        state = _initial_state("example.com", True, initial_guidance="")
        assert state["phase_guidance"] == {}
