"""Tests for report_writer — build_full_report and helpers."""

import pytest

from fackel.report_writer import build_full_report, _extract_section, _format_evaluation


class TestExtractSection:
    """Markdown section extraction."""

    def test_extracts_matching_section(self) -> None:
        md = "# Intro\nParagraph.\n## Executive Summary\nThe summary.\n## Next\nMore."
        result = _extract_section(md, "Executive Summary")
        assert result == "The summary."

    def test_returns_none_on_missing(self) -> None:
        md = "# Intro\nParagraph."
        assert _extract_section(md, "Nonexistent Section") is None


class TestFormatEvaluation:
    """Phase evaluation formatting."""

    def test_handles_float_score(self) -> None:
        ev = {"completeness": "complete", "score": 0.9, "recommendation": "proceed"}
        result = _format_evaluation(ev)
        assert "0.9" in result

    def test_handles_non_float_score(self) -> None:
        """score that is a string should not crash."""
        ev = {"completeness": "partial", "score": "n/a", "recommendation": "retry"}
        # Should not raise
        result = _format_evaluation(ev)
        assert "partial" in result

    def test_handles_none_score(self) -> None:
        ev = {"completeness": "?", "score": None, "recommendation": "?"}
        result = _format_evaluation(ev)
        assert isinstance(result, str)


class TestBuildFullReport:
    """Full report generation from state."""

    def test_minimal_state(self) -> None:
        state = {
            "target": "example.com",
            "active_scan": False,
            "discovered_ips": [],
            "discovered_subdomains": [],
            "findings": [],
            "phase_evaluations": [],
            "unassessed_areas": [],
            "report": "",
        }
        result = build_full_report(state)
        assert "example.com" in result
        assert "# Penetration Test Report" in result

    def test_includes_ips(self) -> None:
        state = {
            "target": "example.com",
            "active_scan": True,
            "discovered_ips": ["1.2.3.4", "::1"],
            "discovered_subdomains": ["sub.example.com"],
            "findings": [],
            "phase_evaluations": [],
            "unassessed_areas": [],
            "report": "",
        }
        result = build_full_report(state)
        assert "1.2.3.4" in result
        assert "::1" in result
        assert "sub.example.com" in result
