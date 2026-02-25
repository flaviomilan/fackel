"""Tests for the phase evaluator module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from fackel.agents.orchestrator.evaluator import (
    PhaseEvaluation,
    _fallback_evaluation,
    evaluate_phase,
)


class TestFallbackEvaluation:
    """Verify fallback evaluation construction."""

    def test_returns_partial_completeness(self):
        result = _fallback_evaluation("port_scan", "LLM failed")
        assert result.phase == "port_scan"
        assert result.completeness == "partial"
        assert result.score == 0.5
        assert result.recommendation == "proceed"
        assert "LLM failed" in result.gaps[0]

    def test_reasoning_contains_reason(self):
        result = _fallback_evaluation("vuln_scan", "timeout")
        assert "timeout" in result.reasoning


class TestPhaseEvaluation:
    """Verify PhaseEvaluation model."""

    def test_valid_evaluation(self):
        ev = PhaseEvaluation(
            phase="port_scan",
            completeness="complete",
            score=0.9,
            key_findings=["Found 5 open ports"],
            gaps=[],
            recommendation="proceed",
            reasoning="Good coverage.",
        )
        assert ev.score == 0.9
        assert ev.recommendation == "proceed"

    def test_score_bounds(self):
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            PhaseEvaluation(
                phase="x",
                completeness="complete",
                score=1.5,
                recommendation="proceed",
                reasoning="x",
            )


class TestEvaluatePhase:
    """Verify evaluate_phase orchestration."""

    @patch("fackel.agents.orchestrator.evaluator.build_llm")
    def test_returns_fallback_on_llm_failure(self, mock_build_llm):
        mock_build_llm.side_effect = Exception("API key missing")
        result = evaluate_phase("port_scan", "summary text", ["1.2.3.4"])
        assert isinstance(result, PhaseEvaluation)
        assert result.completeness == "partial"
        assert result.recommendation == "proceed"

    @patch("fackel.agents.orchestrator.evaluator.build_llm")
    def test_successful_evaluation(self, mock_build_llm):
        expected = PhaseEvaluation(
            phase="port_scan",
            completeness="complete",
            score=0.8,
            key_findings=["SSH on 22"],
            gaps=[],
            recommendation="proceed",
            reasoning="Good scan.",
        )
        mock_llm = MagicMock()
        mock_structured = MagicMock()
        mock_structured.invoke.return_value = expected
        mock_llm.with_structured_output.return_value = mock_structured
        mock_build_llm.return_value = mock_llm

        result = evaluate_phase("port_scan", "Found ssh on port 22", ["1.2.3.4"])
        assert result.score == 0.8
        assert result.completeness == "complete"
