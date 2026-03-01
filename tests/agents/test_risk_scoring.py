"""Tests for Phase 6 — Exposure Risk Scoring.

Covers the RiskScore model, triage_node risk extraction, and report agent
risk_score passthrough.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from fackel.agents.triage.agent import RiskScore, TriageResult, UnassessedArea, run_triage


class TestRiskScoreModel:
    """Pydantic validation for the RiskScore model."""

    def test_valid_critical_score(self) -> None:
        rs = RiskScore(score=9.5, exposure_type="critical", factors=["open admin (+1.0)"])
        assert rs.score == 9.5
        assert rs.exposure_type == "critical"
        assert len(rs.factors) == 1

    def test_valid_minimal_score(self) -> None:
        rs = RiskScore(score=0.0, exposure_type="minimal", factors=[])
        assert rs.score == 0.0
        assert rs.exposure_type == "minimal"

    def test_valid_moderate_score(self) -> None:
        rs = RiskScore(score=5.0, exposure_type="moderate", factors=["no WAF (+0.5)"])
        assert rs.score == 5.0

    def test_rejects_score_above_10(self) -> None:
        with pytest.raises(ValidationError):
            RiskScore(score=10.1, exposure_type="critical", factors=[])

    def test_rejects_score_below_0(self) -> None:
        with pytest.raises(ValidationError):
            RiskScore(score=-0.1, exposure_type="minimal", factors=[])

    def test_rejects_invalid_exposure_type(self) -> None:
        with pytest.raises(ValidationError):
            RiskScore(score=5.0, exposure_type="extreme", factors=[])

    def test_boundary_score_10(self) -> None:
        rs = RiskScore(score=10.0, exposure_type="critical", factors=[])
        assert rs.score == 10.0

    def test_boundary_score_0(self) -> None:
        rs = RiskScore(score=0.0, exposure_type="minimal", factors=[])
        assert rs.score == 0.0

    def test_factors_default_empty(self) -> None:
        rs = RiskScore(score=3.0, exposure_type="low")
        assert rs.factors == []


class TestTriageResultWithRisk:
    """TriageResult now requires a risk_score field."""

    def test_full_result(self) -> None:
        result = TriageResult(
            technologies_detected=["nginx", "React"],
            unassessed_areas=[],
            risk_score=RiskScore(
                score=3.5,
                exposure_type="low",
                factors=["No WAF detected (+0.5)", "CDN protecting primary (-1.0)"],
            ),
            summary="Good coverage.",
        )
        assert result.risk_score.score == 3.5
        assert result.risk_score.exposure_type == "low"
        assert len(result.risk_score.factors) == 2

    def test_missing_risk_score_raises(self) -> None:
        with pytest.raises(ValidationError):
            TriageResult(
                technologies_detected=["nginx"],
                unassessed_areas=[],
                summary="No risk score provided.",
            )

    def test_risk_score_with_unassessed(self) -> None:
        result = TriageResult(
            technologies_detected=["WordPress 6.4"],
            unassessed_areas=[
                UnassessedArea(
                    technology="WordPress 6.4",
                    detected_by="nuclei",
                    reason="Needs plugin audit",
                    recommendation="Run WPScan",
                ),
            ],
            risk_score=RiskScore(
                score=7.0,
                exposure_type="high",
                factors=["Critical vuln found (+2.0)"],
            ),
            summary="Significant gaps.",
        )
        assert len(result.unassessed_areas) == 1
        assert result.risk_score.score == 7.0


class TestRunTriageFallback:
    """run_triage returns a valid fallback with risk_score on LLM failure."""

    @patch("fackel.agents.triage.agent.build")
    def test_fallback_includes_risk_score(self, mock_build: MagicMock) -> None:
        mock_agent = MagicMock()
        mock_agent.invoke.side_effect = RuntimeError("LLM down")
        mock_build.return_value = mock_agent

        result = run_triage([{"phase": "osint", "title": "Test", "detail": "data"}])

        assert result.risk_score.score == 0.0
        assert result.risk_score.exposure_type == "minimal"
        assert len(result.risk_score.factors) == 1
        assert "failed" in result.risk_score.factors[0].lower()


class TestTriageNodeRiskExtraction:
    """triage_node extracts risk_score into state dict."""

    @patch("fackel.agents.orchestrator.streaming.emit")
    @patch("fackel.agents.triage.agent.run_triage")
    def test_triage_node_returns_risk_score(
        self, mock_run_triage: MagicMock, _mock_emit: MagicMock
    ) -> None:
        from fackel.agents.orchestrator.nodes import triage_node

        mock_result = TriageResult(
            technologies_detected=["nginx"],
            unassessed_areas=[],
            risk_score=RiskScore(
                score=6.5,
                exposure_type="high",
                factors=["Direct-host IP 1.2.3.4 (+2.0)", "No WAF (+0.5)"],
            ),
            summary="High exposure.",
        )
        mock_run_triage.return_value = mock_result

        state = {
            "target": "example.com",
            "active_scan": True,
            "findings": [{"phase": "osint", "title": "DNS", "detail": "data"}],
        }

        result = triage_node(state, {})

        assert "risk_score" in result
        risk = result["risk_score"]
        assert risk["score"] == 6.5
        assert risk["exposure_type"] == "high"
        assert len(risk["factors"]) == 2

    @patch("fackel.agents.orchestrator.streaming.emit")
    @patch("fackel.agents.triage.agent.run_triage")
    def test_triage_node_emits_risk_events(
        self, mock_run_triage: MagicMock, mock_emit: MagicMock
    ) -> None:
        from fackel.agents.orchestrator.nodes import triage_node

        mock_result = TriageResult(
            technologies_detected=[],
            unassessed_areas=[],
            risk_score=RiskScore(score=2.0, exposure_type="minimal", factors=[]),
            summary="Minimal exposure.",
        )
        mock_run_triage.return_value = mock_result

        state = {"target": "example.com", "active_scan": False, "findings": []}
        triage_node(state, {})

        done_calls = [c for c in mock_emit.call_args_list if c.args[1] == "done"]
        assert len(done_calls) >= 1
        done_data = done_calls[-1].args[2]
        assert done_data["risk_score"] == 2.0
        assert done_data["risk_exposure_type"] == "minimal"

    @patch("fackel.agents.orchestrator.streaming.emit")
    @patch("fackel.agents.triage.agent.run_triage")
    def test_triage_detail_includes_risk(
        self, mock_run_triage: MagicMock, _mock_emit: MagicMock
    ) -> None:
        from fackel.agents.orchestrator.nodes import triage_node

        mock_result = TriageResult(
            technologies_detected=["Apache"],
            unassessed_areas=[],
            risk_score=RiskScore(
                score=4.5,
                exposure_type="moderate",
                factors=["Subdomain outside CDN (+1.5)"],
            ),
            summary="Moderate risk.",
        )
        mock_run_triage.return_value = mock_result

        state = {"target": "example.com", "active_scan": True, "findings": []}
        result = triage_node(state, {})

        finding = result["findings"][0]
        assert "4.5/10" in finding["detail"]
        assert "moderate" in finding["detail"]
        assert "Subdomain outside CDN" in finding["detail"]


class TestReportRiskScorePassthrough:
    """generate_report correctly injects risk_score into LLM context."""

    @patch("fackel.agents.report.agent.build_llm")
    def test_risk_score_in_llm_prompt(self, mock_build_llm: MagicMock) -> None:
        from fackel.agents.report.agent import generate_report

        mock_response = MagicMock()
        mock_response.content = "# Report\nWith risk score."
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = mock_response
        mock_build_llm.return_value = mock_llm

        risk = {"score": 7.2, "exposure_type": "high", "factors": ["Direct IP (+2.0)"]}

        result = generate_report(
            target="example.com",
            active_scan=True,
            findings=[],
            risk_score=risk,
        )

        call_args = mock_llm.invoke.call_args[0][0]
        human_msg = call_args[1].content
        assert "7.2/10" in human_msg
        assert "high" in human_msg
        assert "Direct IP (+2.0)" in human_msg
        assert result == "# Report\nWith risk score."

    @patch("fackel.agents.report.agent.build_llm")
    def test_no_risk_score_omits_section(self, mock_build_llm: MagicMock) -> None:
        from fackel.agents.report.agent import generate_report

        mock_response = MagicMock()
        mock_response.content = "# Report"
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = mock_response
        mock_build_llm.return_value = mock_llm

        generate_report(
            target="example.com",
            active_scan=False,
            findings=[],
            risk_score=None,
        )

        call_args = mock_llm.invoke.call_args[0][0]
        human_msg = call_args[1].content
        assert "Exposure Risk Score" not in human_msg

    @patch("fackel.agents.report.agent.build_llm")
    def test_empty_factors_still_shows_score(self, mock_build_llm: MagicMock) -> None:
        from fackel.agents.report.agent import generate_report

        mock_response = MagicMock()
        mock_response.content = "# Report"
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = mock_response
        mock_build_llm.return_value = mock_llm

        risk = {"score": 1.0, "exposure_type": "minimal", "factors": []}

        generate_report(
            target="example.com",
            active_scan=False,
            findings=[],
            risk_score=risk,
        )

        call_args = mock_llm.invoke.call_args[0][0]
        human_msg = call_args[1].content
        assert "1.0/10" in human_msg
        assert "Risk Factors" not in human_msg
