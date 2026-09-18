"""Tests for AI pipeline integrity — LAAJ after OSINT, self-reflection retry,
and structured context passthrough to triage.

Validates that every phase of the pipeline uses AI evaluation appropriately
and that structured state data reaches downstream consumers.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from fackel.agents.triage.agent import (
    RiskScore,
    TriageResult,
    _serialize_structured_context,
    run_triage,
)


class TestSerializeStructuredContext:
    """_serialize_structured_context produces Markdown from state data."""

    def test_ip_classifications_rendered(self) -> None:
        result = _serialize_structured_context(
            ip_classifications=[
                {"ip": "1.2.3.4", "ip_class": "cdn", "org": "Cloudflare", "anycast": True},
                {"ip": "5.6.7.8", "ip_class": "direct_host", "org": "OVH", "anycast": False},
            ],
            tech_fingerprints=[],
            phase_evaluations=[],
        )
        assert "1.2.3.4" in result
        assert "cdn" in result
        assert "anycast=yes" in result
        assert "5.6.7.8" in result
        assert "direct_host" in result

    def test_tech_fingerprints_rendered(self) -> None:
        result = _serialize_structured_context(
            ip_classifications=[],
            tech_fingerprints=[
                {
                    "host": "example.com",
                    "server": "nginx/1.25",
                    "technologies": ["React", "Webpack"],
                    "cdn": True,
                    "waf": "Cloudflare",
                },
            ],
            phase_evaluations=[],
        )
        assert "example.com" in result
        assert "nginx/1.25" in result
        assert "React" in result
        assert "CDN=yes" in result
        assert "WAF=Cloudflare" in result

    def test_phase_evaluations_rendered(self) -> None:
        result = _serialize_structured_context(
            ip_classifications=[],
            tech_fingerprints=[],
            phase_evaluations=[
                {
                    "phase": "osint",
                    "completeness": "partial",
                    "score": 0.6,
                    "gaps": ["No subdomain enumeration", "No httpx scan"],
                },
            ],
        )
        assert "osint" in result
        assert "partial" in result
        assert "0.6" in result
        assert "No subdomain enumeration" in result

    def test_empty_context_returns_empty(self) -> None:
        result = _serialize_structured_context(
            ip_classifications=[],
            tech_fingerprints=[],
            phase_evaluations=[],
        )
        assert result == ""

    def test_all_sections_combined(self) -> None:
        result = _serialize_structured_context(
            ip_classifications=[{"ip": "1.2.3.4", "ip_class": "cloud", "org": "AWS"}],
            tech_fingerprints=[{"host": "x.com", "server": "Apache", "technologies": []}],
            phase_evaluations=[{"phase": "port_scan", "completeness": "complete", "score": 0.9}],
        )
        assert "IP Infrastructure" in result
        assert "Technology Fingerprints" in result
        assert "Phase Quality" in result

    def test_caps_tech_fingerprints_at_10(self) -> None:
        fps = [{"host": f"host{i}.com", "server": "nginx", "technologies": []} for i in range(15)]
        result = _serialize_structured_context(
            ip_classifications=[],
            tech_fingerprints=fps,
            phase_evaluations=[],
        )
        assert result.count("server=nginx") == 10

    def test_skips_non_dict_phase_evaluations(self) -> None:
        result = _serialize_structured_context(
            ip_classifications=[],
            tech_fingerprints=[],
            phase_evaluations=["not a dict", None, 42],
        )
        assert "Phase Quality" in result


class TestRunTriageStructuredContext:
    """run_triage passes structured context to the LLM."""

    @patch("fackel.agents.triage.agent.build")
    def test_structured_context_in_llm_prompt(self, mock_build: MagicMock) -> None:
        mock_result = TriageResult(
            technologies_detected=["nginx"],
            unassessed_areas=[],
            risk_score=RiskScore(score=3.0, exposure_type="low", factors=[]),
            summary="OK",
        )
        mock_agent = MagicMock()
        mock_agent.invoke.return_value = {"structured_response": mock_result, "messages": []}
        mock_build.return_value = mock_agent

        run_triage(
            [{"phase": "osint", "title": "DNS", "detail": "found IPs"}],
            ip_classifications=[
                {"ip": "1.2.3.4", "ip_class": "direct_host", "org": "OVH"},
            ],
            tech_fingerprints=[
                {"host": "example.com", "server": "nginx", "technologies": ["React"]},
            ],
            phase_evaluations=[
                {"phase": "osint", "completeness": "complete", "score": 0.9},
            ],
        )

        call_args = mock_agent.invoke.call_args[0][0]
        human_msg = call_args["messages"][0].content
        assert "direct_host" in human_msg
        assert "nginx" in human_msg
        assert "React" in human_msg
        assert "osint" in human_msg

    @patch("fackel.agents.triage.agent.build")
    def test_no_structured_context_still_works(self, mock_build: MagicMock) -> None:
        mock_result = TriageResult(
            technologies_detected=[],
            unassessed_areas=[],
            risk_score=RiskScore(score=0.0, exposure_type="minimal", factors=[]),
            summary="No data.",
        )
        mock_agent = MagicMock()
        mock_agent.invoke.return_value = {"structured_response": mock_result, "messages": []}
        mock_build.return_value = mock_agent

        result = run_triage([])
        assert result.summary == "No data."


class TestTriageNodeStructuredPassthrough:
    """triage_node passes ip_classifications, tech_fingerprints, and
    phase_evaluations from state to run_triage."""

    @patch("fackel.agents.orchestrator.streaming.emit")
    @patch("fackel.agents.triage.agent.run_triage")
    def test_triage_node_passes_structured_data(
        self,
        mock_run_triage: MagicMock,
        _mock_emit: MagicMock,
    ) -> None:
        from fackel.agents.orchestrator.nodes import triage_node

        mock_result = TriageResult(
            technologies_detected=["nginx"],
            unassessed_areas=[],
            risk_score=RiskScore(score=5.0, exposure_type="moderate", factors=[]),
            summary="Moderate.",
        )
        mock_run_triage.return_value = mock_result

        state = {
            "target": "example.com",
            "active_scan": True,
            "findings": [{"phase": "osint", "title": "DNS", "detail": "data"}],
            "ip_classifications": [
                {"ip": "1.2.3.4", "ip_class": "direct_host", "org": "Hetzner"},
            ],
            "tech_fingerprints": [
                {"host": "example.com", "server": "Apache", "technologies": ["PHP"]},
            ],
            "phase_evaluations": [
                {"phase": "osint", "completeness": "complete", "score": 0.9},
            ],
        }

        triage_node(state, {})

        call_kwargs = mock_run_triage.call_args[1]
        assert call_kwargs["ip_classifications"] == state["ip_classifications"]
        assert call_kwargs["tech_fingerprints"] == state["tech_fingerprints"]
        assert call_kwargs["phase_evaluations"] == state["phase_evaluations"]


class TestOsintCollectLAAJ:
    """osint_collect_node evaluates the fan-in specialist output, and runs a
    quality-gated self-reflection retry (full-toolset pass) when the judge rates
    the combined output empty. Specialist messages arrive on ``osint_messages``.
    """

    @staticmethod
    def _make_eval(completeness: str, score: float) -> MagicMock:
        ev = MagicMock()
        ev.completeness = completeness
        ev.score = score
        ev.recommendation = "proceed"
        ev.gaps = ["No subdomain enumeration"] if completeness == "empty" else []
        ev.reasoning = "reason"
        ev.model_dump.return_value = {
            "phase": "osint",
            "completeness": completeness,
            "score": score,
        }
        return ev

    @staticmethod
    def _state() -> dict:
        from langchain_core.messages import AIMessage

        return {
            "target": "example.com",
            "active_scan": True,
            "osint_messages": [AIMessage(content="### OSINT Summary\nFound IPs.")],
        }

    @patch("fackel.agents.orchestrator.streaming.emit")
    @patch("fackel.agents.orchestrator.evaluator.evaluate_phase")
    @patch("fackel.agents.osint.agent.build")
    def test_osint_returns_phase_evaluation(
        self, mock_build: MagicMock, mock_eval: MagicMock, _mock_emit: MagicMock
    ) -> None:
        from fackel.agents.orchestrator.nodes import osint_collect_node

        mock_build.return_value = MagicMock()
        mock_eval.return_value = self._make_eval("complete", 0.8)

        result = osint_collect_node(self._state(), {})

        assert "phase_evaluations" in result
        assert len(result["phase_evaluations"]) == 1
        assert result["phase_evaluations"][0]["phase"] == "osint"
        mock_eval.assert_called_once()
        assert mock_eval.call_args[0][0] == "osint"

    @patch("fackel.agents.orchestrator.streaming.emit")
    @patch("fackel.agents.orchestrator.evaluator.evaluate_phase")
    @patch("fackel.agents.osint.agent.build")
    def test_osint_retries_on_empty_evaluation(
        self, mock_build: MagicMock, mock_eval: MagicMock, mock_emit: MagicMock
    ) -> None:
        from langchain_core.messages import AIMessage

        from fackel.agents.orchestrator.nodes import osint_collect_node

        call_count = 0

        def mock_stream(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return iter([("updates", {"agent": {"messages": [AIMessage(content="Retry pass.")]}})])

        mock_agent = MagicMock()
        mock_agent.checkpointer = None
        mock_agent.stream.side_effect = mock_stream
        mock_build.return_value = mock_agent
        mock_eval.return_value = self._make_eval("empty", 0.1)

        osint_collect_node(self._state(), {})

        # No store bound in tests, so the pivot loop is a no-op: the only agent
        # stream is the single self-reflection retry pass.
        assert call_count == 1
        retry_events = [
            c for c in mock_emit.call_args_list if len(c.args) >= 2 and c.args[1] == "retry"
        ]
        assert len(retry_events) == 1

    @patch("fackel.agents.orchestrator.streaming.emit")
    @patch("fackel.agents.orchestrator.evaluator.evaluate_phase")
    @patch("fackel.agents.osint.agent.build")
    def test_osint_no_retry_on_good_quality(
        self, mock_build: MagicMock, mock_eval: MagicMock, _mock_emit: MagicMock
    ) -> None:
        from fackel.agents.orchestrator.nodes import osint_collect_node

        mock_agent = MagicMock()
        mock_agent.stream.side_effect = AssertionError("agent should not stream")
        mock_build.return_value = mock_agent
        mock_eval.return_value = self._make_eval("complete", 0.9)

        osint_collect_node(self._state(), {})  # no retry, no pivot → no stream

    @patch("fackel.agents.orchestrator.streaming.emit")
    @patch("fackel.agents.orchestrator.evaluator.evaluate_phase")
    @patch("fackel.agents.osint.agent.build")
    def test_osint_no_retry_on_partial_quality(
        self, mock_build: MagicMock, mock_eval: MagicMock, _mock_emit: MagicMock
    ) -> None:
        from fackel.agents.orchestrator.nodes import osint_collect_node

        mock_agent = MagicMock()
        mock_agent.stream.side_effect = AssertionError("agent should not stream")
        mock_build.return_value = mock_agent
        mock_eval.return_value = self._make_eval("partial", 0.5)

        osint_collect_node(self._state(), {})  # partial → no retry

    @patch("fackel.agents.orchestrator.streaming.emit")
    @patch("fackel.agents.orchestrator.evaluator.evaluate_phase")
    @patch("fackel.agents.osint.agent.build")
    def test_osint_evaluation_emitted(
        self, mock_build: MagicMock, mock_eval: MagicMock, mock_emit: MagicMock
    ) -> None:
        from fackel.agents.orchestrator.nodes import osint_collect_node

        mock_build.return_value = MagicMock()
        ev = self._make_eval("complete", 0.85)
        ev.model_dump.return_value = {"phase": "osint", "score": 0.85}
        mock_eval.return_value = ev

        osint_collect_node(self._state(), {})

        eval_events = [
            c for c in mock_emit.call_args_list if len(c.args) >= 2 and c.args[1] == "evaluation"
        ]
        assert len(eval_events) >= 1
        assert eval_events[0].args[2]["score"] == 0.85
