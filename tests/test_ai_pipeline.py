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

# ── Structured context serialization ───────────────────────────────────────


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
        # Should only contain 10 hosts
        assert result.count("server=nginx") == 10

    def test_skips_non_dict_phase_evaluations(self) -> None:
        result = _serialize_structured_context(
            ip_classifications=[],
            tech_fingerprints=[],
            phase_evaluations=["not a dict", None, 42],
        )
        # Should still produce a header but no items
        assert "Phase Quality" in result


# ── run_triage receives structured context ─────────────────────────────────


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

        # Verify the agent received structured context in the message
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

        # Should not raise when no structured context is passed
        result = run_triage([])
        assert result.summary == "No data."


# ── triage_node passes structured state to run_triage ──────────────────────


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

        # run_triage should have received structured context kwargs
        call_kwargs = mock_run_triage.call_args[1]
        assert call_kwargs["ip_classifications"] == state["ip_classifications"]
        assert call_kwargs["tech_fingerprints"] == state["tech_fingerprints"]
        assert call_kwargs["phase_evaluations"] == state["phase_evaluations"]


# ── osint_node LAAJ evaluation ─────────────────────────────────────────────


class TestOsintNodeLAAJ:
    """osint_node now includes LLM-as-a-judge evaluation and retry."""

    @patch("fackel.agents.orchestrator.streaming.emit")
    @patch("fackel.agents.orchestrator.evaluator.evaluate_phase")
    @patch("fackel.agents.osint.agent.build")
    def test_osint_returns_phase_evaluation(
        self,
        mock_build: MagicMock,
        mock_eval: MagicMock,
        _mock_emit: MagicMock,
    ) -> None:
        from langchain_core.messages import AIMessage

        from fackel.agents.orchestrator.nodes import osint_node

        # Mock agent returning dual stream_mode=["updates", "messages"] events.
        mock_agent = MagicMock()
        mock_agent.checkpointer = None
        mock_agent.stream.return_value = iter(
            [
                (
                    "updates",
                    {"agent": {"messages": [AIMessage(content="### OSINT Summary\nFound IPs.")]}},
                ),
            ]
        )
        mock_build.return_value = mock_agent

        # Mock evaluator — good quality
        mock_evaluation = MagicMock()
        mock_evaluation.completeness = "complete"
        mock_evaluation.score = 0.8
        mock_evaluation.recommendation = "proceed"
        mock_evaluation.model_dump.return_value = {
            "phase": "osint",
            "completeness": "complete",
            "score": 0.8,
            "recommendation": "proceed",
        }
        mock_eval.return_value = mock_evaluation

        state = {"target": "example.com", "active_scan": True}
        result = osint_node(state, {})

        # Should include phase_evaluations
        assert "phase_evaluations" in result
        assert len(result["phase_evaluations"]) == 1
        assert result["phase_evaluations"][0]["phase"] == "osint"

        # evaluate_phase was called for osint
        mock_eval.assert_called_once()
        assert mock_eval.call_args[0][0] == "osint"

    @patch("fackel.agents.orchestrator.streaming.emit")
    @patch("fackel.agents.orchestrator.evaluator.evaluate_phase")
    @patch("fackel.agents.osint.agent.build")
    def test_osint_retries_on_empty_evaluation(
        self,
        mock_build: MagicMock,
        mock_eval: MagicMock,
        mock_emit: MagicMock,
    ) -> None:
        from fackel.agents.orchestrator.nodes import osint_node

        # Mock agent stream
        call_count = 0

        def mock_stream(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            from langchain_core.messages import AIMessage

            return iter(
                [
                    (
                        "updates",
                        {"agent": {"messages": [AIMessage(content="Summary pass.")]}},
                    ),
                ]
            )

        mock_agent = MagicMock()
        mock_agent.checkpointer = None
        mock_agent.stream.side_effect = mock_stream
        mock_build.return_value = mock_agent

        # Mock evaluator — empty quality triggers retry
        mock_evaluation = MagicMock()
        mock_evaluation.completeness = "empty"
        mock_evaluation.score = 0.1
        mock_evaluation.recommendation = "adapt"
        mock_evaluation.gaps = ["No subdomain enumeration"]
        mock_evaluation.reasoning = "Only 1 tool was called"
        mock_evaluation.model_dump.return_value = {
            "phase": "osint",
            "completeness": "empty",
            "score": 0.1,
        }
        mock_eval.return_value = mock_evaluation

        state = {"target": "example.com", "active_scan": True}
        osint_node(state, {})

        # Agent should have been streamed twice (initial + retry)
        assert call_count == 2

        # Check a "retry" event was emitted
        retry_events = [
            c for c in mock_emit.call_args_list if len(c.args) >= 2 and c.args[1] == "retry"
        ]
        assert len(retry_events) == 1

    @patch("fackel.agents.orchestrator.streaming.emit")
    @patch("fackel.agents.orchestrator.evaluator.evaluate_phase")
    @patch("fackel.agents.osint.agent.build")
    def test_osint_no_retry_on_good_quality(
        self,
        mock_build: MagicMock,
        mock_eval: MagicMock,
        _mock_emit: MagicMock,
    ) -> None:
        from langchain_core.messages import AIMessage

        from fackel.agents.orchestrator.nodes import osint_node

        call_count = 0

        def mock_stream(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return iter(
                [
                    (
                        "updates",
                        {"agent": {"messages": [AIMessage(content="Rich OSINT findings.")]}},
                    ),
                ]
            )

        mock_agent = MagicMock()
        mock_agent.checkpointer = None
        mock_agent.stream.side_effect = mock_stream
        mock_build.return_value = mock_agent

        # Good evaluation — no retry
        mock_evaluation = MagicMock()
        mock_evaluation.completeness = "complete"
        mock_evaluation.score = 0.9
        mock_evaluation.recommendation = "proceed"
        mock_evaluation.model_dump.return_value = {
            "phase": "osint",
            "completeness": "complete",
            "score": 0.9,
        }
        mock_eval.return_value = mock_evaluation

        state = {"target": "example.com", "active_scan": True}
        osint_node(state, {})

        # Should only stream once — no retry
        assert call_count == 1

    @patch("fackel.agents.orchestrator.streaming.emit")
    @patch("fackel.agents.orchestrator.evaluator.evaluate_phase")
    @patch("fackel.agents.osint.agent.build")
    def test_osint_no_retry_on_partial_quality(
        self,
        mock_build: MagicMock,
        mock_eval: MagicMock,
        _mock_emit: MagicMock,
    ) -> None:
        from langchain_core.messages import AIMessage

        from fackel.agents.orchestrator.nodes import osint_node

        call_count = 0

        def mock_stream(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return iter(
                [
                    (
                        "updates",
                        {"agent": {"messages": [AIMessage(content="Partial findings.")]}},
                    ),
                ]
            )

        mock_agent = MagicMock()
        mock_agent.checkpointer = None
        mock_agent.stream.side_effect = mock_stream
        mock_build.return_value = mock_agent

        # Partial evaluation — score >= 0.3, no retry
        mock_evaluation = MagicMock()
        mock_evaluation.completeness = "partial"
        mock_evaluation.score = 0.5
        mock_evaluation.recommendation = "adapt"
        mock_evaluation.model_dump.return_value = {
            "phase": "osint",
            "completeness": "partial",
            "score": 0.5,
        }
        mock_eval.return_value = mock_evaluation

        state = {"target": "example.com", "active_scan": True}
        osint_node(state, {})

        # Should not retry on partial
        assert call_count == 1

    @patch("fackel.agents.orchestrator.streaming.emit")
    @patch("fackel.agents.orchestrator.evaluator.evaluate_phase")
    @patch("fackel.agents.osint.agent.build")
    def test_osint_evaluation_emitted(
        self,
        mock_build: MagicMock,
        mock_eval: MagicMock,
        mock_emit: MagicMock,
    ) -> None:
        from langchain_core.messages import AIMessage

        from fackel.agents.orchestrator.nodes import osint_node

        mock_agent = MagicMock()
        mock_agent.checkpointer = None
        mock_agent.stream.return_value = iter(
            [
                (
                    "updates",
                    {"agent": {"messages": [AIMessage(content="Summary.")]}},
                ),
            ]
        )
        mock_build.return_value = mock_agent

        mock_evaluation = MagicMock()
        mock_evaluation.completeness = "complete"
        mock_evaluation.score = 0.85
        mock_evaluation.recommendation = "proceed"
        mock_evaluation.model_dump.return_value = {"phase": "osint", "score": 0.85}
        mock_eval.return_value = mock_evaluation

        state = {"target": "example.com", "active_scan": True}
        osint_node(state, {})

        # Verify evaluation event was emitted
        eval_events = [
            c for c in mock_emit.call_args_list if len(c.args) >= 2 and c.args[1] == "evaluation"
        ]
        assert len(eval_events) >= 1
        assert eval_events[0].args[2]["score"] == 0.85
