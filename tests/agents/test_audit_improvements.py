"""Tests for the architecture audit improvements.

Covers:
- merge_findings dedup reducer
- _TimeoutGuard cross-platform context manager
- reset_orchestrator cache clearing
- _estimate_tokens helper
- _classify_error structured classification
- approval_gate rejection finding via Command(update=...)
- agent_context_window setting
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from fackel.agents.orchestrator.state import Finding, merge_findings
from fackel.settings import _reset_settings, get_settings


@pytest.fixture(autouse=True)
def _clear_settings():
    _reset_settings()
    yield
    _reset_settings()


# ---------------------------------------------------------------------------
# merge_findings reducer
# ---------------------------------------------------------------------------


class TestMergeFindingsReducer:
    """Verify fingerprint-based deduplication in the findings reducer."""

    def test_appends_unique_findings(self):
        old = [Finding(phase="osint", title="A", detail="x")]
        new = [Finding(phase="port_scan", title="B", detail="y")]
        result = merge_findings(old, new)
        assert len(result) == 2
        assert result[0]["title"] == "A"
        assert result[1]["title"] == "B"

    def test_deduplicates_identical_findings(self):
        f = Finding(phase="osint", title="A", detail="same detail text")
        old = [f]
        new = [Finding(phase="osint", title="A", detail="same detail text")]
        result = merge_findings(old, new)
        assert len(result) == 1

    def test_keeps_higher_confidence_on_duplicate(self):
        old = [Finding(phase="osint", title="A", detail="d", confidence=0.5)]
        new = [Finding(phase="osint", title="A", detail="d", confidence=0.9)]
        result = merge_findings(old, new)
        assert len(result) == 1
        assert result[0]["confidence"] == 0.9

    def test_keeps_old_when_new_confidence_lower(self):
        old = [Finding(phase="osint", title="A", detail="d", confidence=0.9)]
        new = [Finding(phase="osint", title="A", detail="d", confidence=0.3)]
        result = merge_findings(old, new)
        assert len(result) == 1
        assert result[0]["confidence"] == 0.9

    def test_empty_old_returns_new(self):
        new = [Finding(phase="osint", title="A", detail="d")]
        result = merge_findings([], new)
        assert len(result) == 1

    def test_empty_new_returns_old(self):
        old = [Finding(phase="osint", title="A", detail="d")]
        result = merge_findings(old, [])
        assert len(result) == 1

    def test_different_phases_not_deduped(self):
        old = [Finding(phase="osint", title="A", detail="d")]
        new = [Finding(phase="vuln_scan", title="A", detail="d")]
        result = merge_findings(old, new)
        assert len(result) == 2

    def test_long_detail_fingerprint_uses_prefix(self):
        """Two findings with same first 120 chars but different tails are deduped."""
        shared = "x" * 120
        old = [Finding(phase="osint", title="A", detail=shared + " old tail")]
        new = [Finding(phase="osint", title="A", detail=shared + " new tail")]
        result = merge_findings(old, new)
        assert len(result) == 1

    def test_multiple_duplicates_in_single_batch(self):
        old: list[Finding] = []
        new = [
            Finding(phase="osint", title="A", detail="d"),
            Finding(phase="osint", title="A", detail="d"),
            Finding(phase="osint", title="A", detail="d"),
        ]
        result = merge_findings(old, new)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# _TimeoutGuard
# ---------------------------------------------------------------------------


class TestTimeoutGuard:
    """Verify the cross-platform timeout context manager."""

    def test_guard_does_not_raise_within_timeout(self):
        from fackel.agents.orchestrator.main import _TimeoutGuard

        with _TimeoutGuard(10) as guard:
            guard.check()  # should not raise

    def test_guard_threading_fallback_raises_on_expiry(self):
        """Force the threading path (use_signals=False) and verify it detects expiry."""
        from fackel.agents.orchestrator.main import ScanTimeoutError, _TimeoutGuard

        # use_signals=False forces the threading.Timer path (e.g. worker thread).
        guard = _TimeoutGuard(1, install_signal_handlers=False, use_signals=False)
        with guard:
            guard._expired.set()  # manually trigger expiry
            with pytest.raises(ScanTimeoutError):
                guard.check()

    def test_zero_timeout_is_disabled(self):
        """A timeout of 0 disables the guard — no alarm/timer, check() no-ops."""
        from fackel.agents.orchestrator.main import _TimeoutGuard

        guard = _TimeoutGuard(0)
        assert guard._enabled is False
        with guard:
            guard.check()  # never raises when disabled

    def test_negative_timeout_is_disabled(self):
        from fackel.agents.orchestrator.main import _TimeoutGuard

        assert _TimeoutGuard(-5)._enabled is False

    def test_disabled_threading_path_does_not_arm_timer(self):
        """Regression: timeout=0 on the threading path must NOT start a Timer
        (a ``Timer(0)`` would fire immediately and raise spuriously)."""
        from fackel.agents.orchestrator.main import _TimeoutGuard

        guard = _TimeoutGuard(0)
        with patch("fackel.agents.orchestrator.main._HAS_SIGALRM", False), guard:
            assert guard._timer is None
            guard.check()  # no expiry possible


# ---------------------------------------------------------------------------
# reset_orchestrator
# ---------------------------------------------------------------------------


class TestResetOrchestrator:
    """Verify the public reset helper clears caches."""

    def test_reset_clears_graph_cache(self):
        from fackel.agents.orchestrator.main import _get_graph, reset_orchestrator

        # Ensure the cache is considered valid by checking info
        reset_orchestrator()
        info = _get_graph.cache_info()
        assert info.hits == 0


# ---------------------------------------------------------------------------
# _estimate_tokens
# ---------------------------------------------------------------------------


class TestEstimateTokens:
    """Verify the token estimator for trim_messages."""

    def test_string_content(self):
        from langchain_core.messages import HumanMessage

        from fackel.agents.orchestrator.streaming import _estimate_tokens

        msgs = [HumanMessage(content="hello world " * 50)]
        result = _estimate_tokens(msgs)
        # tiktoken (cl100k_base) puts "hello world " at ~2 tokens; the
        # heuristic fallback gives len/3+1.  Either way, it must be a
        # positive estimate proportional to input length.
        assert 50 < result < 500

    def test_empty_messages(self):
        from fackel.agents.orchestrator.streaming import _estimate_tokens

        assert _estimate_tokens([]) == 0

    def test_list_content_with_text_block(self):
        from fackel.agents.orchestrator.streaming import _estimate_tokens

        msg = MagicMock()
        msg.content = [{"text": "hello world " * 10}]
        result = _estimate_tokens([msg])
        assert result > 0


# ---------------------------------------------------------------------------
# _classify_error
# ---------------------------------------------------------------------------


class TestClassifyError:
    """Verify error classification for structured persistence."""

    def test_timeout_classification(self):
        from fackel.agents.orchestrator.streaming import _classify_error

        assert _classify_error("Connection timed out after 30s") == "timeout"
        assert _classify_error("Request timeout exceeded") == "timeout"

    def test_auth_classification(self):
        from fackel.agents.orchestrator.streaming import _classify_error

        assert _classify_error("HTTP 401 Unauthorized") == "auth"
        assert _classify_error("HTTP 403 Forbidden") == "auth"
        assert _classify_error("Invalid API key") == "auth"

    def test_connection_classification(self):
        from fackel.agents.orchestrator.streaming import _classify_error

        assert _classify_error("Connection refused") == "connection"
        assert _classify_error("Host unreachable") == "connection"

    def test_rate_limit_classification(self):
        from fackel.agents.orchestrator.streaming import _classify_error

        assert _classify_error("Rate limit exceeded") == "rate_limit"

    def test_unknown_fallback(self):
        from fackel.agents.orchestrator.streaming import _classify_error

        assert _classify_error("Something weird happened") == "unknown"


# ---------------------------------------------------------------------------
# agent_context_window setting
# ---------------------------------------------------------------------------


class TestAgentContextWindowSetting:
    """Verify the new agent_context_window setting."""

    def test_default_value(self, monkeypatch):
        monkeypatch.delenv("FACKEL_AGENT_CONTEXT_WINDOW", raising=False)
        s = get_settings()
        assert s.agent_context_window == 120_000

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("FACKEL_AGENT_CONTEXT_WINDOW", "200000")
        s = get_settings()
        assert s.agent_context_window == 200_000


# ---------------------------------------------------------------------------
# approval_gate rejection finding
# ---------------------------------------------------------------------------


class TestApprovalGateRejectionFinding:
    """Verify the rejection Command carries a finding in update."""

    def test_rejection_command_has_finding(self):
        from unittest.mock import patch as mock_patch

        from fackel.agents.orchestrator.nodes.report_and_gates import approval_gate

        state = {
            "target": "example.com",
            "active_scan": True,
            "discovered_ips": ["1.2.3.4"],
            "discovered_subdomains": [],
            "ip_classifications": [],
        }

        with (
            mock_patch(
                "fackel.agents.orchestrator.nodes.report_and_gates.interrupt",
                return_value=False,
            ),
            mock_patch(
                "fackel.agents.orchestrator.nodes.report_and_gates.streaming",
            ),
        ):
            cmd = approval_gate(state)

        assert cmd.goto == "report"
        assert "findings" in cmd.update
        findings = cmd.update["findings"]
        assert len(findings) == 1
        assert findings[0]["phase"] == "approval"
        assert findings[0]["title"] == "Active Scan Rejected"

    def test_approval_command_has_no_update(self):
        from unittest.mock import patch as mock_patch

        from fackel.agents.orchestrator.nodes.report_and_gates import approval_gate

        state = {
            "target": "example.com",
            "active_scan": True,
            "discovered_ips": ["1.2.3.4"],
            "discovered_subdomains": [],
            "ip_classifications": [],
        }

        with (
            mock_patch(
                "fackel.agents.orchestrator.nodes.report_and_gates.interrupt",
                return_value=True,
            ),
            mock_patch(
                "fackel.agents.orchestrator.nodes.report_and_gates.streaming",
            ),
        ):
            cmd = approval_gate(state)

        assert cmd.goto == "port_scan"
