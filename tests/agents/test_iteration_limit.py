"""Tests for the configurable / disableable agent tool-call limit."""

from __future__ import annotations

import fackel.settings as settings_mod
from fackel.agents.orchestrator import streaming


class _FakeAgent:
    checkpointer = None


def _streamer() -> streaming._AgentStreamer:
    return streaming._AgentStreamer(_FakeAgent(), "osint")


class TestIterationLimit:
    def test_default_caps_and_sets_recursion_limit(self, monkeypatch) -> None:
        monkeypatch.delenv("FACKEL_MAX_AGENT_ITERATIONS", raising=False)
        settings_mod.get_settings.cache_clear()
        st = _streamer()
        # recursion limit tracks the budget (2 * 50 + 10), not LangGraph's default 25.
        assert st._config["recursion_limit"] == 110
        st._tool_call_count = 50
        st._check_iteration_limit()
        assert st._hit_limit is True

    def test_zero_disables_limit(self, monkeypatch) -> None:
        monkeypatch.setenv("FACKEL_MAX_AGENT_ITERATIONS", "0")
        settings_mod.get_settings.cache_clear()
        try:
            st = _streamer()
            assert st._config["recursion_limit"] == 10_000  # effectively unlimited
            st._tool_call_count = 999
            st._check_iteration_limit()
            assert st._hit_limit is False  # never capped
        finally:
            settings_mod.get_settings.cache_clear()

    def test_custom_limit_respected(self, monkeypatch) -> None:
        monkeypatch.setenv("FACKEL_MAX_AGENT_ITERATIONS", "10")
        settings_mod.get_settings.cache_clear()
        try:
            st = _streamer()
            assert st._config["recursion_limit"] == 30  # 2 * 10 + 10
            st._tool_call_count = 10
            st._check_iteration_limit()
            assert st._hit_limit is True
        finally:
            settings_mod.get_settings.cache_clear()
