"""Tests for agents/config — model configuration and middleware."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from fackel.agents.config import (
    ACTIVE_SCAN_TOOLS,
    ParallelToolCalls,
    get_model,
    default_middleware,
)


class TestGetModel:
    """Verify model name resolution from environment."""

    def test_default_model(self, monkeypatch):
        monkeypatch.delenv("FACKEL_MODEL_OSINT", raising=False)
        model = get_model("osint")
        assert model == "gpt-5-mini"

    def test_custom_model_from_env(self, monkeypatch):
        monkeypatch.setenv("FACKEL_MODEL_OSINT", "gpt-4o")
        model = get_model("osint")
        assert model == "gpt-4o"

    def test_uppercased_env_var(self, monkeypatch):
        monkeypatch.setenv("FACKEL_MODEL_PORT_SCAN", "claude-3-opus")
        model = get_model("port_scan")
        assert model == "claude-3-opus"


class TestParallelToolCalls:
    """Verify parallel tool calls middleware."""

    def test_sets_parallel_tool_calls(self):
        mw = ParallelToolCalls()
        request = MagicMock()
        request.model_settings = {}
        handler = MagicMock(return_value=MagicMock())

        mw.wrap_model_call(request, handler)

        assert request.model_settings["parallel_tool_calls"] is True
        handler.assert_called_once_with(request)

    def test_does_not_override_existing_setting(self):
        mw = ParallelToolCalls()
        request = MagicMock()
        request.model_settings = {"parallel_tool_calls": False}
        handler = MagicMock(return_value=MagicMock())

        mw.wrap_model_call(request, handler)

        assert request.model_settings["parallel_tool_calls"] is False


class TestDefaultMiddleware:
    """Verify middleware stack construction."""

    def test_default_has_two_middleware(self):
        mw_list = default_middleware()
        assert len(mw_list) == 2

    def test_approve_tools_adds_hitl(self):
        mw_list = default_middleware(approve_tools=True)
        assert len(mw_list) == 3


class TestActiveScanTools:
    """Verify active scanning tools constant."""

    def test_contains_expected_tools(self):
        assert "nmap_port_scan" in ACTIVE_SCAN_TOOLS
        assert "nuclei_scan" in ACTIVE_SCAN_TOOLS
        assert "naabu_scan" in ACTIVE_SCAN_TOOLS

    def test_does_not_contain_passive_tools(self):
        assert "dns_resolve" not in ACTIVE_SCAN_TOOLS
        assert "shodan_lookup" not in ACTIVE_SCAN_TOOLS
