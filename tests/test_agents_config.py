"""Tests for agents/config — model configuration, provider resolution, and middleware."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from fackel.agents.config import (
    _PROVIDER_FACTORIES,
    ACTIVE_SCAN_TOOLS,
    ParallelToolCalls,
    build_llm,
    default_middleware,
    get_model,
    get_provider,
)


class TestGetProvider:
    """Verify provider resolution from environment."""

    def test_default_provider(self, monkeypatch):
        monkeypatch.delenv("FACKEL_PROVIDER_OSINT", raising=False)
        assert get_provider("osint") == "openai"

    def test_custom_provider_from_env(self, monkeypatch):
        monkeypatch.setenv("FACKEL_PROVIDER_OSINT", "ollama")
        assert get_provider("osint") == "ollama"

    def test_provider_normalised_to_lowercase(self, monkeypatch):
        monkeypatch.setenv("FACKEL_PROVIDER_REPORT", "Ollama")
        assert get_provider("report") == "ollama"

    def test_uppercased_agent_name(self, monkeypatch):
        monkeypatch.setenv("FACKEL_PROVIDER_PORT_SCAN", "ollama")
        assert get_provider("port_scan") == "ollama"


class TestGetModel:
    """Verify model name resolution from environment."""

    def test_default_model_openai(self, monkeypatch):
        monkeypatch.delenv("FACKEL_MODEL_OSINT", raising=False)
        monkeypatch.delenv("FACKEL_PROVIDER_OSINT", raising=False)
        model = get_model("osint")
        assert model == "gpt-5-mini"

    def test_default_model_ollama(self, monkeypatch):
        monkeypatch.delenv("FACKEL_MODEL_OSINT", raising=False)
        monkeypatch.setenv("FACKEL_PROVIDER_OSINT", "ollama")
        model = get_model("osint")
        assert model == "llama3.2"

    def test_custom_model_from_env(self, monkeypatch):
        monkeypatch.setenv("FACKEL_MODEL_OSINT", "gpt-4o")
        model = get_model("osint")
        assert model == "gpt-4o"

    def test_uppercased_env_var(self, monkeypatch):
        monkeypatch.setenv("FACKEL_MODEL_PORT_SCAN", "claude-3-opus")
        model = get_model("port_scan")
        assert model == "claude-3-opus"


class TestBuildLlm:
    """Verify build_llm dispatches to the correct provider factory."""

    def test_openai_provider_calls_factory(self, monkeypatch):
        monkeypatch.delenv("FACKEL_PROVIDER_OSINT", raising=False)
        monkeypatch.delenv("FACKEL_MODEL_OSINT", raising=False)
        mock_model = MagicMock()
        with patch.dict(_PROVIDER_FACTORIES, {"openai": MagicMock(return_value=mock_model)}):
            result = build_llm("osint")
        assert result is mock_model

    def test_ollama_provider_calls_factory(self, monkeypatch):
        monkeypatch.setenv("FACKEL_PROVIDER_OSINT", "ollama")
        monkeypatch.delenv("FACKEL_MODEL_OSINT", raising=False)
        mock_model = MagicMock()
        with patch.dict(_PROVIDER_FACTORIES, {"ollama": MagicMock(return_value=mock_model)}):
            result = build_llm("osint")
        assert result is mock_model

    def test_explicit_model_overrides_env(self, monkeypatch):
        monkeypatch.delenv("FACKEL_PROVIDER_OSINT", raising=False)
        monkeypatch.setenv("FACKEL_MODEL_OSINT", "gpt-4o")
        factory = MagicMock(return_value=MagicMock())
        with patch.dict(_PROVIDER_FACTORIES, {"openai": factory}):
            build_llm("osint", model_name="gpt-5")
        factory.assert_called_once_with("gpt-5", None, 120)

    def test_unknown_provider_raises(self, monkeypatch):
        monkeypatch.setenv("FACKEL_PROVIDER_OSINT", "not_a_provider")
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            build_llm("osint")

    def test_temperature_and_timeout_forwarded(self, monkeypatch):
        monkeypatch.delenv("FACKEL_PROVIDER_OSINT", raising=False)
        monkeypatch.delenv("FACKEL_MODEL_OSINT", raising=False)
        factory = MagicMock(return_value=MagicMock())
        with patch.dict(_PROVIDER_FACTORIES, {"openai": factory}):
            build_llm("osint", temperature=0.5, request_timeout=30)
        factory.assert_called_once_with("gpt-5-mini", 0.5, 30)

    def test_per_agent_provider_isolation(self, monkeypatch):
        """Different agents can use different providers simultaneously."""
        monkeypatch.setenv("FACKEL_PROVIDER_OSINT", "ollama")
        monkeypatch.setenv("FACKEL_PROVIDER_REPORT", "openai")
        monkeypatch.delenv("FACKEL_PROVIDER_PORT_SCAN", raising=False)
        assert get_provider("osint") == "ollama"
        assert get_provider("report") == "openai"
        assert get_provider("port_scan") == "openai"  # default


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
