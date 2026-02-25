"""Tests for provider_keys module — API key checks and tool filtering."""

from __future__ import annotations

from unittest.mock import MagicMock

from fackel.provider_keys import (
    ProviderKeySpec,
    _is_env_set,
    filter_tools,
    get_provider_key_status,
    get_unavailable_tool_names,
)


class TestIsEnvSet:
    """Verify _is_env_set helper."""

    def test_set_variable(self, monkeypatch):
        monkeypatch.setenv("TEST_KEY", "value")
        assert _is_env_set("TEST_KEY") is True

    def test_empty_variable(self, monkeypatch):
        monkeypatch.setenv("TEST_KEY", "")
        assert _is_env_set("TEST_KEY") is False

    def test_whitespace_only(self, monkeypatch):
        monkeypatch.setenv("TEST_KEY", "   ")
        assert _is_env_set("TEST_KEY") is False

    def test_missing_variable(self, monkeypatch):
        monkeypatch.delenv("TEST_KEY", raising=False)
        assert _is_env_set("TEST_KEY") is False


class TestGetProviderKeyStatus:
    """Verify provider status detection."""

    def test_returns_all_providers(self):
        status = get_provider_key_status()
        assert len(status) > 0
        for spec, available in status:
            assert isinstance(spec, ProviderKeySpec)
            assert isinstance(available, bool)

    def test_available_when_keys_set(self, monkeypatch):
        monkeypatch.setenv("SHODAN_API_KEY", "test-key")
        status = get_provider_key_status()
        shodan = next(s for s in status if s[0].provider == "Shodan")
        assert shodan[1] is True

    def test_unavailable_when_key_missing(self, monkeypatch):
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        status = get_provider_key_status()
        shodan = next(s for s in status if s[0].provider == "Shodan")
        assert shodan[1] is False


class TestGetUnavailableToolNames:
    """Verify tool name filtering based on API keys."""

    def test_missing_key_marks_tool_unavailable(self, monkeypatch):
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        unavailable = get_unavailable_tool_names()
        assert "shodan_lookup" in unavailable
        provider, missing = unavailable["shodan_lookup"]
        assert provider == "Shodan"
        assert "SHODAN_API_KEY" in missing

    def test_set_key_removes_tool_from_unavailable(self, monkeypatch):
        monkeypatch.setenv("SHODAN_API_KEY", "test-key")
        unavailable = get_unavailable_tool_names()
        assert "shodan_lookup" not in unavailable

    def test_soft_fail_providers_excluded(self, monkeypatch):
        """HIBP and EmailRep should NOT be in unavailable even without keys."""
        monkeypatch.delenv("HIBP_API_KEY", raising=False)
        monkeypatch.delenv("EMAILREP_API_KEY", raising=False)
        unavailable = get_unavailable_tool_names()
        assert "analyze_email" not in unavailable


class TestFilterTools:
    """Verify tool list partitioning."""

    def test_available_tool_passes_through(self, monkeypatch):
        monkeypatch.setenv("SHODAN_API_KEY", "key")
        tool = MagicMock()
        tool.name = "shodan_lookup"
        available, skipped = filter_tools([tool])
        assert tool in available
        assert len(skipped) == 0

    def test_unavailable_tool_skipped(self, monkeypatch):
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        tool = MagicMock()
        tool.name = "shodan_lookup"
        available, skipped = filter_tools([tool])
        assert tool not in available
        assert len(skipped) == 1
        assert skipped[0][0] == "shodan_lookup"
        assert skipped[0][1] == "Shodan"

    def test_unknown_tool_passes_through(self, monkeypatch):
        tool = MagicMock()
        tool.name = "custom_tool"
        available, skipped = filter_tools([tool])
        assert tool in available

    def test_mixed_tools_partitioned(self, monkeypatch):
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        monkeypatch.setenv("OTX_API_KEY", "key")
        shodan = MagicMock()
        shodan.name = "shodan_lookup"
        otx = MagicMock()
        otx.name = "otx_passive_dns"
        available, skipped = filter_tools([shodan, otx])
        assert otx in available
        assert shodan not in available
        assert len(skipped) == 1
