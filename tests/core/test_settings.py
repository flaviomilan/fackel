"""Tests for the centralized settings module."""

from __future__ import annotations

import pytest

from fackel.settings import _reset_settings, get_settings


@pytest.fixture(autouse=True)
def _clear_cache():
    """Reset the settings cache before and after each test."""
    _reset_settings()
    yield
    _reset_settings()


class TestDefaults:
    """Verify sensible defaults when no env vars are set."""

    def test_scan_timeout_default(self, monkeypatch):
        monkeypatch.delenv("FACKEL_SCAN_TIMEOUT", raising=False)
        s = get_settings()
        assert s.scan_timeout == 3600

    def test_max_agent_iterations_default(self, monkeypatch):
        monkeypatch.delenv("FACKEL_MAX_AGENT_ITERATIONS", raising=False)
        s = get_settings()
        assert s.max_agent_iterations == 50

    def test_budget_warning_ratio_default(self, monkeypatch):
        monkeypatch.delenv("FACKEL_BUDGET_WARNING_RATIO", raising=False)
        s = get_settings()
        assert s.budget_warning_ratio == pytest.approx(0.8)

    def test_default_model(self, monkeypatch):
        monkeypatch.delenv("FACKEL_DEFAULT_MODEL", raising=False)
        s = get_settings()
        assert s.default_model == "gpt-5-mini"

    def test_llm_request_timeout_default(self, monkeypatch):
        monkeypatch.delenv("FACKEL_LLM_REQUEST_TIMEOUT", raising=False)
        s = get_settings()
        assert s.llm_request_timeout == 120

    def test_subprocess_timeout_default(self, monkeypatch):
        monkeypatch.delenv("FACKEL_SUBPROCESS_TIMEOUT", raising=False)
        s = get_settings()
        assert s.subprocess_timeout == 180

    def test_subprocess_max_output_default(self, monkeypatch):
        monkeypatch.delenv("FACKEL_SUBPROCESS_MAX_OUTPUT", raising=False)
        s = get_settings()
        assert s.subprocess_max_output == 2 * 1024 * 1024

    def test_sanitizer_max_bytes_default(self, monkeypatch):
        monkeypatch.delenv("FACKEL_SANITIZER_MAX_BYTES", raising=False)
        s = get_settings()
        assert s.sanitizer_max_bytes == 50_000

    def test_circuit_breaker_threshold_default(self, monkeypatch):
        monkeypatch.delenv("FACKEL_CIRCUIT_BREAKER_THRESHOLD", raising=False)
        s = get_settings()
        assert s.circuit_breaker_threshold == 3

    def test_circuit_breaker_reset_timeout_default(self, monkeypatch):
        monkeypatch.delenv("FACKEL_CIRCUIT_BREAKER_RESET_TIMEOUT", raising=False)
        s = get_settings()
        assert s.circuit_breaker_reset_timeout == pytest.approx(60.0)

    def test_log_format_default(self, monkeypatch):
        monkeypatch.delenv("FACKEL_LOG_FORMAT", raising=False)
        s = get_settings()
        assert s.log_format == "text"


class TestEnvOverride:
    """Verify each setting can be overridden via environment variables."""

    def test_scan_timeout_from_env(self, monkeypatch):
        monkeypatch.setenv("FACKEL_SCAN_TIMEOUT", "7200")
        s = get_settings()
        assert s.scan_timeout == 7200

    def test_max_agent_iterations_from_env(self, monkeypatch):
        monkeypatch.setenv("FACKEL_MAX_AGENT_ITERATIONS", "100")
        s = get_settings()
        assert s.max_agent_iterations == 100

    def test_budget_warning_ratio_from_env(self, monkeypatch):
        monkeypatch.setenv("FACKEL_BUDGET_WARNING_RATIO", "0.9")
        s = get_settings()
        assert s.budget_warning_ratio == pytest.approx(0.9)

    def test_default_model_from_env(self, monkeypatch):
        monkeypatch.setenv("FACKEL_DEFAULT_MODEL", "gpt-4o")
        s = get_settings()
        assert s.default_model == "gpt-4o"

    def test_llm_request_timeout_from_env(self, monkeypatch):
        monkeypatch.setenv("FACKEL_LLM_REQUEST_TIMEOUT", "60")
        s = get_settings()
        assert s.llm_request_timeout == 60

    def test_subprocess_timeout_from_env(self, monkeypatch):
        monkeypatch.setenv("FACKEL_SUBPROCESS_TIMEOUT", "300")
        s = get_settings()
        assert s.subprocess_timeout == 300

    def test_circuit_breaker_threshold_from_env(self, monkeypatch):
        monkeypatch.setenv("FACKEL_CIRCUIT_BREAKER_THRESHOLD", "5")
        s = get_settings()
        assert s.circuit_breaker_threshold == 5

    def test_http_retry_total_from_env(self, monkeypatch):
        monkeypatch.setenv("FACKEL_HTTP_RETRY_TOTAL", "5")
        s = get_settings()
        assert s.http_retry_total == 5

    def test_log_format_from_env(self, monkeypatch):
        monkeypatch.setenv("FACKEL_LOG_FORMAT", "json")
        s = get_settings()
        assert s.log_format == "json"


class TestInvalidEnvValues:
    """Verify graceful fallback when env vars contain invalid values."""

    def test_invalid_int_falls_back(self, monkeypatch):
        monkeypatch.setenv("FACKEL_SCAN_TIMEOUT", "not-a-number")
        s = get_settings()
        assert s.scan_timeout == 3600  # default

    def test_invalid_float_falls_back(self, monkeypatch):
        monkeypatch.setenv("FACKEL_BUDGET_WARNING_RATIO", "abc")
        s = get_settings()
        assert s.budget_warning_ratio == pytest.approx(0.8)  # default

    def test_whitespace_only_uses_default(self, monkeypatch):
        monkeypatch.setenv("FACKEL_SCAN_TIMEOUT", "  ")
        s = get_settings()
        assert s.scan_timeout == 3600


class TestSettingsImmutability:
    """Verify the Settings dataclass is frozen."""

    def test_frozen_attribute(self):
        s = get_settings()
        with pytest.raises(AttributeError):
            s.scan_timeout = 999  # type: ignore[misc]


class TestCaching:
    """Verify get_settings caching and reset."""

    def test_singleton_across_calls(self):
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2

    def test_reset_forces_reload(self, monkeypatch):
        s1 = get_settings()
        _reset_settings()
        monkeypatch.setenv("FACKEL_SCAN_TIMEOUT", "999")
        s2 = get_settings()
        assert s2.scan_timeout == 999
        assert s1 is not s2
