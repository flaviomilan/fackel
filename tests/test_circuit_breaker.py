"""Tests for circuit_breaker module."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from langchain_core.tools import ToolException

from tools.circuit_breaker import (
    FAILURE_THRESHOLD,
    _CircuitState,
    _get_circuit,
    circuit_breaker,
    reset_all,
)


@pytest.fixture(autouse=True)
def _clean_circuits():
    """Reset all circuits before each test."""
    reset_all()
    yield
    reset_all()


class TestCircuitBreakerClosed:
    """Verify closed-state behaviour."""

    def test_passes_through_on_success(self):
        with circuit_breaker("test_service"):
            pass  # no error
        cb = _get_circuit("test_service")
        assert cb.state is _CircuitState.CLOSED
        assert cb.failure_count == 0

    def test_records_failure(self):
        with pytest.raises(ValueError):
            with circuit_breaker("test_service"):
                raise ValueError("boom")
        cb = _get_circuit("test_service")
        assert cb.failure_count == 1
        assert cb.state is _CircuitState.CLOSED  # not yet threshold

    def test_opens_after_threshold(self):
        for _ in range(FAILURE_THRESHOLD):
            with pytest.raises(RuntimeError):
                with circuit_breaker("test_service"):
                    raise RuntimeError("fail")
        cb = _get_circuit("test_service")
        assert cb.state is _CircuitState.OPEN


class TestCircuitBreakerOpen:
    """Verify open-state behaviour."""

    def _open_circuit(self, service: str = "test_service"):
        for _ in range(FAILURE_THRESHOLD):
            with pytest.raises(RuntimeError):
                with circuit_breaker(service):
                    raise RuntimeError("fail")

    def test_raises_tool_exception_immediately(self):
        self._open_circuit()
        with pytest.raises(ToolException, match="temporarily unavailable"):
            with circuit_breaker("test_service"):
                pass  # should not execute

    def test_transitions_to_half_open_after_timeout(self):
        self._open_circuit()
        cb = _get_circuit("test_service")
        # Simulate time passing beyond reset timeout
        cb.last_failure_time = time.monotonic() - 120
        with circuit_breaker("test_service"):
            pass  # probe succeeds
        assert cb.state is _CircuitState.CLOSED

    def test_half_open_probe_failure_reopens(self):
        self._open_circuit()
        cb = _get_circuit("test_service")
        cb.last_failure_time = time.monotonic() - 120
        with pytest.raises(RuntimeError):
            with circuit_breaker("test_service"):
                raise RuntimeError("probe failed")
        assert cb.state is _CircuitState.OPEN


class TestResetAll:
    """Verify reset function."""

    def test_clears_all_circuits(self):
        with pytest.raises(ValueError):
            with circuit_breaker("svc1"):
                raise ValueError("x")
        reset_all()
        cb = _get_circuit("svc1")
        assert cb.state is _CircuitState.CLOSED
        assert cb.failure_count == 0
