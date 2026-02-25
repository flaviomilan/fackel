"""Per-service circuit breaker for external HTTP APIs.

Prevents cascading failures by temporarily disabling services that fail
repeatedly.  Each service name tracks its own independent circuit state.

States
------
- **closed** — normal operation, requests pass through.
- **open** — service disabled, requests fail immediately with a clear
  ``ToolException`` so the agent can try an alternative.
- **half-open** — after ``reset_timeout`` seconds, one probe request is
  allowed.  Success closes the circuit; failure re-opens it.

Usage inside a tool::

    from tools.circuit_breaker import circuit_breaker

    @tool(handle_tool_error=True)
    def my_tool(target: str) -> dict:
        with circuit_breaker("crtsh"):
            resp = get_session().get(url, timeout=30)
            resp.raise_for_status()
            return format_tool_output(...)

The context manager:

1. Checks circuit state — raises immediately if open.
2. On successful ``__exit__`` — records success.
3. On exception — records failure, re-raises the original exception.

Thread-safety is ensured via a module-level ``threading.Lock``.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from enum import Enum

from langchain_core.tools import ToolException

logger = logging.getLogger(__name__)


FAILURE_THRESHOLD: int = 3

RESET_TIMEOUT: float = 60.0


class _CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half-open"


class _ServiceCircuit:
    """Mutable state for a single service's circuit breaker."""

    __slots__ = ("failure_count", "last_failure_time", "state")

    def __init__(self) -> None:
        self.state: _CircuitState = _CircuitState.CLOSED
        self.failure_count: int = 0
        self.last_failure_time: float = 0.0


_circuits: dict[str, _ServiceCircuit] = {}
_lock = threading.Lock()


def _get_circuit(service: str) -> _ServiceCircuit:
    """Return the circuit for *service*, creating one if needed."""
    if service not in _circuits:
        _circuits[service] = _ServiceCircuit()
    return _circuits[service]


@contextmanager
def circuit_breaker(service: str) -> Generator[None, None, None]:
    """Context manager that enforces circuit-breaker logic for *service*.

    Raises
    ------
    ToolException
        When the circuit is open and the service is temporarily unavailable.
    """
    with _lock:
        cb = _get_circuit(service)

        if cb.state is _CircuitState.OPEN:
            elapsed = time.monotonic() - cb.last_failure_time
            if elapsed >= RESET_TIMEOUT:
                cb.state = _CircuitState.HALF_OPEN
                logger.info(
                    "circuit_breaker(%s): transitioning OPEN → HALF-OPEN after %.0fs",
                    service,
                    elapsed,
                )
            else:
                remaining = RESET_TIMEOUT - elapsed
                raise ToolException(
                    f"{service} is temporarily unavailable (circuit breaker open, "
                    f"retry in {remaining:.0f}s after {cb.failure_count} consecutive failures)"
                )

    try:
        yield
    except Exception:
        with _lock:
            cb = _get_circuit(service)
            cb.failure_count += 1
            cb.last_failure_time = time.monotonic()
            if cb.failure_count >= FAILURE_THRESHOLD:
                cb.state = _CircuitState.OPEN
                logger.warning(
                    "circuit_breaker(%s): OPEN after %d consecutive failures",
                    service,
                    cb.failure_count,
                )
            elif cb.state is _CircuitState.HALF_OPEN:
                cb.state = _CircuitState.OPEN
                logger.warning(
                    "circuit_breaker(%s): half-open probe failed — re-opening",
                    service,
                )
        raise
    else:
        with _lock:
            cb = _get_circuit(service)
            if cb.state is not _CircuitState.CLOSED:
                logger.info(
                    "circuit_breaker(%s): %s → CLOSED (success)",
                    service,
                    cb.state.value,
                )
            cb.state = _CircuitState.CLOSED
            cb.failure_count = 0


def reset_all() -> None:
    """Reset all circuit breakers to closed.  Intended for testing."""
    with _lock:
        _circuits.clear()
