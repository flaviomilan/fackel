"""Orchestrator entry point.

Provides ``run`` (blocking) as the public interface consumed by the CLI
and tests.

Supports Human-in-the-Loop via ``interrupt()`` — when the graph pauses
at the approval gate, callers must resume with ``Command(resume=value)``.
"""

from __future__ import annotations

import functools
import logging
import signal
import uuid
from collections.abc import Callable
from typing import Any, cast

from langchain_core.runnables import RunnableConfig
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command

from fackel.settings import get_settings
from fackel.tooling import sanitize_target

from .graph import build_graph
from .state import ScanState

logger = logging.getLogger(__name__)


@functools.lru_cache(maxsize=1)
def _get_graph() -> CompiledStateGraph:  # type: ignore[type-arg]
    """Lazy-build the compiled graph (cached after first call)."""
    return build_graph()


def _initial_state(target: str, active_scan: bool) -> dict[str, Any]:
    clean_target = sanitize_target(target)
    return {
        "target": clean_target,
        "active_scan": active_scan,
        "discovered_ips": [],
        "discovered_subdomains": [],
        "findings": [],
        "unassessed_areas": [],
        "phase_evaluations": [],
        "ip_classifications": [],
        "tech_fingerprints": [],
        "risk_score": {},
        "report": "",
    }


def _config(scan_id: str) -> RunnableConfig:
    """Generate a unique thread config with scan-level correlation ID."""
    return cast(
        RunnableConfig,
        {
            "configurable": {"thread_id": str(uuid.uuid4())},
            "metadata": {"scan_id": scan_id},
        },
    )


class ScanTimeoutError(Exception):
    """Raised when the global scan timeout is exceeded."""


class ScanInterruptedError(Exception):
    """Raised when the scan receives SIGINT or SIGTERM."""


def _scan_timeout() -> int:
    """Return the global scan timeout in seconds from settings."""
    return get_settings().scan_timeout


def _timeout_handler(signum: int, frame: Any) -> None:
    raise ScanTimeoutError("Global scan timeout exceeded")


def _interrupt_handler(signum: int, frame: Any) -> None:
    sig_name = signal.Signals(signum).name
    raise ScanInterruptedError(f"Scan interrupted by {sig_name}")


def run(
    target: str,
    *,
    active_scan: bool = True,
    approval_callback: Callable[[dict[str, Any]], bool] | None = None,
) -> ScanState:
    """Execute the full scan workflow and return final state.

    Parameters
    ----------
    target:
        Domain or IP to scan.
    active_scan:
        Whether to enable active scanning phases.
    approval_callback:
        An optional callable ``(interrupt_value: dict) -> bool`` used to
        handle the human-in-the-loop approval gate.  If *None* and an
        interrupt occurs, the scan is automatically approved.

    Raises
    ------
    ScanTimeoutError
        When the scan exceeds ``FACKEL_SCAN_TIMEOUT`` seconds (default 3600).
    ScanInterruptedError
        When the process receives SIGINT or SIGTERM during scanning.
    """
    scan_id = uuid.uuid4().hex[:12]
    logger.info("orchestrator: run %s (active_scan=%s, scan_id=%s)", target, active_scan, scan_id)

    graph = _get_graph()
    config = _config(scan_id)

    timeout = _scan_timeout()
    prev_alarm = signal.signal(signal.SIGALRM, _timeout_handler)
    prev_int = signal.signal(signal.SIGINT, _interrupt_handler)
    prev_term = signal.signal(signal.SIGTERM, _interrupt_handler)
    signal.alarm(timeout)
    logger.info("orchestrator: global timeout set to %d s", timeout)

    try:
        result = graph.invoke(_initial_state(target, active_scan), config=config)

        snapshot = graph.get_state(config)
        while snapshot.next:
            interrupt_values = snapshot.tasks[0].interrupts
            if interrupt_values:
                interrupt_data = interrupt_values[0].value
                approved = (
                    approval_callback(interrupt_data) if approval_callback is not None else True
                )
            else:
                approved = True

            result = graph.invoke(Command(resume=approved), config=config)
            snapshot = graph.get_state(config)
    except ScanInterruptedError:
        logger.warning("orchestrator: scan %s interrupted — cleaning up", scan_id)
        raise
    finally:
        signal.alarm(0)  # cancel the alarm
        signal.signal(signal.SIGALRM, prev_alarm)
        signal.signal(signal.SIGINT, prev_int)
        signal.signal(signal.SIGTERM, prev_term)

    return cast(ScanState, result)
