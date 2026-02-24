"""Orchestrator entry point.

Provides ``run`` (blocking) as the public interface consumed by the CLI
and tests.

Supports Human-in-the-Loop via ``interrupt()`` — when the graph pauses
at the approval gate, callers must resume with ``Command(resume=value)``.
"""

from __future__ import annotations

import logging
import uuid

from langgraph.types import Command

from fackel.tooling import sanitize_target

from .graph import build_graph
from .state import ScanState

logger = logging.getLogger(__name__)

_graph = None


def _get_graph():
    """Lazy-build the compiled graph (cached at module level)."""
    global _graph  # noqa: PLW0603
    if _graph is None:
        _graph = build_graph()
    return _graph


def _initial_state(target: str, active_scan: bool) -> dict:
    clean_target = sanitize_target(target)
    return {
        "target": clean_target,
        "active_scan": active_scan,
        "discovered_ips": [],
        "discovered_subdomains": [],
        "findings": [],
        "unassessed_areas": [],
        "phase_evaluations": [],
        "report": "",
    }


def _config() -> dict:
    """Generate a unique thread config for checkpointing."""
    return {"configurable": {"thread_id": str(uuid.uuid4())}}


def run(
    target: str,
    *,
    active_scan: bool = True,
    approval_callback=None,
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
    """
    logger.info("orchestrator: run %s (active_scan=%s)", target, active_scan)

    graph = _get_graph()
    config = _config()

    # First invocation — may pause at approval_gate interrupt().
    result = graph.invoke(_initial_state(target, active_scan), config=config)

    # Check if the graph is paused at an interrupt.
    snapshot = graph.get_state(config)
    while snapshot.next:  # There are pending nodes → interrupt occurred
        interrupt_values = snapshot.tasks[0].interrupts
        if interrupt_values:
            interrupt_data = interrupt_values[0].value
            if approval_callback is not None:
                approved = approval_callback(interrupt_data)
            else:
                approved = True  # Auto-approve when no callback
        else:
            approved = True

        # Resume with the user's decision.
        result = graph.invoke(Command(resume=approved), config=config)
        snapshot = graph.get_state(config)

    return result
