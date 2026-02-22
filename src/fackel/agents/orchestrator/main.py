"""Orchestrator entry point.

Provides ``run`` (blocking) and ``run_stream`` (incremental snapshots)
as the public interface consumed by the CLI and tests.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterator

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
    return {
        "target": target,
        "active_scan": active_scan,
        "discovered_ips": [],
        "findings": [],
        "report": "",
    }


def _config() -> dict:
    """Generate a unique thread config for checkpointing."""
    return {"configurable": {"thread_id": str(uuid.uuid4())}}


def run(target: str, *, active_scan: bool = True) -> ScanState:
    """Execute the full scan workflow and return final state."""
    logger.info("orchestrator: run %s (active_scan=%s)", target, active_scan)
    return _get_graph().invoke(_initial_state(target, active_scan), config=_config())


def run_stream(target: str, *, active_scan: bool = True) -> Iterator[tuple[str, dict]]:
    """Yield ``(node_name, partial_update)`` as each graph node completes."""
    logger.info("orchestrator: stream %s (active_scan=%s)", target, active_scan)
    for chunk in _get_graph().stream(
        _initial_state(target, active_scan),
        config=_config(),
        stream_mode="updates",
    ):
        for node_name, update in chunk.items():
            yield node_name, update
