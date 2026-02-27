"""Orchestrator entry point.

Provides ``run`` (blocking) as the public interface consumed by the CLI
and tests.

Supports Human-in-the-Loop via ``interrupt()`` — when the graph pauses
at the approval gate or guidance gates, callers must resume with
``Command(resume=value)``.
"""

from __future__ import annotations

import functools
import logging
import uuid
from collections.abc import Callable
from typing import Any, cast

from langchain_core.runnables import RunnableConfig
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command

from fackel.tooling import sanitize_target

from .graph import build_graph
from .state import ScanState

logger = logging.getLogger(__name__)

GuidanceCallback = Callable[[dict[str, Any]], str] | None


@functools.lru_cache(maxsize=1)
def _get_graph() -> CompiledStateGraph:  # type: ignore[type-arg]
    """Lazy-build the compiled graph (cached after first call)."""
    return build_graph()


def _initial_state(target: str, active_scan: bool, *, initial_guidance: str = "") -> dict[str, Any]:
    clean_target = sanitize_target(target)
    phase_guidance: dict[str, str] = {}
    if initial_guidance:
        phase_guidance["osint"] = initial_guidance
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
        "phase_guidance": phase_guidance,
        "risk_score": {},
        "report": "",
    }


def _config() -> RunnableConfig:
    """Generate a unique thread config for checkpointing."""
    return cast(RunnableConfig, {"configurable": {"thread_id": str(uuid.uuid4())}})


def run(
    target: str,
    *,
    active_scan: bool = True,
    approval_callback: Callable[[dict[str, Any]], bool] | None = None,
    guidance_callback: GuidanceCallback = None,
    initial_guidance: str = "",
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
    guidance_callback:
        An optional callable ``(interrupt_value: dict) -> str`` used to
        handle per-phase guidance gates.  If *None*, guidance gates are
        silently skipped (empty guidance).
    initial_guidance:
        Free-text guidance to pre-seed the OSINT phase (e.g. from
        interactive intake).  Applied even without ``--guided``.
    """
    logger.info("orchestrator: run %s (active_scan=%s)", target, active_scan)

    graph = _get_graph()
    config = _config()

    result = graph.invoke(
        _initial_state(target, active_scan, initial_guidance=initial_guidance),
        config=config,
    )

    snapshot = graph.get_state(config)
    while snapshot.next:
        interrupt_values = snapshot.tasks[0].interrupts
        if interrupt_values:
            interrupt_data = interrupt_values[0].value
            resume_value = _resolve_interrupt(
                interrupt_data,
                approval_callback=approval_callback,
                guidance_callback=guidance_callback,
            )
        else:
            resume_value: Any = True

        result = graph.invoke(Command(resume=resume_value), config=config)
        snapshot = graph.get_state(config)

    return cast(ScanState, result)


def _resolve_interrupt(
    interrupt_data: Any,
    *,
    approval_callback: Callable[[dict[str, Any]], bool] | None,
    guidance_callback: GuidanceCallback,
) -> Any:
    """Dispatch an interrupt to the appropriate callback.

    Interrupt types:
    - ``guidance`` — per-phase operator guidance; returns ``str``.
    - ``approval`` (default) — approval gate; returns ``bool``.
    """
    if isinstance(interrupt_data, dict) and interrupt_data.get("type") == "guidance":
        if guidance_callback is not None:
            return guidance_callback(interrupt_data)
        return ""  # no guidance, proceed
    if approval_callback is not None:
        return approval_callback(interrupt_data)
    return True  # auto-approve
