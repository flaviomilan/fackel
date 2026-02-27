"""Per-phase guidance gates — optional operator steering before agent runs.

Each gate uses ``interrupt()`` to pause the graph and collect free-text
instructions from the operator.  When guidance is disabled (the default),
the nodes return immediately without interrupting.

Guidance text is stored in ``phase_guidance[phase]`` and injected into
the agent prompt by the corresponding phase node.
"""

from __future__ import annotations

from typing import Any

from langgraph.types import interrupt

from fackel.agents.prompts import load_section_map

from ..state import ScanState
from ..streaming import emit, is_guidance_enabled


def _guidance_gate(phase: str, state: ScanState) -> dict[str, Any]:
    """Collect optional operator guidance for *phase*.

    When guidance is disabled, returns immediately without interrupting.
    When enabled, pauses with ``interrupt()`` and stores the operator's
    text in ``phase_guidance``.
    """
    if not is_guidance_enabled():
        return {}

    description = load_section_map("phase_descriptions").get(phase, "")
    emit(phase, "guidance_request", {"description": description})

    guidance = interrupt(
        {
            "type": "guidance",
            "phase": phase,
            "description": description,
        }
    )

    current = dict(state.get("phase_guidance") or {})
    text = str(guidance).strip() if guidance else ""
    if text:
        current[phase] = text
        emit(phase, "guidance_received", {"guidance": text})
    return {"phase_guidance": current}


def osint_guidance(state: ScanState) -> dict[str, Any]:
    """Collect optional operator guidance before OSINT reconnaissance."""
    return _guidance_gate("osint", state)


def port_scan_guidance(state: ScanState) -> dict[str, Any]:
    """Collect optional operator guidance before port scanning."""
    return _guidance_gate("port_scan", state)


def vuln_scan_guidance(state: ScanState) -> dict[str, Any]:
    """Collect optional operator guidance before vulnerability scanning."""
    return _guidance_gate("vuln_scan", state)
