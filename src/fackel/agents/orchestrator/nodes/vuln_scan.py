"""Vuln-scan graph node — vulnerability scanning with tech-aware prompting."""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.runnables import RunnableConfig

from fackel.agents.prompts import load_template
from fackel.formatting import format_tech_fingerprint

from .. import evaluator, streaming
from ..state import ScanState
from ..streaming import agent_summary, is_tool_approval_enabled, run_and_stream_agent
from ._helpers import (
    SUBDOMAIN_CAP,
    emit_evaluation,
    get_phase_evaluation,
    get_phase_guidance,
    make_finding,
    prepare_scan_targets,
)

logger = logging.getLogger(__name__)


def vuln_scan_node(state: ScanState, config: RunnableConfig) -> dict[str, Any]:
    """Run the vuln-scan ReAct agent on the target domain, subdomains, and IPs."""
    from fackel.agents.vuln_scan.agent import build

    target = state["target"]
    ips, subdomains = prepare_scan_targets(state)
    capped_subs = subdomains[:SUBDOMAIN_CAP]

    prompt = _build_vuln_scan_prompt(target, ips, capped_subs, state)
    guidance = get_phase_guidance(state, "vuln_scan")
    if guidance:
        prompt += "\n\n" + load_template("guidance_suffix").format(guidance=guidance)
    agent = build(approve_tools=is_tool_approval_enabled())
    messages = run_and_stream_agent(agent, "vuln_scan", prompt, config=config)

    summary = agent_summary(messages)
    streaming.emit("vuln_scan", "summary", {"content": summary})

    scan_targets = [target, *capped_subs, *ips]
    evaluation = evaluator.evaluate_phase("vuln_scan", summary, scan_targets, config=config)
    emit_evaluation("vuln_scan", evaluation)
    streaming.emit("vuln_scan", "done", {})

    return {
        "findings": [make_finding("vuln_scan", "Vulnerability Scan Findings", summary)],
        "phase_evaluations": [evaluation.model_dump()],
    }


def _build_vuln_scan_prompt(
    target: str,
    ips: list[str],
    subdomains: list[str],
    state: ScanState,
) -> str:
    """Build the vuln-scan agent prompt with context from prior phases."""
    all_subs = state.get("discovered_subdomains", [])
    skipped = len(all_subs) - len(subdomains)

    parts = [load_template("vuln_scan_task")]
    parts.append(f"\nOriginal target domain: {target}")
    if subdomains:
        parts.append(f"Discovered subdomains ({len(subdomains)}): {', '.join(subdomains)}")
    if skipped > 0:
        parts.append(f"({skipped} additional subdomains omitted — focus on the above.)")
    if ips:
        parts.append(f"Discovered IPv4 addresses: {', '.join(ips)}")
    else:
        parts.append("No IPv4 addresses were discovered.")

    _append_tech_fingerprint_context(parts, state)
    _append_port_scan_strategy(parts, state)
    return "\n".join(parts)


def _append_tech_fingerprint_context(parts: list[str], state: ScanState) -> None:
    """Append technology fingerprint context to vuln-scan prompt."""
    tech_fps = state.get("tech_fingerprints", [])
    if not tech_fps:
        return

    parts.append("\nTechnology fingerprints (from OSINT httpx scan):")
    for fp in tech_fps[:10]:
        parts.append(f"  {format_tech_fingerprint(fp)}")

    all_techs = sorted({t for fp in tech_fps for t in fp.get("technologies", [])})
    if all_techs:
        parts.append(
            "\n" + load_template("vuln_scan_tech_hint").format(technologies=", ".join(all_techs))
        )


def _append_port_scan_strategy(parts: list[str], state: ScanState) -> None:
    """Append vulnerability scan strategy based on port-scan evaluation."""
    port_eval = get_phase_evaluation(state, "port_scan")
    if not port_eval:
        parts.append("\n" + load_template("vuln_scan_strategy"))
        return

    completeness = port_eval.get("completeness", "partial")
    if completeness == "empty":
        parts.append("\n" + load_template("vuln_scan_empty_ports"))
    elif completeness == "partial":
        eval_gaps = port_eval.get("gaps", [])
        if eval_gaps:
            parts.append(f"\n⚠ Port scan gaps: {'; '.join(eval_gaps)}")
        parts.append("\n" + load_template("vuln_scan_partial_ports"))
    else:
        parts.append("\n" + load_template("vuln_scan_strategy"))
