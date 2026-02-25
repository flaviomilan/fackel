"""Vuln-scan graph node — vulnerability scanning with tech-aware prompting."""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.runnables import RunnableConfig

from fackel.formatting import format_tech_fingerprint

from .. import evaluator, streaming
from ..state import ScanState
from ..streaming import agent_summary, is_tool_approval_enabled, run_and_stream_agent
from ._helpers import (
    DEFAULT_VULN_SCAN_STRATEGY,
    SUBDOMAIN_CAP,
    emit_evaluation,
    get_phase_evaluation,
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

    parts = ["Run vulnerability scans on the target."]
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
            f"\nDetected technologies: {', '.join(all_techs)}. "
            "Prioritise nuclei templates targeting these specific "
            "technologies for higher-value findings."
        )


def _append_port_scan_strategy(parts: list[str], state: ScanState) -> None:
    """Append vulnerability scan strategy based on port-scan evaluation."""
    port_eval = get_phase_evaluation(state, "port_scan")
    if not port_eval:
        parts.append(DEFAULT_VULN_SCAN_STRATEGY)
        return

    completeness = port_eval.get("completeness", "partial")
    if completeness == "empty":
        parts.append(
            "\n⚠ PORT SCAN FOUND NO OPEN PORTS. Focus entirely on "
            "domain-level checks: nuclei templates (DNS, SSL, HTTP), "
            "wafw00f, httpx, and katana on the domain and subdomains. "
            "Do NOT waste iterations on IP-specific scans."
        )
    elif completeness == "partial":
        eval_gaps = port_eval.get("gaps", [])
        if eval_gaps:
            parts.append(f"\n⚠ Port scan gaps: {'; '.join(eval_gaps)}")
        parts.append(
            "\nPort scan was partial. Prioritise domain-level nuclei "
            "and httpx. Run IP-specific checks only if ports were found "
            "on that IP."
        )
    else:
        parts.append(DEFAULT_VULN_SCAN_STRATEGY)
