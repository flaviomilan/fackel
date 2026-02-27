"""Port-scan graph node — active port discovery with IP classification context."""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.runnables import RunnableConfig

from fackel.agents.prompts import load_section_map, load_template

from .. import evaluator, streaming
from ..state import ScanState
from ..streaming import agent_summary, is_tool_approval_enabled, run_and_stream_agent
from ._helpers import (
    SUBDOMAIN_CAP,
    emit_evaluation,
    get_phase_guidance,
    make_finding,
    prepare_scan_targets,
)

logger = logging.getLogger(__name__)


def port_scan_node(state: ScanState, config: RunnableConfig) -> dict[str, Any]:
    """Run the port-scan ReAct agent on discovered IPs and subdomains."""
    from fackel.agents.port_scan.agent import build

    ips, subdomains = prepare_scan_targets(state)
    if not ips and not subdomains:
        return {
            "findings": [
                make_finding(
                    "port_scan", "Port Scan", "No IPv4 targets available.", severity="info"
                )
            ]
        }

    prompt = _build_port_scan_prompt(state["target"], ips, subdomains, state)
    guidance = get_phase_guidance(state, "port_scan")
    if guidance:
        prompt += "\n\n" + load_template("guidance_suffix").format(guidance=guidance)
    agent = build(approve_tools=is_tool_approval_enabled())
    messages = run_and_stream_agent(agent, "port_scan", prompt, config=config)

    summary = agent_summary(messages)
    streaming.emit("port_scan", "summary", {"content": summary})

    scan_targets = ips + subdomains[:SUBDOMAIN_CAP]
    evaluation = evaluator.evaluate_phase("port_scan", summary, scan_targets, config=config)
    emit_evaluation("port_scan", evaluation)
    streaming.emit("port_scan", "done", {})

    return {
        "findings": [make_finding("port_scan", "Port Scan Findings", summary)],
        "phase_evaluations": [evaluation.model_dump()],
    }


def _build_port_scan_prompt(
    target: str,
    ips: list[str],
    subdomains: list[str],
    state: ScanState,
) -> str:
    """Build the port-scan agent prompt with context from OSINT."""
    capped_subs = subdomains[:SUBDOMAIN_CAP]
    skipped = len(subdomains) - len(capped_subs)

    parts = [load_template("port_scan_task")]
    parts.append(f"\nMain domain: {target}")
    if ips:
        parts.append(f"IPv4 addresses: {', '.join(ips)}")
    if capped_subs:
        parts.append(f"Discovered subdomains ({len(capped_subs)}): {', '.join(capped_subs)}")
    if skipped:
        parts.append(f"({skipped} additional subdomains omitted — focus on the above.)")

    _append_ip_classification_context(parts, ips, state)
    parts.append("\n" + load_template("port_scan_strategy"))
    return "\n".join(parts)


def _append_ip_classification_context(
    parts: list[str],
    ips: list[str],
    state: ScanState,
) -> None:
    """Append IP infrastructure classification hints to prompt parts."""
    ip_classes = {c["ip"]: c for c in state.get("ip_classifications", []) if c.get("ip") in ips}
    if not ip_classes:
        return

    ip_hints = load_section_map("ip_class_hints")
    parts.append("\nIP infrastructure classification (from OSINT):")
    for ip in ips:
        c = ip_classes.get(ip)
        if c:
            label = c.get("ip_class", "unknown")
            org = c.get("org", "")
            parts.append(f"  - {ip}: {label} ({org}){ip_hints.get(label, '')}")

    if any(c.get("ip_class") == "cdn" for c in ip_classes.values()):
        parts.append("\n" + load_template("cdn_warning"))
