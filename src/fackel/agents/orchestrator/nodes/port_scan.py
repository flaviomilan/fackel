"""Port-scan graph node — active port discovery with IP classification context."""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.runnables import RunnableConfig

from fackel.prompts import load_section

from .. import evaluator, streaming
from ..state import ScanState
from ..streaming import agent_summary, is_tool_approval_enabled, run_and_stream_agent
from ._helpers import (
    IP_CLASS_HINTS,
    SUBDOMAIN_CAP,
    emit_evaluation,
    make_finding,
    prepare_scan_targets,
)

logger = logging.getLogger(__name__)

# Loaded once and cached — supplies node-level prompt context.
_ENUMERATION_GUIDANCE: str | None = None
_PIVOT_PRIORITY_GUIDANCE: str | None = None


def _load_port_scan_guidance() -> tuple[str, str]:
    """Lazy-load stage and orchestrator prompt sections for port scanning."""
    global _ENUMERATION_GUIDANCE, _PIVOT_PRIORITY_GUIDANCE  # noqa: PLW0603
    if _ENUMERATION_GUIDANCE is None:
        _ENUMERATION_GUIDANCE = load_section("stages/enumeration")
        _PIVOT_PRIORITY_GUIDANCE = load_section("orchestrator/pivot_priority")
    return _ENUMERATION_GUIDANCE, _PIVOT_PRIORITY_GUIDANCE  # type: ignore[return-value]


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

    parts = ["Scan the following targets for open ports and services."]
    parts.append(f"\nMain domain: {target}")
    if ips:
        parts.append(f"IPv4 addresses: {', '.join(ips)}")
    if capped_subs:
        parts.append(f"Discovered subdomains ({len(capped_subs)}): {', '.join(capped_subs)}")
    if skipped:
        parts.append(f"({skipped} additional subdomains omitted — focus on the above.)")

    _append_ip_classification_context(parts, ips, state)
    parts.append(
        "\nStrategy: scan the IPs first (naabu → nmap). Then scan only "
        "subdomains that might resolve to DIFFERENT IPs than those already "
        "scanned. Skip subdomains that point to the same IP — the IP scan "
        "already covers them."
    )

    enumeration_guide, pivot_guide = _load_port_scan_guidance()
    parts.append(f"\n## Enumeration Stage Guidance\n\n{enumeration_guide}")
    parts.append(f"\n## Target Prioritisation\n\n{pivot_guide}")

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

    parts.append("\nIP infrastructure classification (from OSINT):")
    for ip in ips:
        c = ip_classes.get(ip)
        if c:
            label = c.get("ip_class", "unknown")
            org = c.get("org", "")
            parts.append(f"  - {ip}: {label} ({org}){IP_CLASS_HINTS.get(label, '')}")

    if any(c.get("ip_class") == "cdn" for c in ip_classes.values()):
        parts.append(
            "\n⚠ CDN IPs detected. Scanning CDN proxy IPs (e.g. Cloudflare) "
            "yields the CDN's ports/services, not the origin server. "
            "Prioritise direct_host and cloud IPs instead."
        )
