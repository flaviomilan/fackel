"""Orchestrator graph nodes — thin wrappers that stream specialist ReAct agents.

Each node invokes its specialist agent via ``.stream()`` so that every
ReAct reasoning step (think → tool call → observe) can be surfaced to
the CLI in real-time.  Results are collected and returned as a partial
``ScanState`` update.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from collections.abc import Callable
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.types import Command, interrupt

from .state import ScanState

logger = logging.getLogger(__name__)

# Type alias for the optional event callback injected by the CLI.
EventCallback = Callable[[str, str, dict[str, Any]], None] | None

# Module-level slot — set by the CLI before invoking the graph.
_event_callback: EventCallback = None


def set_event_callback(cb: EventCallback) -> None:
    """Set the callback that receives real-time ReAct events."""
    global _event_callback  # noqa: PLW0603
    _event_callback = cb


# ── Helpers ────────────────────────────────────────────────────────────────


def _emit(phase: str, event_type: str, data: dict[str, Any]) -> None:
    """Notify the event callback if set."""
    if _event_callback is not None:
        _event_callback(phase, event_type, data)


def _extract_ips_from_messages(messages: list) -> list[str]:
    """Pull IP addresses out of ToolMessage payloads returned by dns_resolve.

    Handles both the ``format_tool_output`` envelope (``data.ips``) and
    legacy flat format (``ips``).
    """
    ips: list[str] = []
    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        try:
            payload = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
            # format_tool_output envelope: {"data": {"ips": [...]}}
            inner = payload.get("data", payload) if isinstance(payload, dict) else payload
            for ip in (inner.get("ips", []) if isinstance(inner, dict) else []):
                ip_str = str(ip).strip()
                if ip_str and ip_str not in ips:
                    ips.append(ip_str)
        except (json.JSONDecodeError, TypeError, AttributeError):
            continue
    return ips


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _run_and_stream_agent(agent, phase: str, user_message: str) -> list:
    """Stream a ReAct agent and emit events, returning all collected messages."""
    all_messages: list = []
    _emit(phase, "start", {})

    for event in agent.stream(
        {"messages": [HumanMessage(content=user_message)]},
        stream_mode="updates",
    ):
        for node_name, data in event.items():
            for msg in data.get("messages", []):
                all_messages.append(msg)

                if isinstance(msg, AIMessage):
                    tool_calls = getattr(msg, "tool_calls", None)
                    if tool_calls:
                        for tc in tool_calls:
                            _emit(phase, "tool_call", {
                                "tool": tc["name"],
                                "args": tc.get("args", {}),
                            })
                    elif msg.content:
                        _emit(phase, "reasoning", {"content": msg.content})

                elif isinstance(msg, ToolMessage):
                    _emit(phase, "tool_result", {
                        "tool": msg.name,
                        "content": str(msg.content)[:500],
                    })

    return all_messages


def _agent_summary(messages: list) -> str:
    """Return the last AI message content, or a fallback."""
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and msg.content and msg.content.strip():
            if not getattr(msg, "tool_calls", None):
                return msg.content.strip()
    return "No findings."


# ── Nodes ──────────────────────────────────────────────────────────────────


def osint_node(state: ScanState) -> dict:
    """Run the OSINT ReAct agent for passive reconnaissance."""
    from fackel.agents.osint.agent import build

    target = state["target"]
    agent = build()
    messages = _run_and_stream_agent(
        agent, "osint", f"Perform passive OSINT reconnaissance on: {target}"
    )

    ips = _extract_ips_from_messages(messages)
    if not ips and _is_ip(target):
        ips = [target]

    summary = _agent_summary(messages)
    _emit("osint", "summary", {"content": summary})
    _emit("osint", "done", {})
    return {
        "discovered_ips": ips,
        "findings": [f"## OSINT Findings\n\n{summary}"],
    }


def port_scan_node(state: ScanState) -> dict:
    """Run the port-scan ReAct agent on discovered IPs."""
    from fackel.agents.port_scan.agent import build

    ips = [ip for ip in state.get("discovered_ips", []) if ":" not in ip]
    if not ips:
        return {"findings": ["## Port Scan\n\nNo IPv4 targets available."]}

    ip_list = ", ".join(ips)
    agent = build()
    messages = _run_and_stream_agent(
        agent, "port_scan", f"Scan these IPs for open ports and services: {ip_list}"
    )

    summary = _agent_summary(messages)
    _emit("port_scan", "summary", {"content": summary})
    _emit("port_scan", "done", {})
    return {"findings": [f"## Port Scan Findings\n\n{summary}"]}


def report_node(state: ScanState) -> dict:
    """Generate the final pentest report via LLM."""
    from fackel.agents.report.agent import generate_report

    _emit("report", "start", {})
    report = generate_report(
        target=state["target"],
        active_scan=state["active_scan"],
        findings=state.get("findings", []),
        unassessed_areas=state.get("unassessed_areas", []),
    )
    _emit("report", "done", {})
    return {"report": report}


def approval_gate(state: ScanState) -> Command:
    """Pause for human approval before active scanning.

    Uses LangGraph ``interrupt()`` to suspend execution.  The CLI (or API)
    resumes the graph with ``Command(resume=True/False)`` to approve or
    reject.
    """
    ips = state.get("discovered_ips", [])
    target = state["target"]

    _emit("approval", "start", {})

    approved = interrupt({
        "question": (
            f"OSINT found {len(ips)} IP(s) for {target}: {', '.join(ips)}.\n"
            "Proceed with active scanning (port scan + vuln scan)?"
        ),
        "targets": ips,
    })

    _emit("approval", "done", {"approved": approved})

    if approved:
        return Command(goto="port_scan")
    return Command(goto="report")


def vuln_scan_node(state: ScanState) -> dict:
    """Run the vuln-scan ReAct agent on the target domain and discovered IPs."""
    from fackel.agents.vuln_scan.agent import build

    target = state["target"]
    ips = [ip for ip in state.get("discovered_ips", []) if ":" not in ip]

    parts = ["Run vulnerability scans on the target."]
    parts.append(f"\nOriginal target domain: {target}")
    if ips:
        parts.append(f"Discovered IPv4 addresses: {', '.join(ips)}")
    else:
        parts.append("No IPv4 addresses were discovered.")
    parts.append(
        "\nScan the DOMAIN first (DNS/SSL/HTTP templates need the hostname), "
        "then scan individual IPs for port-specific checks."
    )

    agent = build()
    messages = _run_and_stream_agent(agent, "vuln_scan", "\n".join(parts))

    summary = _agent_summary(messages)
    _emit("vuln_scan", "summary", {"content": summary})
    _emit("vuln_scan", "done", {})
    return {"findings": [f"## Vulnerability Scan Findings\n\n{summary}"]}


def triage_node(state: ScanState) -> dict:
    """Analyse findings and identify unassessed areas via structured LLM output."""
    from fackel.agents.triage.agent import run_triage

    _emit("triage", "start", {})

    findings = state.get("findings", [])
    result = run_triage(findings)

    unassessed = [
        {
            "technology": area.technology,
            "detected_by": area.detected_by,
            "reason": area.reason,
            "recommendation": area.recommendation,
        }
        for area in result.unassessed_areas
    ]

    summary_parts = [f"## Triage Summary\n\n{result.summary}"]
    if result.technologies_detected:
        techs = ", ".join(result.technologies_detected)
        summary_parts.append(f"\n**Technologies detected:** {techs}")
    if unassessed:
        names = ", ".join(a["technology"] for a in unassessed)
        summary_parts.append(f"\n**Unassessed areas:** {names}")

    _emit("triage", "summary", {"content": "\n".join(summary_parts)})
    _emit("triage", "done", {
        "technologies": result.technologies_detected,
        "unassessed_count": len(unassessed),
    })

    return {
        "findings": ["\n".join(summary_parts)],
        "unassessed_areas": unassessed,
    }


# ── Routing ────────────────────────────────────────────────────────────────


def route_after_osint(state: ScanState) -> str:
    """Decide next step: approval gate (active) or straight to report (passive)."""
    if state.get("active_scan") and state.get("discovered_ips"):
        return "approval_gate"
    return "report"
