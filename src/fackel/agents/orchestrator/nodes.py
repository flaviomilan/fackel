"""Orchestrator graph nodes — thin wrappers that stream specialist ReAct agents.

Each node invokes its specialist agent via ``.stream()`` so that every
ReAct reasoning step (think → tool call → observe) can be surfaced to
the CLI in real-time.  Results are collected and returned as a partial
``ScanState`` update.

Architecture layers (per recommendation):
- **Input sanitiser** validates targets before they reach tools.
- **Output validator** checks tool results for structural correctness.
- **Max-iterations** guard prevents runaway ReAct loops.
- **Structured findings** — nodes always emit ``Finding`` dicts, never raw text.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.types import Command, interrupt

from .state import Finding, ScanState

logger = logging.getLogger(__name__)

# Type alias for the optional event callback injected by the CLI.
EventCallback = Callable[[str, str, dict[str, Any]], None] | None

# Module-level slot — set by the CLI before invoking the graph.
_event_callback: EventCallback = None

# Maximum ReAct iterations (tool calls) per agent invocation.
MAX_AGENT_ITERATIONS = 15


def set_event_callback(cb: EventCallback) -> None:
    """Set the callback that receives real-time ReAct events."""
    global _event_callback  # noqa: PLW0603
    _event_callback = cb


# ── Helpers ────────────────────────────────────────────────────────────────


def _emit(phase: str, event_type: str, data: dict[str, Any]) -> None:
    """Notify the event callback if set."""
    if _event_callback is not None:
        _event_callback(phase, event_type, data)


def _make_finding(
    phase: str,
    title: str,
    detail: str,
    *,
    severity: str = "info",
    source_tool: str = "",
    confidence: float = 1.0,
) -> Finding:
    """Build a typed Finding dict."""
    return Finding(
        phase=phase,
        title=title,
        detail=detail,
        severity=severity,
        source_tool=source_tool,
        confidence=confidence,
    )


# ── Input validation ──────────────────────────────────────────────────────

_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)


def _is_valid_ip(value: str) -> bool:
    """Return True if *value* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _is_valid_domain(value: str) -> bool:
    """Return True if *value* looks like a valid domain name."""
    return bool(_DOMAIN_RE.match(value.strip()))


def sanitize_target(raw: str) -> str:
    """Normalise and validate a user-supplied target string.

    Strips scheme/path from URLs, rejects shell metacharacters,
    and ensures the result is a valid IP or domain.

    Raises
    ------
    ValueError
        If the target is empty, contains dangerous characters, or
        is neither a valid IP nor a valid domain.
    """
    if not raw or not raw.strip():
        raise ValueError("Target is empty.")

    raw = raw.strip()

    # Strip URL scheme / path if present.
    parsed = urlparse(raw)
    host = parsed.hostname or parsed.netloc or parsed.path.split("/")[0] or raw
    host = host.strip().rstrip(".")

    # Block shell metacharacters (prevent injection via subprocess tools).
    if re.search(r"[;&|`$(){}!\[\]<>'\"\\\n\r]", host):
        raise ValueError(f"Target contains forbidden characters: {host!r}")

    if _is_valid_ip(host) or _is_valid_domain(host):
        return host

    raise ValueError(f"Target is not a valid IP or domain: {host!r}")


# ── Tool output validation ────────────────────────────────────────────────


def _validate_tool_output(msg: ToolMessage) -> ToolMessage:
    """Basic structural validation of tool results.

    Ensures the tool returned our standard envelope (``tool``, ``status``).
    Logs warnings for malformed or error outputs without blocking the agent.
    """
    try:
        payload = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
        if isinstance(payload, dict):
            status = payload.get("status")
            if status == "error":
                logger.warning(
                    "tool %s returned error: %s",
                    msg.name,
                    payload.get("error", "unknown"),
                )
            elif "tool" not in payload:
                logger.warning(
                    "tool %s returned non-standard output (missing 'tool' key)",
                    msg.name,
                )
    except (json.JSONDecodeError, TypeError, AttributeError):
        logger.warning("tool %s returned non-JSON output", msg.name)
    return msg


# ── IP extraction ─────────────────────────────────────────────────────────


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
    """Stream a ReAct agent and emit events, returning all collected messages.

    Enforces ``MAX_AGENT_ITERATIONS`` — if the agent calls more tools than
    the limit, streaming stops to prevent runaway loops.
    """
    all_messages: list = []
    tool_call_count = 0
    _emit(phase, "start", {})

    for event in agent.stream(
        {"messages": [HumanMessage(content=user_message)]},
        stream_mode="updates",
    ):
        for node_name, data in event.items():
            for msg in data.get("messages", []):

                # ── Output validation on tool results ──
                if isinstance(msg, ToolMessage):
                    msg = _validate_tool_output(msg)

                all_messages.append(msg)

                if isinstance(msg, AIMessage):
                    tool_calls = getattr(msg, "tool_calls", None)
                    if tool_calls:
                        for tc in tool_calls:
                            tool_call_count += 1
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

        # ── Max-iterations guard ──
        if tool_call_count >= MAX_AGENT_ITERATIONS:
            logger.warning(
                "%s: hit max iterations (%d tool calls) — stopping agent",
                phase, MAX_AGENT_ITERATIONS,
            )
            _emit(phase, "reasoning", {
                "content": f"⚠ Agent stopped: reached {MAX_AGENT_ITERATIONS} tool call limit.",
            })
            break

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

    target = sanitize_target(state["target"])
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
        "findings": [_make_finding("osint", "OSINT Findings", summary)],
    }


def port_scan_node(state: ScanState) -> dict:
    """Run the port-scan ReAct agent on discovered IPs."""
    from fackel.agents.port_scan.agent import build

    ips = [ip for ip in state.get("discovered_ips", []) if ":" not in ip]
    if not ips:
        return {"findings": [_make_finding(
            "port_scan", "Port Scan", "No IPv4 targets available.",
            severity="info",
        )]}

    ip_list = ", ".join(ips)
    agent = build()
    messages = _run_and_stream_agent(
        agent, "port_scan", f"Scan these IPs for open ports and services: {ip_list}"
    )

    summary = _agent_summary(messages)
    _emit("port_scan", "summary", {"content": summary})
    _emit("port_scan", "done", {})
    return {"findings": [_make_finding("port_scan", "Port Scan Findings", summary)]}


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
    return {"findings": [_make_finding("vuln_scan", "Vulnerability Scan Findings", summary)]}


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

    triage_detail = "\n".join(summary_parts)

    _emit("triage", "summary", {"content": triage_detail})
    _emit("triage", "done", {
        "technologies": result.technologies_detected,
        "unassessed_count": len(unassessed),
    })

    return {
        "findings": [_make_finding("triage", "Triage Summary", triage_detail)],
        "unassessed_areas": unassessed,
    }


# ── Routing ────────────────────────────────────────────────────────────────


def route_after_osint(state: ScanState) -> str:
    """Decide next step: approval gate (active) or straight to report (passive)."""
    if state.get("active_scan") and state.get("discovered_ips"):
        return "approval_gate"
    return "report"
