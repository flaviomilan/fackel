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

import json
import logging
from collections.abc import Callable
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.types import Command, interrupt

from fackel.utils import is_reverse_ptr_subdomain, is_valid_domain, is_valid_ip, sanitize_target

from .evaluator import evaluate_phase
from .state import Finding, ScanState

logger = logging.getLogger(__name__)

# Type alias for the optional event callback injected by the CLI.
EventCallback = Callable[[str, str, dict[str, Any]], None] | None

# Module-level slot — set by the CLI before invoking the graph.
_event_callback: EventCallback = None

# Maximum ReAct iterations (tool calls) per agent invocation.
MAX_AGENT_ITERATIONS = 40

# Maximum number of subdomains propagated to downstream agents.
# Reverse-PTR entries are filtered first; this cap applies afterwards.
_SUBDOMAIN_CAP = 30


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
                logger.debug(
                    "tool %s returned error: %s",
                    msg.name,
                    payload.get("error", "unknown"),
                )
            elif "tool" not in payload:
                logger.debug(
                    "tool %s returned non-standard output (missing 'tool' key)",
                    msg.name,
                )
    except (json.JSONDecodeError, TypeError, AttributeError):
        logger.debug("tool %s returned non-JSON output", msg.name)
    return msg


# ── IP extraction ─────────────────────────────────────────────────────────


def _extract_ips_from_messages(messages: list) -> list[str]:
    """Pull IP addresses out of ToolMessage payloads from all OSINT tools.

    Handles the ``format_tool_output`` envelope and extracts IPs from:
    - ``dns_resolve`` — ``data.ips``
    - ``dnsdumpster_lookup`` — ``data.hosts[*].ip``
    - ``shodan_lookup`` — ``data.ip`` (host) / ``data.matches[*].ip`` (search)
    - ``censys_lookup`` — ``data.hosts[*].ip``
    """
    ips: list[str] = []

    def _add(value: object) -> None:
        ip_str = str(value).strip()
        if ip_str and ip_str not in ips and is_valid_ip(ip_str):
            ips.append(ip_str)

    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        try:
            payload = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
            if not isinstance(payload, dict):
                continue

            # Unwrap format_tool_output envelope → data dict
            inner = payload.get("data", payload)
            if not isinstance(inner, dict):
                continue

            # dns_resolve: {"ips": ["1.2.3.4", ...]}
            for ip in inner.get("ips", []):
                _add(ip)

            # dnsdumpster_lookup: {"hosts": [{"hostname": ..., "ip": "1.2.3.4"}, ...]}
            for host in inner.get("hosts", []):
                if isinstance(host, dict) and "ip" in host:
                    _add(host["ip"])

            # shodan_lookup (host mode): {"ip": "1.2.3.4", ...}
            if "ip" in inner and isinstance(inner["ip"], str):
                _add(inner["ip"])

            # shodan_lookup (search mode): {"matches": [{"ip": "1.2.3.4"}, ...]}
            for match in inner.get("matches", []):
                if isinstance(match, dict) and "ip" in match:
                    _add(match["ip"])
        except (json.JSONDecodeError, TypeError, AttributeError):
            continue
    return ips


# ── Subdomain extraction ──────────────────────────────────────────────────


def _extract_subdomains_from_messages(messages: list, base_domain: str) -> list[str]:
    """Pull subdomain hostnames from ToolMessage payloads.

    Extracts from:
    - ``crtsh_subdomain_enum`` / ``virustotal_subdomain_enum`` / ``subfinder_enum`` — ``data.subdomains``
    - ``dnsdumpster_lookup`` — ``data.hosts[*].hostname``
    - ``subfinder_enum`` — ``data.details[*].subdomain`` (fallback)

    Filters out reverse-PTR-style subdomains (e.g. ``200-210-75-128.example.com``)
    that inflate the list without adding real scan value.
    """
    subs: list[str] = []
    base_lower = base_domain.lower()

    def _add(value: object) -> None:
        host = str(value).strip().lower().rstrip(".")
        if (
            host
            and host not in subs
            and host != base_lower
            and host.endswith(f".{base_lower}")
            and is_valid_domain(host)
            and not is_reverse_ptr_subdomain(host)
        ):
            subs.append(host)

    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        try:
            payload = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
            if not isinstance(payload, dict):
                continue

            inner = payload.get("data", payload)
            if not isinstance(inner, dict):
                continue

            # crtsh / virustotal / subfinder: {"subdomains": ["a.example.com", ...]}
            for sub in inner.get("subdomains", []):
                _add(sub)

            # dnsdumpster: {"hosts": [{"hostname": "sub.example.com", ...}, ...]}
            for host in inner.get("hosts", []):
                if isinstance(host, dict) and "hostname" in host:
                    _add(host["hostname"])

            # subfinder details fallback: {"details": [{"subdomain": "x.example.com"}, ...]}
            for detail in inner.get("details", []):
                if isinstance(detail, dict) and "subdomain" in detail:
                    _add(detail["subdomain"])
        except (json.JSONDecodeError, TypeError, AttributeError):
            continue
    return sorted(subs)


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
                    # Distinguish tool errors from successful results.
                    _is_error = False
                    _error_hint = ""
                    try:
                        _pl = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
                        if isinstance(_pl, dict) and _pl.get("status") == "error":
                            _is_error = True
                            _error_hint = str(_pl.get("error", "unknown"))
                    except (json.JSONDecodeError, TypeError, AttributeError):
                        pass

                    if _is_error:
                        _emit(phase, "tool_error", {
                            "tool": msg.name,
                            "error": _error_hint,
                        })
                    else:
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


def _get_phase_evaluation(state: ScanState, phase: str) -> dict | None:
    """Retrieve the latest LLM-as-a-judge evaluation for *phase* from state."""
    for evaluation in reversed(state.get("phase_evaluations", [])):
        if isinstance(evaluation, dict) and evaluation.get("phase") == phase:
            return evaluation
    return None


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
    if not ips and is_valid_ip(target):
        ips = [target]

    subdomains = (
        _extract_subdomains_from_messages(messages, target)
        if is_valid_domain(target)
        else []
    )

    summary = _agent_summary(messages)
    _emit("osint", "summary", {"content": summary})
    _emit("osint", "done", {})
    return {
        "discovered_ips": ips,
        "discovered_subdomains": subdomains,
        "findings": [_make_finding("osint", "OSINT Findings", summary)],
    }


def port_scan_node(state: ScanState) -> dict:
    """Run the port-scan ReAct agent on discovered IPs and subdomains."""
    from fackel.agents.port_scan.agent import build

    target = state["target"]
    ips = [ip for ip in state.get("discovered_ips", []) if ":" not in ip]
    subdomains = state.get("discovered_subdomains", [])

    if not ips and not subdomains:
        return {"findings": [_make_finding(
            "port_scan", "Port Scan", "No IPv4 targets available.",
            severity="info",
        )]}

    capped_subs = subdomains[:_SUBDOMAIN_CAP]
    skipped = len(subdomains) - len(capped_subs)

    parts = ["Scan the following targets for open ports and services."]
    parts.append(f"\nMain domain: {target}")
    if ips:
        parts.append(f"IPv4 addresses: {', '.join(ips)}")
    if capped_subs:
        parts.append(f"Discovered subdomains ({len(capped_subs)}): {', '.join(capped_subs)}")
    if skipped:
        parts.append(f"({skipped} additional subdomains omitted — focus on the above.)")
    parts.append(
        "\nStrategy: scan the IPs first (naabu → nmap). Then scan only "
        "subdomains that might resolve to DIFFERENT IPs than those already "
        "scanned. Skip subdomains that point to the same IP — the IP scan "
        "already covers them."
    )

    agent = build()
    messages = _run_and_stream_agent(agent, "port_scan", "\n".join(parts))

    summary = _agent_summary(messages)
    _emit("port_scan", "summary", {"content": summary})

    # ── LLM-as-a-judge quality evaluation ──
    scan_targets = ips + capped_subs
    evaluation = evaluate_phase("port_scan", summary, scan_targets)
    _emit("port_scan", "evaluation", {
        "score": evaluation.score,
        "completeness": evaluation.completeness,
        "recommendation": evaluation.recommendation,
    })

    _emit("port_scan", "done", {})
    return {
        "findings": [_make_finding("port_scan", "Port Scan Findings", summary)],
        "phase_evaluations": [evaluation.model_dump()],
    }


def report_node(state: ScanState) -> dict:
    """Generate the final pentest report via LLM."""
    from fackel.agents.report.agent import generate_report

    _emit("report", "start", {})
    report = generate_report(
        target=state["target"],
        active_scan=state["active_scan"],
        findings=state.get("findings", []),
        unassessed_areas=state.get("unassessed_areas", []),
        phase_evaluations=state.get("phase_evaluations", []),
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
    subdomains = state.get("discovered_subdomains", [])
    target = state["target"]

    _emit("approval", "start", {})

    summary_lines = [f"OSINT found {len(ips)} IP(s) for {target}: {', '.join(ips)}."]
    if subdomains:
        summary_lines.append(f"Subdomains ({len(subdomains)}): {', '.join(subdomains)}.")
    summary_lines.append("Proceed with active scanning (port scan + vuln scan)?")

    approved = interrupt({
        "question": "\n".join(summary_lines),
        "targets": ips,
        "subdomains": subdomains,
    })

    _emit("approval", "done", {"approved": approved})

    if approved:
        return Command(goto="port_scan")
    return Command(goto="report")


def vuln_scan_node(state: ScanState) -> dict:
    """Run the vuln-scan ReAct agent on the target domain, subdomains, and IPs."""
    from fackel.agents.vuln_scan.agent import build

    target = state["target"]
    ips = [ip for ip in state.get("discovered_ips", []) if ":" not in ip]
    subdomains = state.get("discovered_subdomains", [])

    capped_subs = subdomains[:_SUBDOMAIN_CAP]
    skipped = len(subdomains) - len(capped_subs)

    parts = ["Run vulnerability scans on the target."]
    parts.append(f"\nOriginal target domain: {target}")
    if capped_subs:
        parts.append(f"Discovered subdomains ({len(capped_subs)}): {', '.join(capped_subs)}")
    if skipped:
        parts.append(f"({skipped} additional subdomains omitted — focus on the above.)")
    if ips:
        parts.append(f"Discovered IPv4 addresses: {', '.join(ips)}")
    else:
        parts.append("No IPv4 addresses were discovered.")

    # ── Adapt strategy from port_scan evaluation ──
    port_eval = _get_phase_evaluation(state, "port_scan")
    if port_eval:
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
                gaps_str = "; ".join(eval_gaps)
                parts.append(f"\n⚠ Port scan gaps: {gaps_str}")
            parts.append(
                "\nPort scan was partial. Prioritise domain-level nuclei "
                "and httpx. Run IP-specific checks only if ports were found "
                "on that IP."
            )
        else:  # complete
            parts.append(
                "\nScan the DOMAIN first (nuclei with empty severity for full "
                "template coverage). Then scan the most interesting subdomains "
                "(www, web apps, APIs, panels). Then per-IP checks. Prioritise "
                "breadth — it's better to scan more targets shallowly than "
                "fewer targets deeply."
            )
    else:
        parts.append(
            "\nScan the DOMAIN first (nuclei with empty severity for full template "
            "coverage). Then scan the most interesting subdomains (www, web apps, "
            "APIs, panels). Then per-IP checks. Prioritise breadth — it's better "
            "to scan more targets shallowly than fewer targets deeply."
        )

    agent = build()
    messages = _run_and_stream_agent(agent, "vuln_scan", "\n".join(parts))

    summary = _agent_summary(messages)
    _emit("vuln_scan", "summary", {"content": summary})

    # ── LLM-as-a-judge quality evaluation ──
    scan_targets = [target] + capped_subs + ips
    evaluation = evaluate_phase("vuln_scan", summary, scan_targets)
    _emit("vuln_scan", "evaluation", {
        "score": evaluation.score,
        "completeness": evaluation.completeness,
        "recommendation": evaluation.recommendation,
    })

    _emit("vuln_scan", "done", {})
    return {
        "findings": [_make_finding("vuln_scan", "Vulnerability Scan Findings", summary)],
        "phase_evaluations": [evaluation.model_dump()],
    }


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
    if not state.get("active_scan"):
        return "report"
    ipv4 = [ip for ip in state.get("discovered_ips", []) if ":" not in ip]
    has_scan_targets = bool(ipv4) or bool(state.get("discovered_subdomains"))
    return "approval_gate" if has_scan_targets else "report"


def route_after_port_scan(state: ScanState) -> str:
    """Route after port scan: vuln_scan normally, or skip to triage if empty.

    Uses the LLM-as-a-judge evaluation stored in state by ``port_scan_node``.
    Only skips to triage when the judge explicitly recommends it — default
    is to proceed to vuln_scan (which can still find domain-level issues).
    """
    port_eval = _get_phase_evaluation(state, "port_scan")
    if port_eval and port_eval.get("recommendation") == "skip_downstream":
        logger.info("routing: port_scan judge recommends skip → triage")
        return "triage"
    return "vuln_scan"
