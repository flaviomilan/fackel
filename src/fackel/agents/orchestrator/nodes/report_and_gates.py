"""Report graph node and approval gate with routing functions."""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.runnables import RunnableConfig
from langgraph.types import Command, interrupt

from fackel.formatting import is_ipv6

from .. import streaming
from ..state import ScanState
from ._helpers import get_phase_evaluation, make_finding

logger = logging.getLogger(__name__)


def report_node(state: ScanState, config: RunnableConfig) -> dict[str, Any]:
    """Generate the final pentest report via LLM."""
    from fackel.agents.report.agent import generate_report

    streaming.emit("report", "start", {})
    report = generate_report(
        target=state["target"],
        active_scan=state["active_scan"],
        findings=state.get("findings", []),  # type: ignore[arg-type]
        unassessed_areas=state.get("unassessed_areas", []),
        phase_evaluations=state.get("phase_evaluations", []),
        risk_score=state.get("risk_score"),
        config=config,
    )
    streaming.emit("report", "done", {})
    return {"report": report}


def approval_gate(state: ScanState) -> Command:  # type: ignore[type-arg]
    """Pause for human approval before active scanning.

    Uses LangGraph ``interrupt()`` to suspend execution.  The CLI (or API)
    resumes the graph with ``Command(resume=True/False)`` to approve or
    reject.
    """
    ips = state.get("discovered_ips", [])
    subdomains = state.get("discovered_subdomains", [])
    target = state["target"]

    streaming.emit("approval", "start", {})

    summary_lines = [f"OSINT found {len(ips)} IP(s) for {target}: {', '.join(ips)}."]
    ip_classes = {c["ip"]: c for c in state.get("ip_classifications", [])}
    if ip_classes:
        for ip in ips:
            c = ip_classes.get(ip)
            if c:
                summary_lines.append(
                    f"  {ip}: {c.get('ip_class', '?')} ({c.get('org', 'unknown')})"
                )
    if subdomains:
        summary_lines.append(f"Subdomains ({len(subdomains)}): {', '.join(subdomains)}.")
    summary_lines.append("Proceed with active scanning (port scan + vuln scan)?")

    approved = interrupt(
        {
            "question": "\n".join(summary_lines),
            "targets": ips,
            "subdomains": subdomains,
        }
    )

    streaming.emit("approval", "done", {"approved": approved})

    if approved:
        return Command(goto="port_scan")
    return Command(
        goto="report",
        update={
            "findings": [
                make_finding(
                    "approval",
                    "Active Scan Rejected",
                    "Operator declined active scanning at the approval gate. "
                    "Report generated from passive OSINT data only.",
                )
            ],
        },
    )


def route_after_osint(state: ScanState) -> str:
    """Decide next step: approval gate (active) or straight to report (passive)."""
    if not state.get("active_scan"):
        return "report"
    all_ips = state.get("discovered_ips", [])
    ipv4 = [ip for ip in all_ips if not is_ipv6(ip)]
    dropped = len(all_ips) - len(ipv4)
    if dropped:
        logger.info("route_after_osint: dropping %d IPv6 address(es) — not yet supported", dropped)
    has_scan_targets = bool(ipv4) or bool(state.get("discovered_subdomains"))
    return "approval_gate" if has_scan_targets else "report"


def route_after_port_scan(state: ScanState) -> str:
    """Route after port scan: vuln_scan normally, or skip to triage if empty.

    Uses the LLM-as-a-judge evaluation stored in state by ``port_scan_node``.
    Only skips to triage when the judge explicitly recommends it — default
    is to proceed to vuln_scan (which can still find domain-level issues).
    """
    port_eval = get_phase_evaluation(state, "port_scan")
    if port_eval and port_eval.get("recommendation") == "skip_downstream":
        logger.info("routing: port_scan judge recommends skip → triage")
        return "triage"
    return "vuln_scan"
