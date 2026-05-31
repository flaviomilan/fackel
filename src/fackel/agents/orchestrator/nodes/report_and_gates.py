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
    """Generate the final pentest report via LLM, grounded in the knowledge graph."""
    from fackel.agents.report.agent import generate_report
    from fackel.agents.report.report_data import build_asset_inventory_md, build_report_context
    from fackel.agents.report.verification import build_verification_md, verify_findings
    from fackel.persistence import get_current_store

    streaming.emit("report", "start", {})

    # Source the report from the structured store (all tool output, deduplicated
    # and confidence-scored) instead of only the lossy agent summaries.  No-op
    # when no store is bound (e.g. unit tests bypassing orchestrator.run).
    store = get_current_store()
    graph_context = build_report_context(store) if store is not None else ""
    asset_inventory = build_asset_inventory_md(store) if store is not None else ""

    # Corroborate findings before writing: append a deterministic verification
    # section so the report distinguishes verified facts from single-source ones
    # and flags high-impact uncorroborated findings for manual confirmation.
    if store is not None and graph_context:
        summary = verify_findings(store)
        streaming.emit(
            "report",
            "verification",
            {
                "verified": summary.verified,
                "unverified": summary.unverified,
                "flagged": len(summary.flagged),
            },
        )
        verification_md = build_verification_md(summary)
        if verification_md:
            graph_context = f"{graph_context}\n\n{verification_md}"

    report = generate_report(
        target=state["target"],
        active_scan=state["active_scan"],
        findings=state.get("findings", []),  # type: ignore[arg-type]
        unassessed_areas=state.get("unassessed_areas", []),
        phase_evaluations=state.get("phase_evaluations", []),
        risk_score=state.get("risk_score"),
        graph_context=graph_context or None,
        config=config,
    )
    streaming.emit("report", "done", {})
    return {"report": report, "asset_inventory": asset_inventory}


def review_node(state: ScanState, config: RunnableConfig) -> dict[str, Any]:
    """QA-review the draft report against the knowledge graph.

    Verifies the draft covers every high-value finding (vulnerabilities,
    credential leaks, high-confidence assets), incorporates any that are
    missing, and appends a computed coverage footer.  No-op without a bound
    store or an empty draft (so tests / passive runs are unaffected).
    """
    from fackel.agents.report.reviewer import review_report
    from fackel.persistence import get_current_store

    draft = state.get("report", "")
    store = get_current_store()
    if not draft or store is None:
        return {}

    streaming.emit("review", "start", {})
    final = review_report(draft, store, config=config)
    streaming.emit("review", "done", {})
    return {"report": final}


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
    """Route after port scan: vuln scanning normally, or skip to triage if empty.

    Uses the LLM-as-a-judge evaluation stored in state by ``port_scan_node``.
    Only skips to triage when the judge explicitly recommends it — default is to
    proceed to vuln scanning (which can still find domain-level issues).

    Picks the vuln entry node: ``vuln_dispatch`` for the parallel specialist
    fan-out (``FACKEL_VULN_SPECIALISTS`` on), or the monolithic ``vuln_scan``
    agent.  Per-tool HITL approval forces the monolithic path, since parallel
    branches can't share one coherent approval interrupt stream.
    """
    from fackel.settings import get_settings

    from ..streaming import is_tool_approval_enabled

    port_eval = get_phase_evaluation(state, "port_scan")
    if port_eval and port_eval.get("recommendation") == "skip_downstream":
        logger.info("routing: port_scan judge recommends skip → triage")
        return "triage"
    if get_settings().vuln_specialists and not is_tool_approval_enabled():
        return "vuln_dispatch"
    return "vuln_scan"
