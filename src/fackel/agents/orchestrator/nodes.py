"""Orchestrator graph nodes — thin wrappers that stream specialist ReAct agents.

Each node invokes its specialist agent via ``.stream()`` so that every
ReAct reasoning step (think → tool call → observe) can be surfaced to
the CLI in real-time.  Results are collected and returned as a partial
``ScanState`` update.

Architecture layers:
- **Input sanitiser** validates targets before they reach tools.
- **Output validator** checks tool results for structural correctness.
- **Max-iterations** guard prevents runaway ReAct loops.
- **Structured findings** — nodes always emit ``Finding`` dicts, never raw text.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from langgraph.types import Command, interrupt

from fackel.formatting import find_evaluation, format_tech_fingerprint, is_ipv6
from fackel.tooling import is_valid_domain, is_valid_ip, sanitize_target

from .evaluator import evaluate_phase
from .extractors import (
    extract_historical_ips,
    extract_ip_classifications,
    extract_ips,
    extract_san_domains,
    extract_subdomains,
    extract_tech_fingerprints,
)
from .state import Finding, ScanState
from .streaming import (
    agent_summary,
    emit,
    is_tool_approval_enabled,
    run_and_stream_agent,
)

logger = logging.getLogger(__name__)

__all__ = [
    "approval_gate",
    "osint_node",
    "port_scan_node",
    "report_node",
    "route_after_osint",
    "route_after_port_scan",
    "triage_node",
    "vuln_scan_node",
]

# Maximum number of subdomains propagated to downstream agents.
_SUBDOMAIN_CAP = 30

# Default strategy text appended to vuln-scan prompts.
_DEFAULT_VULN_SCAN_STRATEGY = (
    "\nScan the DOMAIN first (nuclei with empty severity for full template "
    "coverage). Then scan the most interesting subdomains (www, web apps, "
    "APIs, panels). Then per-IP checks. Prioritise breadth — it's better "
    "to scan more targets shallowly than fewer targets deeply."
)

# IP class → prompt hint for port-scan context.
_IP_CLASS_HINTS: dict[str, str] = {
    "cdn": " → CDN proxy, skip deep scanning (ports are the CDN's, not the origin)",
    "cloud": " → cloud-hosted, scan normally",
    "direct_host": " → direct infrastructure, HIGH PRIORITY",
}


# ── Helpers ────────────────────────────────────────────────────────────────


def _make_finding(
    phase: str,
    title: str,
    detail: str,
    *,
    severity: Literal["critical", "high", "medium", "low", "info"] = "info",
    source_tool: str = "",
    confidence: float = 1.0,
) -> Finding:
    """Build a typed ``Finding`` dict."""
    return Finding(
        phase=phase,
        title=title,
        detail=detail,
        severity=severity,
        source_tool=source_tool,
        confidence=confidence,
    )


def _get_phase_evaluation(state: ScanState, phase: str) -> dict[str, Any] | None:
    """Retrieve the latest LLM-as-a-judge evaluation for *phase* from state."""
    return find_evaluation(state.get("phase_evaluations", []), phase)


def _prepare_scan_targets(state: ScanState) -> tuple[list[str], list[str]]:
    """Filter IPv6 addresses and return ``(ipv4_ips, subdomains)``."""
    all_ips = state.get("discovered_ips", [])
    ips = [ip for ip in all_ips if not is_ipv6(ip)]
    dropped = len(all_ips) - len(ips)
    if dropped:
        logger.info("dropping %d IPv6 address(es) — not yet supported", dropped)
    subdomains = state.get("discovered_subdomains", [])
    return ips, subdomains


def _emit_evaluation(phase: str, evaluation: Any) -> None:
    """Emit a quality-evaluation event for *phase*."""
    emit(
        phase,
        "evaluation",
        {
            "score": evaluation.score,
            "completeness": evaluation.completeness,
            "recommendation": evaluation.recommendation,
        },
    )


# ── OSINT node ─────────────────────────────────────────────────────────────


def osint_node(state: ScanState) -> dict[str, Any]:
    """Run the OSINT ReAct agent for passive reconnaissance.

    Includes LLM-as-a-judge quality evaluation and self-reflection retry:
    if the first pass produces thin output (judge says "empty"), the agent
    is re-invoked with enriched instructions based on the judge's gaps.
    """
    from fackel.agents.osint.agent import build

    target = sanitize_target(state["target"])
    agent = build()
    messages, evaluation = _run_osint_with_retry(agent, target)
    return _build_osint_result(messages, target, evaluation)


def _run_osint_with_retry(agent: Any, target: str) -> tuple[list[Any], Any]:
    """Run OSINT agent with quality evaluation and retry on poor output."""
    messages = run_and_stream_agent(
        agent,
        "osint",
        f"Perform passive OSINT reconnaissance on: {target}",
    )
    summary = agent_summary(messages)

    evaluation = evaluate_phase("osint", summary, [target])
    _emit_evaluation("osint", evaluation)

    if evaluation.completeness == "empty" and evaluation.score < 0.3:
        retry_msgs = _retry_osint(agent, target, evaluation)
        messages = messages + retry_msgs

    return messages, evaluation


def _retry_osint(agent: Any, target: str, evaluation: Any) -> list[Any]:
    """Re-invoke OSINT agent with enriched prompt on poor quality."""
    logger.info(
        "osint: judge rated output as empty (score=%.1f) — retrying with enriched prompt",
        evaluation.score,
    )
    gaps_text = "; ".join(evaluation.gaps) if evaluation.gaps else "thin output"
    retry_prompt = (
        f"Your first OSINT pass on {target} was insufficient.\n"
        f"Quality assessment: {evaluation.completeness} (score: {evaluation.score:.1f})\n"
        f"Gaps identified: {gaps_text}\n"
        f"Reasoning: {evaluation.reasoning}\n\n"
        f"Please perform a MORE THOROUGH reconnaissance on: {target}\n"
        "Use ALL available tools from your playbook — DNS, WHOIS, subdomain "
        "enumeration, reverse DNS, IP classification, Shodan/Censys, httpx, "
        "TLS certs. Do not stop after one or two tools."
    )
    emit("osint", "retry", {"reason": gaps_text})
    return run_and_stream_agent(agent, "osint", retry_prompt)


def _build_osint_result(
    messages: list[Any],
    target: str,
    evaluation: Any,
) -> dict[str, Any]:
    """Extract structured data from OSINT messages and build state update."""
    ips = extract_ips(messages)
    if not ips and is_valid_ip(target):
        ips = [target]

    subdomains = extract_subdomains(messages, target) if is_valid_domain(target) else []
    classifications = extract_ip_classifications(messages, target)
    fingerprints = extract_tech_fingerprints(messages)

    subdomains = _enrich_subdomains_with_sans(messages, target, subdomains)
    ips = _enrich_ips_with_historical(messages, ips)
    _log_classifications(classifications)
    _log_fingerprints(fingerprints)

    summary = agent_summary(messages)
    emit("osint", "summary", {"content": summary})
    emit("osint", "done", {})
    return {
        "discovered_ips": ips,
        "discovered_subdomains": subdomains,
        "ip_classifications": classifications,
        "tech_fingerprints": fingerprints,
        "findings": [_make_finding("osint", "OSINT Findings", summary)],
        "phase_evaluations": [evaluation.model_dump()],
    }


def _enrich_subdomains_with_sans(
    messages: list[Any],
    target: str,
    subdomains: list[str],
) -> list[str]:
    """Merge TLS SAN domains into the subdomain list."""
    if not is_valid_domain(target):
        return subdomains
    san_subs = extract_san_domains(messages, target)
    new_sans = [s for s in san_subs if s not in subdomains]
    if new_sans:
        subdomains = sorted(set(subdomains) | set(new_sans))
        logger.info("osint: TLS SANs added %d new subdomain(s)", len(new_sans))
    return subdomains


def _enrich_ips_with_historical(messages: list[Any], ips: list[str]) -> list[str]:
    """Merge historical DNS IPs into the IP list."""
    historical_ips = extract_historical_ips(messages, ips)
    if historical_ips:
        ips = list(dict.fromkeys(ips + historical_ips))
        logger.info(
            "osint: historical DNS revealed %d direct-origin candidate(s)",
            len(historical_ips),
        )
    return ips


def _log_classifications(classifications: list[dict[str, Any]]) -> None:
    """Log IP infrastructure classifications if any were found."""
    if not classifications:
        return
    lines = [f"  {c['ip']}: {c['ip_class']} ({c.get('org', 'unknown')})" for c in classifications]
    logger.info("osint: classified %d IP(s):\n%s", len(classifications), "\n".join(lines))


def _log_fingerprints(fingerprints: list[dict[str, Any]]) -> None:
    """Log HTTP tech fingerprints if any were found."""
    if not fingerprints:
        return
    lines = [
        f"  {fp['host']}: server={fp.get('server', '?')}, "
        f"tech={fp.get('technologies', [])} cdn={fp.get('cdn', False)}"
        for fp in fingerprints
    ]
    logger.info("osint: fingerprinted %d target(s):\n%s", len(fingerprints), "\n".join(lines))


# ── Port Scan node ─────────────────────────────────────────────────────────


def port_scan_node(state: ScanState) -> dict[str, Any]:
    """Run the port-scan ReAct agent on discovered IPs and subdomains."""
    from fackel.agents.port_scan.agent import build

    ips, subdomains = _prepare_scan_targets(state)
    if not ips and not subdomains:
        return {
            "findings": [
                _make_finding(
                    "port_scan", "Port Scan", "No IPv4 targets available.", severity="info"
                )
            ]
        }

    prompt = _build_port_scan_prompt(state["target"], ips, subdomains, state)
    agent = build(approve_tools=is_tool_approval_enabled())
    messages = run_and_stream_agent(agent, "port_scan", prompt)

    summary = agent_summary(messages)
    emit("port_scan", "summary", {"content": summary})

    scan_targets = ips + subdomains[:_SUBDOMAIN_CAP]
    evaluation = evaluate_phase("port_scan", summary, scan_targets)
    _emit_evaluation("port_scan", evaluation)
    emit("port_scan", "done", {})

    return {
        "findings": [_make_finding("port_scan", "Port Scan Findings", summary)],
        "phase_evaluations": [evaluation.model_dump()],
    }


def _build_port_scan_prompt(
    target: str,
    ips: list[str],
    subdomains: list[str],
    state: ScanState,
) -> str:
    """Build the port-scan agent prompt with context from OSINT."""
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

    _append_ip_classification_context(parts, ips, state)
    parts.append(
        "\nStrategy: scan the IPs first (naabu → nmap). Then scan only "
        "subdomains that might resolve to DIFFERENT IPs than those already "
        "scanned. Skip subdomains that point to the same IP — the IP scan "
        "already covers them."
    )
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
            parts.append(f"  - {ip}: {label} ({org}){_IP_CLASS_HINTS.get(label, '')}")

    if any(c.get("ip_class") == "cdn" for c in ip_classes.values()):
        parts.append(
            "\n⚠ CDN IPs detected. Scanning CDN proxy IPs (e.g. Cloudflare) "
            "yields the CDN's ports/services, not the origin server. "
            "Prioritise direct_host and cloud IPs instead."
        )


# ── Vuln Scan node ─────────────────────────────────────────────────────────


def vuln_scan_node(state: ScanState) -> dict[str, Any]:
    """Run the vuln-scan ReAct agent on the target domain, subdomains, and IPs."""
    from fackel.agents.vuln_scan.agent import build

    target = state["target"]
    ips, subdomains = _prepare_scan_targets(state)
    capped_subs = subdomains[:_SUBDOMAIN_CAP]

    prompt = _build_vuln_scan_prompt(target, ips, capped_subs, state)
    agent = build(approve_tools=is_tool_approval_enabled())
    messages = run_and_stream_agent(agent, "vuln_scan", prompt)

    summary = agent_summary(messages)
    emit("vuln_scan", "summary", {"content": summary})

    scan_targets = [target, *capped_subs, *ips]
    evaluation = evaluate_phase("vuln_scan", summary, scan_targets)
    _emit_evaluation("vuln_scan", evaluation)
    emit("vuln_scan", "done", {})

    return {
        "findings": [_make_finding("vuln_scan", "Vulnerability Scan Findings", summary)],
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
    port_eval = _get_phase_evaluation(state, "port_scan")
    if not port_eval:
        parts.append(_DEFAULT_VULN_SCAN_STRATEGY)
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
        parts.append(_DEFAULT_VULN_SCAN_STRATEGY)


# ── Triage node ────────────────────────────────────────────────────────────


def triage_node(state: ScanState) -> dict[str, Any]:
    """Analyse findings and identify unassessed areas via structured LLM output.

    Passes structured state context (IP classifications, tech fingerprints,
    phase evaluations) alongside textual findings so the triage LLM can
    produce evidence-backed risk scores from machine-readable data.
    """
    from fackel.agents.triage.agent import run_triage

    emit("triage", "start", {})
    result = run_triage(
        state.get("findings", []),
        ip_classifications=state.get("ip_classifications", []),
        tech_fingerprints=state.get("tech_fingerprints", []),
        phase_evaluations=state.get("phase_evaluations", []),
    )
    return _build_triage_result(result)


def _build_triage_result(result: Any) -> dict[str, Any]:
    """Build state update from triage analysis result."""
    unassessed = [
        {
            "technology": area.technology,
            "detected_by": area.detected_by,
            "reason": area.reason,
            "recommendation": area.recommendation,
        }
        for area in result.unassessed_areas
    ]

    risk = result.risk_score
    risk_dict = {
        "score": risk.score,
        "exposure_type": risk.exposure_type,
        "factors": list(risk.factors),
    }

    triage_detail = _format_triage_summary(result, risk, unassessed)
    emit("triage", "summary", {"content": triage_detail})
    emit(
        "triage",
        "done",
        {
            "technologies": result.technologies_detected,
            "unassessed_count": len(unassessed),
            "risk_score": risk.score,
            "risk_exposure_type": risk.exposure_type,
        },
    )

    return {
        "findings": [_make_finding("triage", "Triage Summary", triage_detail)],
        "unassessed_areas": unassessed,
        "risk_score": risk_dict,
    }


def _format_triage_summary(result: Any, risk: Any, unassessed: list[dict[str, Any]]) -> str:
    """Format the triage summary as Markdown."""
    parts = [f"## Triage Summary\n\n{result.summary}"]
    parts.append(f"\n**Risk Score:** {risk.score:.1f}/10 ({risk.exposure_type})")
    if risk.factors:
        parts.append("\n**Risk Factors:**\n" + "\n".join(f"- {f}" for f in risk.factors))
    if result.technologies_detected:
        techs = ", ".join(result.technologies_detected)
        parts.append(f"\n**Technologies detected:** {techs}")
    if unassessed:
        names = ", ".join(a["technology"] for a in unassessed)
        parts.append(f"\n**Unassessed areas:** {names}")
    return "\n".join(parts)


# ── Report node ────────────────────────────────────────────────────────────


def report_node(state: ScanState) -> dict[str, Any]:
    """Generate the final pentest report via LLM."""
    from fackel.agents.report.agent import generate_report

    emit("report", "start", {})
    report = generate_report(
        target=state["target"],
        active_scan=state["active_scan"],
        findings=state.get("findings", []),
        unassessed_areas=state.get("unassessed_areas", []),
        phase_evaluations=state.get("phase_evaluations", []),
        risk_score=state.get("risk_score"),
    )
    emit("report", "done", {})
    return {"report": report}


# ── Approval gate ──────────────────────────────────────────────────────────


def approval_gate(state: ScanState) -> Command:
    """Pause for human approval before active scanning.

    Uses LangGraph ``interrupt()`` to suspend execution.  The CLI (or API)
    resumes the graph with ``Command(resume=True/False)`` to approve or
    reject.
    """
    ips = state.get("discovered_ips", [])
    subdomains = state.get("discovered_subdomains", [])
    target = state["target"]

    emit("approval", "start", {})

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

    emit("approval", "done", {"approved": approved})

    if approved:
        return Command(goto="port_scan")
    return Command(goto="report")


# ── Routing ────────────────────────────────────────────────────────────────


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
    port_eval = _get_phase_evaluation(state, "port_scan")
    if port_eval and port_eval.get("recommendation") == "skip_downstream":
        logger.info("routing: port_scan judge recommends skip → triage")
        return "triage"
    return "vuln_scan"
