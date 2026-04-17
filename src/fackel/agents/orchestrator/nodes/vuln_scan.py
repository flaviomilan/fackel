"""Vuln-scan graph node — vulnerability scanning with quality-gated retry."""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.runnables import RunnableConfig
from langgraph.types import Send

from fackel.formatting import format_tech_fingerprint
from fackel.prompts import load_section

from .. import evaluator, streaming
from ..state import ScanState
from ..streaming import agent_summary, is_tool_approval_enabled, run_and_stream_agent
from ._helpers import (
    DEFAULT_VULN_SCAN_STRATEGY,
    SUBDOMAIN_CAP,
    build_retry_prompt,
    emit_evaluation,
    get_phase_evaluation,
    make_finding,
    prepare_scan_targets,
)

logger = logging.getLogger(__name__)

# Loaded once and cached — supplies node-level prompt context.
_CORRELATION_GUIDANCE: str | None = None
_DEPTH_ADJUSTMENT_GUIDANCE: str | None = None
_LOOP_DETECTION_GUIDANCE: str | None = None
_APPROACH_CHANGE_GUIDANCE: str | None = None


def _load_vuln_scan_guidance() -> tuple[str, str]:
    """Lazy-load correlation and depth adjustment prompt sections."""
    global _CORRELATION_GUIDANCE, _DEPTH_ADJUSTMENT_GUIDANCE
    if _CORRELATION_GUIDANCE is None:
        _CORRELATION_GUIDANCE = load_section("stages/correlation")
        _DEPTH_ADJUSTMENT_GUIDANCE = load_section("strategy/depth_adjustment")
    return _CORRELATION_GUIDANCE, _DEPTH_ADJUSTMENT_GUIDANCE  # type: ignore[return-value]


def _load_retry_guidance() -> tuple[str, str]:
    """Lazy-load loop detection and approach change prompt sections."""
    global _LOOP_DETECTION_GUIDANCE, _APPROACH_CHANGE_GUIDANCE
    if _LOOP_DETECTION_GUIDANCE is None:
        _LOOP_DETECTION_GUIDANCE = load_section("orchestrator/loop_detection")
        _APPROACH_CHANGE_GUIDANCE = load_section("strategy/approach_change")
    return _LOOP_DETECTION_GUIDANCE, _APPROACH_CHANGE_GUIDANCE  # type: ignore[return-value]


def vuln_scan_node(state: ScanState, config: RunnableConfig) -> dict[str, Any]:
    """Run the vuln-scan ReAct agent with quality evaluation and retry.

    Includes LLM-as-a-judge quality evaluation and self-reflection retry:
    if the first pass produces thin output (judge says "empty"), the agent
    is re-invoked with enriched instructions based on the judge's gaps,
    focusing on tools that failed or areas left unscanned.
    """
    from fackel.agents.vuln_scan.agent import build

    target = state["target"]
    ips, subdomains = prepare_scan_targets(state)
    capped_subs = subdomains[:SUBDOMAIN_CAP]

    prompt = _build_vuln_scan_prompt(target, ips, capped_subs, state)
    agent = build(approve_tools=is_tool_approval_enabled())

    messages, evaluation = _run_vuln_scan_with_retry(
        agent,
        target,
        ips,
        capped_subs,
        state,
        prompt,
        config,
    )

    from ..translators import persist_phase

    persist_phase(messages, phase="vuln_scan", target=target)

    summary = agent_summary(messages)
    streaming.emit("vuln_scan", "summary", {"content": summary})
    streaming.emit("vuln_scan", "done", {})

    return {
        "findings": [make_finding("vuln_scan", "Vulnerability Scan Findings", summary)],
        "phase_evaluations": [evaluation.model_dump()],
    }


# ---------------------------------------------------------------------------
# Parallel specialist fan-out (idiomatic LangGraph Send map-reduce)
#
# Used when ``FACKEL_VULN_SPECIALISTS`` is on AND per-tool HITL approval is off
# (parallel branches can't coherently share a single approval interrupt stream).
# ---------------------------------------------------------------------------


def vuln_dispatch_node(state: ScanState, config: RunnableConfig) -> dict[str, Any]:
    """Build the shared per-run vuln context once, before fanning out.

    The rich prompt context (targets, tech fingerprints, port-scan strategy) is
    derived from state here so each parallel specialist receives it without
    rebuilding — specialist ``Send`` tasks only get their payload, not full state.
    """
    target = state["target"]
    ips, subdomains = prepare_scan_targets(state)
    capped_subs = subdomains[:SUBDOMAIN_CAP]
    prompt = _build_vuln_scan_prompt(target, ips, capped_subs, state)
    return {"vuln_base_prompt": prompt}


def dispatch_vuln_specialists(state: ScanState) -> list[Send]:
    """Fan out to one parallel ``vuln_specialist`` task per specialist.

    LangGraph runs the resulting ``Send`` tasks concurrently (thread pool in sync
    mode).  Note: vuln scanning is active, so these branches send concurrent
    traffic to the target — by design, gated behind ``FACKEL_VULN_SPECIALISTS``.
    """
    from fackel.agents.vuln_scan.specialists import VULN_SPECIALISTS

    target = state["target"]
    base_prompt = state.get("vuln_base_prompt", "")
    return [
        Send(
            "vuln_specialist", {"specialist": s.name, "target": target, "base_prompt": base_prompt}
        )
        for s in VULN_SPECIALISTS
    ]


def vuln_specialist_node(state: dict[str, Any], config: RunnableConfig) -> dict[str, Any]:
    """Run a single vuln-scan specialist (the ``Send`` payload names which one).

    Persists its structured output to the scan-bound store (``current_store`` is
    propagated into this worker thread; the store serialises writes) and returns
    its message log on the ``vuln_messages`` fan-in channel.
    """
    from fackel.agents.vuln_scan.specialists import (
        VULN_SPECIALISTS_BY_NAME,
        _vuln_specialist_task,
        build_vuln_specialist,
    )

    from ..translators import persist_phase

    name = state["specialist"]
    target = state["target"]
    spec = VULN_SPECIALISTS_BY_NAME.get(name)
    if spec is None:
        return {}
    agent = build_vuln_specialist(spec)
    if agent is None:  # no usable tools (missing keys/binaries)
        logger.info("vuln_scan: specialist %s skipped (no usable tools)", name)
        return {}

    logger.info("vuln_scan: running specialist %s", name)
    task = _vuln_specialist_task(spec, state.get("base_prompt", ""))
    # Bind a per-agent lane so the renderer can show this specialist in its own
    # lane instead of interleaving with the others running in parallel.
    with streaming.lane(name):
        streaming.emit("vuln_scan", "lane_start", {"name": name})
        try:
            msgs = run_and_stream_agent(agent, "vuln_scan", task, config=config)
        finally:
            streaming.emit("vuln_scan", "lane_end", {"name": name})
    persist_phase(msgs, phase="vuln_scan", target=target)
    return {"vuln_messages": msgs}


def vuln_collect_node(state: ScanState, config: RunnableConfig) -> dict[str, Any]:
    """Fan-in node: after all specialists finish, evaluate and build state.

    Runs once after the parallel barrier; operates on the union of specialist
    message logs accumulated on ``vuln_messages``.
    """
    target = state["target"]
    ips, subdomains = prepare_scan_targets(state)
    messages: list[Any] = list(state.get("vuln_messages", []))

    from ..translators import persist_phase

    persist_phase(messages, phase="vuln_scan", target=target)

    summary = agent_summary(messages)
    scan_targets = [target, *subdomains[:SUBDOMAIN_CAP], *ips]
    evaluation = evaluator.evaluate_phase("vuln_scan", summary, scan_targets, config=config)
    emit_evaluation("vuln_scan", evaluation)

    streaming.emit("vuln_scan", "summary", {"content": summary})
    streaming.emit("vuln_scan", "done", {})
    return {
        "findings": [make_finding("vuln_scan", "Vulnerability Scan Findings", summary)],
        "phase_evaluations": [evaluation.model_dump()],
    }


def _run_vuln_scan_with_retry(
    agent: Any,
    target: str,
    ips: list[str],
    subdomains: list[str],
    state: ScanState,
    prompt: str,
    config: RunnableConfig,
) -> tuple[list[Any], Any]:
    """Run vuln-scan agent with quality evaluation and retry on poor output."""
    messages = run_and_stream_agent(agent, "vuln_scan", prompt, config=config)
    summary = agent_summary(messages)

    scan_targets = [target, *subdomains, *ips]
    evaluation = evaluator.evaluate_phase("vuln_scan", summary, scan_targets, config=config)
    emit_evaluation("vuln_scan", evaluation)

    if evaluation.completeness == "empty" and evaluation.score < 0.3:
        retry_msgs = _retry_vuln_scan(agent, target, evaluation, config)
        messages = messages + retry_msgs
        retry_summary = agent_summary(messages)
        evaluation = evaluator.evaluate_phase(
            "vuln_scan",
            retry_summary,
            scan_targets,
            config=config,
        )
        emit_evaluation("vuln_scan", evaluation)

    return messages, evaluation


def _retry_vuln_scan(
    agent: Any,
    target: str,
    evaluation: Any,
    config: RunnableConfig,
) -> list[Any]:
    """Re-invoke vuln-scan agent with enriched prompt on poor quality."""
    logger.info(
        "vuln_scan: judge rated output as empty (score=%.1f) — retrying with enriched prompt",
        evaluation.score,
    )
    loop_guidance, approach_guidance = _load_retry_guidance()
    body = (
        f"## Loop Detection\n\n{loop_guidance}\n\n"
        f"## Strategy Adjustment\n\n{approach_guidance}\n\n"
        "IMPORTANT: If a tool failed in the first pass (error, missing "
        "dependency, timeout), try an ALTERNATIVE tool or different "
        "parameters. For example:\n"
        "- feroxbuster failed → use ffuf_scan instead (or vice-versa)\n"
        "- testssl timed out → retry with checks='protocols,vulnerabilities'\n"
        "- nuclei returned nothing → try with specific tags for detected tech\n\n"
        f"Please re-scan {target} focusing on the identified gaps. "
        "Use ALL available tools from your playbook."
    )
    retry_prompt = build_retry_prompt(
        phase="vuln_scan",
        intro=f"Your first vulnerability scan pass on {target} was insufficient.",
        evaluation=evaluation,
        body=body,
    )
    streaming.emit("vuln_scan", "retry", {"reason": "judge: empty output"})
    return run_and_stream_agent(agent, "vuln_scan", retry_prompt, config=config)


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

    correlation_guide, depth_guide = _load_vuln_scan_guidance()
    parts.append(f"\n## Cross-Phase Correlation\n\n{correlation_guide}")
    parts.append(f"\n## Depth Adjustment\n\n{depth_guide}")

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
