"""Vuln-scan graph node — vulnerability scanning with quality-gated retry."""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.runnables import RunnableConfig

from fackel.formatting import format_tech_fingerprint
from fackel.prompts import load_section

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

# Loaded once and cached — supplies node-level prompt context.
_CORRELATION_GUIDANCE: str | None = None
_DEPTH_ADJUSTMENT_GUIDANCE: str | None = None
_LOOP_DETECTION_GUIDANCE: str | None = None
_APPROACH_CHANGE_GUIDANCE: str | None = None


def _load_vuln_scan_guidance() -> tuple[str, str]:
    """Lazy-load correlation and depth adjustment prompt sections."""
    global _CORRELATION_GUIDANCE, _DEPTH_ADJUSTMENT_GUIDANCE  # noqa: PLW0603
    if _CORRELATION_GUIDANCE is None:
        _CORRELATION_GUIDANCE = load_section("stages/correlation")
        _DEPTH_ADJUSTMENT_GUIDANCE = load_section("strategy/depth_adjustment")
    return _CORRELATION_GUIDANCE, _DEPTH_ADJUSTMENT_GUIDANCE  # type: ignore[return-value]


def _load_retry_guidance() -> tuple[str, str]:
    """Lazy-load loop detection and approach change prompt sections."""
    global _LOOP_DETECTION_GUIDANCE, _APPROACH_CHANGE_GUIDANCE  # noqa: PLW0603
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
        agent, target, ips, capped_subs, state, prompt, config,
    )

    summary = agent_summary(messages)
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
            "vuln_scan", retry_summary, scan_targets, config=config,
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
    gaps_text = "; ".join(evaluation.gaps) if evaluation.gaps else "thin output"
    loop_guidance, approach_guidance = _load_retry_guidance()
    retry_prompt = (
        f"Your first vulnerability scan pass on {target} was insufficient.\n"
        f"Quality assessment: {evaluation.completeness} (score: {evaluation.score:.1f})\n"
        f"Gaps identified: {gaps_text}\n"
        f"Reasoning: {evaluation.reasoning}\n\n"
        f"## Loop Detection\n\n{loop_guidance}\n\n"
        f"## Strategy Adjustment\n\n{approach_guidance}\n\n"
        f"IMPORTANT: If a tool failed in the first pass (error, missing "
        f"dependency, timeout), try an ALTERNATIVE tool or different "
        f"parameters. For example:\n"
        f"- feroxbuster failed → use ffuf_scan instead (or vice-versa)\n"
        f"- testssl timed out → retry with checks='protocols,vulnerabilities'\n"
        f"- nuclei returned nothing → try with specific tags for detected tech\n\n"
        f"Please re-scan {target} focusing on the identified gaps. "
        f"Use ALL available tools from your playbook."
    )
    streaming.emit("vuln_scan", "retry", {"reason": gaps_text})
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
