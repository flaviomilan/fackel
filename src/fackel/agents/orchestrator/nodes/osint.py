"""OSINT graph node — passive reconnaissance with quality-gated retry."""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.runnables import RunnableConfig

from fackel.agents.prompts import load_template
from fackel.tooling import is_valid_domain, is_valid_ip, sanitize_target

from .. import evaluator, streaming
from ..extractors import (
    extract_historical_ips,
    extract_ip_classifications,
    extract_ips,
    extract_san_domains,
    extract_subdomains,
    extract_tech_fingerprints,
)
from ..state import ScanState
from ..streaming import agent_summary, run_and_stream_agent
from ._helpers import emit_evaluation, get_phase_guidance, make_finding

logger = logging.getLogger(__name__)


def osint_node(state: ScanState, config: RunnableConfig) -> dict[str, Any]:
    """Run the OSINT ReAct agent for passive reconnaissance.

    Includes LLM-as-a-judge quality evaluation and self-reflection retry:
    if the first pass produces thin output (judge says "empty"), the agent
    is re-invoked with enriched instructions based on the judge's gaps.
    """
    from fackel.agents.osint.agent import build

    target = sanitize_target(state["target"])
    guidance = get_phase_guidance(state, "osint")
    agent = build()
    messages, evaluation = _run_osint_with_retry(agent, target, guidance, config)
    return _build_osint_result(messages, target, evaluation)


def _run_osint_with_retry(
    agent: Any,
    target: str,
    guidance: str,
    config: RunnableConfig,
) -> tuple[list[Any], Any]:
    """Run OSINT agent with quality evaluation and retry on poor output."""
    prompt = load_template("osint_task").format(target=target)
    if guidance:
        prompt += "\n\n" + load_template("guidance_suffix").format(guidance=guidance)
    messages = run_and_stream_agent(
        agent,
        "osint",
        prompt,
        config=config,
    )
    summary = agent_summary(messages)

    evaluation = evaluator.evaluate_phase("osint", summary, [target], config=config)
    emit_evaluation("osint", evaluation)

    if evaluation.completeness == "empty" and evaluation.score < 0.3:
        retry_msgs = _retry_osint(agent, target, evaluation, config)
        messages = messages + retry_msgs

    return messages, evaluation


def _retry_osint(agent: Any, target: str, evaluation: Any, config: RunnableConfig) -> list[Any]:
    """Re-invoke OSINT agent with enriched prompt on poor quality."""
    logger.info(
        "osint: judge rated output as empty (score=%.1f) — retrying with enriched prompt",
        evaluation.score,
    )
    gaps_text = "; ".join(evaluation.gaps) if evaluation.gaps else "thin output"
    retry_prompt = load_template("osint_retry").format(
        target=target,
        completeness=evaluation.completeness,
        score=f"{evaluation.score:.1f}",
        gaps_text=gaps_text,
        reasoning=evaluation.reasoning,
    )
    streaming.emit("osint", "retry", {"reason": gaps_text})
    return run_and_stream_agent(agent, "osint", retry_prompt, config=config)


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
    streaming.emit("osint", "summary", {"content": summary})
    streaming.emit("osint", "done", {})
    return {
        "discovered_ips": ips,
        "discovered_subdomains": subdomains,
        "ip_classifications": classifications,
        "tech_fingerprints": fingerprints,
        "findings": [make_finding("osint", "OSINT Findings", summary)],
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
