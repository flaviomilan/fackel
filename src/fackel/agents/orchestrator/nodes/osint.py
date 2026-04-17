"""OSINT graph node — passive reconnaissance with quality-gated retry."""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.runnables import RunnableConfig
from langgraph.types import Send

from fackel.settings import get_settings
from fackel.tooling import is_valid_domain, is_valid_ip, sanitize_target

from .. import evaluator, planner, streaming
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
from ._helpers import build_retry_prompt, emit_evaluation, make_finding

logger = logging.getLogger(__name__)

# Loaded once and cached — supplies retry enrichment context.
_LOOP_DETECTION_GUIDANCE: str | None = None
_APPROACH_CHANGE_GUIDANCE: str | None = None


def _load_retry_guidance() -> tuple[str, str]:
    """Lazy-load loop detection and approach change prompt sections."""
    global _LOOP_DETECTION_GUIDANCE, _APPROACH_CHANGE_GUIDANCE
    if _LOOP_DETECTION_GUIDANCE is None:
        from fackel.prompts import load_section

        _LOOP_DETECTION_GUIDANCE = load_section("orchestrator/loop_detection")
        _APPROACH_CHANGE_GUIDANCE = load_section("strategy/approach_change")
    return _LOOP_DETECTION_GUIDANCE, _APPROACH_CHANGE_GUIDANCE  # type: ignore[return-value]


def osint_node(state: ScanState, config: RunnableConfig) -> dict[str, Any]:
    """Monolithic single-agent OSINT (the ``FACKEL_OSINT_SPECIALISTS=false`` path).

    Runs one 31-tool agent with LLM-as-a-judge evaluation + self-reflection
    retry, then the agentic pivot loop.  The default path is the parallel
    specialist fan-out (``dispatch_osint_specialists`` → ``osint_specialist`` →
    ``osint_collect``); see :func:`build_graph`.
    """
    from fackel.agents.osint.agent import build

    target = sanitize_target(state["target"])
    agent = build()
    messages, evaluation = _run_osint_with_retry(agent, target, config)
    messages = messages + _run_pivot_loop(agent, target, config)
    return _build_osint_result(messages, target, evaluation)


# ---------------------------------------------------------------------------
# Parallel specialist fan-out (idiomatic LangGraph Send map-reduce)
# ---------------------------------------------------------------------------


def dispatch_osint_specialists(state: ScanState) -> list[Send]:
    """Fan out to one parallel ``osint_specialist`` task per specialist.

    LangGraph runs the resulting ``Send`` tasks concurrently (thread pool in
    sync mode), so the focused specialists execute in parallel instead of in a
    sequential loop.
    """
    from fackel.agents.osint.specialists import SPECIALISTS

    target = sanitize_target(state["target"])
    return [Send("osint_specialist", {"specialist": s.name, "target": target}) for s in SPECIALISTS]


def osint_specialist_node(state: dict[str, Any], config: RunnableConfig) -> dict[str, Any]:
    """Run a single OSINT specialist (the ``Send`` payload names which one).

    Persists its structured output to the scan-bound store (the ``current_store``
    ContextVar is propagated into this worker thread; the store serialises writes)
    and returns its message log on the ``osint_messages`` fan-in channel.
    """
    from fackel.agents.osint.specialists import (
        SPECIALISTS_BY_NAME,
        _specialist_task,
        build_specialist,
    )

    from ..translators import persist_phase

    name = state["specialist"]
    target = state["target"]
    spec = SPECIALISTS_BY_NAME.get(name)
    if spec is None:
        return {}
    agent = build_specialist(spec)
    if agent is None:  # no usable tools (missing keys/binaries)
        logger.info("osint: specialist %s skipped (no usable tools)", name)
        return {}

    logger.info("osint: running specialist %s", name)
    # Bind a per-agent lane so the renderer can show this specialist in its own
    # lane instead of interleaving with the others running in parallel.
    with streaming.lane(name):
        streaming.emit("osint", "lane_start", {"name": name})
        try:
            msgs = run_and_stream_agent(
                agent, "osint", _specialist_task(spec, target), config=config
            )
        finally:
            streaming.emit("osint", "lane_end", {"name": name})
    persist_phase(msgs, phase="osint", target=target)
    return {"osint_messages": msgs}


def osint_collect_node(state: ScanState, config: RunnableConfig) -> dict[str, Any]:
    """Fan-in node: after all specialists finish, evaluate, pivot, and build state.

    Runs once after the parallel barrier; operates on the union of specialist
    message logs accumulated on ``osint_messages``.
    """
    from fackel.agents.osint.agent import build

    target = sanitize_target(state["target"])
    messages: list[Any] = list(state.get("osint_messages", []))

    evaluation = evaluator.evaluate_phase("osint", agent_summary(messages), [target], config=config)
    emit_evaluation("osint", evaluation)

    # Cross-domain pivots (sequential, post-barrier) use the full toolset.
    messages = messages + _run_pivot_loop(build(), target, config)
    return _build_osint_result(messages, target, evaluation)


def _run_pivot_loop(agent: Any, target: str, config: RunnableConfig) -> list[Any]:
    """Entity-driven pivot loop — the agentic investigation engine.

    After the main OSINT pass, inspect the knowledge graph for high-value
    *unexpanded* entities (e.g. discovered emails or an organisation) and run
    bounded, focused follow-up passes that expand them.  Each pivot persists
    its tool executions, so :func:`planner.plan_osint_pivots` stops proposing a
    directive once its expanding tool has run — the loop self-terminates.

    No-op when no :class:`InformationStore` is bound (e.g. unit tests) or when
    ``FACKEL_MAX_PIVOTS`` is ``0``.
    """
    from fackel.persistence import get_current_store

    from ..translators import persist_phase

    store = get_current_store()
    max_pivots = get_settings().max_pivots
    if store is None or max_pivots <= 0:
        return []

    extra: list[Any] = []
    for _ in range(max_pivots):
        directives = planner.plan_osint_pivots(store)
        if not directives:
            break
        kinds = [d.kind for d in directives]
        logger.info("osint: pivoting on %s", kinds)
        streaming.emit("osint", "pivot", {"kinds": kinds})
        prompt = planner.build_pivot_prompt(target, directives)
        pivot_msgs = run_and_stream_agent(agent, "osint", prompt, config=config)
        persist_phase(pivot_msgs, phase="osint", target=target)
        extra += pivot_msgs

    return extra


def _run_osint_with_retry(
    agent: Any,
    target: str,
    config: RunnableConfig,
) -> tuple[list[Any], Any]:
    """Run OSINT agent with quality evaluation and retry on poor output."""
    messages = run_and_stream_agent(
        agent,
        "osint",
        f"Perform passive OSINT reconnaissance on: {target}",
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
    loop_guidance, approach_guidance = _load_retry_guidance()
    body = (
        f"## Loop Detection Guidance\n\n{loop_guidance}\n\n"
        f"## Strategy Adjustment\n\n{approach_guidance}\n\n"
        f"Please perform a MORE THOROUGH reconnaissance on: {target}\n"
        "Use ALL available tools from your playbook — DNS, WHOIS, subdomain "
        "enumeration, reverse DNS, IP classification, Shodan/Censys, httpx, "
        "TLS certs. Do not stop after one or two tools."
    )
    retry_prompt = build_retry_prompt(
        phase="osint",
        intro=f"Your first OSINT pass on {target} was insufficient.",
        evaluation=evaluation,
        body=body,
    )
    streaming.emit("osint", "retry", {"reason": "judge: empty output"})
    return run_and_stream_agent(agent, "osint", retry_prompt, config=config)


def _build_osint_result(
    messages: list[Any],
    target: str,
    evaluation: Any,
) -> dict[str, Any]:
    """Extract structured data from OSINT messages and build state update."""
    from ..translators import persist_phase

    persist_phase(messages, phase="osint", target=target)

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
