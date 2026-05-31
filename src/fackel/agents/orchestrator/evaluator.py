"""Phase output evaluator — LLM-as-a-judge for quality-gated routing.

After each active-scan phase, a lightweight structured LLM call evaluates
the agent's output.  The resulting ``PhaseEvaluation`` drives:

- **Routing** — skip or adapt downstream phases when data is insufficient.
- **Context enrichment** — pass quality signals to the next agent.
- **Report honesty** — surface gaps and limitations in the final report.
"""

from __future__ import annotations

import logging
from typing import Literal, cast

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig
from pydantic import BaseModel, Field, field_validator

from fackel.agents.config import build_llm
from fackel.prompts import compose_prompt

logger = logging.getLogger(__name__)


class PhaseEvaluation(BaseModel):
    """Structured quality assessment of a scan phase's output."""

    phase: str = Field(description="Phase evaluated (e.g. port_scan, vuln_scan)")
    completeness: Literal["complete", "partial", "empty"] = Field(
        description=(
            "Coverage level: complete (all targets covered), "
            "partial (some gaps), empty (no meaningful data)"
        ),
    )
    score: float = Field(
        ge=0.0,
        le=1.0,
        description="Quality score: 0.0 (no useful output) to 1.0 (thorough coverage)",
    )

    @field_validator("score", mode="before")
    @classmethod
    def _normalize_score(cls, v: float) -> float:
        """Normalise scores >1 to the 0-1 range.

        Smaller LLMs (e.g. Ollama models) sometimes return scores on a
        0-100 scale despite the schema requesting 0-1.
        """
        if isinstance(v, int | float) and v > 1:
            return v / 100.0
        return v

    key_findings: list[str] = Field(
        default_factory=list,
        description="Brief factual bullets of the most important discoveries",
    )
    gaps: list[str] = Field(
        default_factory=list,
        description="Actionable items that are missing or incomplete",
    )
    recommendation: Literal["proceed", "adapt", "skip_downstream"] = Field(
        description="Routing advice for the next phase",
    )
    reasoning: str = Field(
        description="One-paragraph explanation of the assessment",
    )


def _fallback_evaluation(phase: str, reason: str) -> PhaseEvaluation:
    """Return a safe default when the judge LLM call fails."""
    return PhaseEvaluation(
        phase=phase,
        completeness="partial",
        score=0.5,
        key_findings=[],
        gaps=[reason],
        recommendation="proceed",
        reasoning=f"Evaluation unavailable: {reason}. Proceeding with default routing.",
    )


def _summarize_records_for_phase(phase: str) -> str:
    """Return a structured summary of records persisted in *phase*.

    Reads from the scan-bound :class:`InformationStore` (if any) so the
    judge sees the actual extracted facts — not just the agent's
    self-reported narrative.  Returns an empty string when no store is
    bound or no records exist for *phase*.
    """
    from fackel.persistence import get_current_store

    store = get_current_store()
    if store is None:
        return ""
    records = store.records_by_phase(phase)
    if not records:
        return ""

    counts: dict[str, int] = {}
    for record in records:
        counts[record.type.value] = counts.get(record.type.value, 0) + 1

    sample_lines: list[str] = []
    for record in records[:20]:
        sample_lines.append(
            f"- [{record.type.value}] {record.normalized_value} (confidence={record.confidence})"
        )
    overflow = len(records) - len(sample_lines)
    if overflow > 0:
        sample_lines.append(f"- … (+{overflow} more)")

    summary = ["Extracted information records (from the persistent store):"]
    summary.append("Counts: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    summary.extend(sample_lines)
    return "\n".join(summary)


def evaluate_phase(
    phase: str,
    agent_summary: str,
    targets: list[str],
    *,
    model_name: str | None = None,
    config: RunnableConfig | None = None,
) -> PhaseEvaluation:
    """Evaluate a phase's output quality via LLM-as-a-judge.

    Returns a structured ``PhaseEvaluation`` that downstream nodes and
    routing functions use to adapt the pipeline.  Never raises — returns
    a safe fallback on any LLM failure.

    Parameters
    ----------
    config:
        Optional ``RunnableConfig`` for observability trace nesting.
    """
    try:
        llm = build_llm(
            "judge",
            model_name=model_name,
            temperature=0,
            request_timeout=30,
        )
        structured_llm = llm.with_structured_output(PhaseEvaluation)

        records_summary = _summarize_records_for_phase(phase)
        context_parts = [
            f"Phase: {phase}",
            f"Targets: {', '.join(targets) if targets else 'none'}",
        ]
        if records_summary:
            context_parts.append("")
            context_parts.append(records_summary)
        context_parts.append("")
        context_parts.append("Agent narrative:")
        context_parts.append(agent_summary)
        context = "\n".join(context_parts)

        judge_prompt = compose_prompt(
            "judge",
            "orchestrator/phase_transition",
            "orchestrator/continue_or_stop",
            "orchestrator/surface_exhaustion",
        )

        result = cast(
            PhaseEvaluation,
            structured_llm.invoke(
                [
                    SystemMessage(content=judge_prompt),
                    HumanMessage(content=context),
                ],
                config=config,
            ),
        )
        logger.info(
            "judge: %s → %s (score=%.1f, rec=%s)",
            phase,
            result.completeness,
            result.score,
            result.recommendation,
        )
        return result
    except Exception:
        logger.warning(
            "judge: evaluation failed for %s — using fallback",
            phase,
            exc_info=True,
        )
        return _fallback_evaluation(phase, "LLM evaluation call failed")
