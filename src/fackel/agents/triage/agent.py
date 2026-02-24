"""Triage specialist — analyses scan findings to identify coverage gaps.

Uses structured output to produce a typed assessment of detected technologies
and areas that could not be evaluated due to missing specialist agents.
"""

from __future__ import annotations

import logging

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from fackel.agents.config import get_model
from fackel.agents.prompts import load_prompt

logger = logging.getLogger(__name__)


class UnassessedArea(BaseModel):
    """A technology or attack surface detected but not covered by any specialist."""

    technology: str = Field(description="Name and version of the detected technology")
    detected_by: str = Field(description="Which tool/template detected it")
    reason: str = Field(description="Why this area needs specialist analysis")
    recommendation: str = Field(description="What a manual audit should focus on")


class TriageResult(BaseModel):
    """Structured output from the triage analysis."""

    technologies_detected: list[str] = Field(
        description="All technologies identified across all findings"
    )
    unassessed_areas: list[UnassessedArea] = Field(
        default_factory=list,
        description="Technologies detected but not covered by available specialists",
    )
    summary: str = Field(description="Brief overall assessment of scan coverage")


def run_triage(findings: list[dict], model_name: str | None = None) -> TriageResult:
    """Analyse accumulated findings and return a structured triage result.

    Parameters
    ----------
    findings:
        List of ``Finding`` dicts with keys: phase, title, detail,
        (optional) severity, source_tool, confidence.
    """
    llm = ChatOpenAI(model=model_name or get_model("triage"))
    structured_llm = llm.with_structured_output(TriageResult)

    # Serialise structured findings into text for the LLM.
    context = _serialize_findings(findings)

    try:
        return structured_llm.invoke([
            SystemMessage(content=load_prompt("triage")),
            HumanMessage(content=f"Analyse these scan findings:\n\n{context}"),
        ])
    except Exception:
        logger.exception("Triage LLM call failed — returning fallback result")
        return TriageResult(
            technologies_detected=[],
            unassessed_areas=[],
            summary="Triage analysis could not be completed due to an LLM error. "
                    "Review the raw findings manually.",
        )


def _serialize_findings(findings: list[dict]) -> str:
    """Convert a list of Finding dicts into Markdown sections for the LLM."""
    sections: list[str] = []
    for f in findings:
        if isinstance(f, dict):
            header = f.get("title", f.get("phase", "Finding"))
            detail = f.get("detail", "")
            sections.append(f"## {header}\n\n{detail}")
        else:
            sections.append(str(f))
    return "\n\n---\n\n".join(sections) if sections else "No findings collected."
