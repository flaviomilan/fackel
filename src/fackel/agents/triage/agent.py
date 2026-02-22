"""Triage specialist — analyses scan findings to identify coverage gaps.

Uses structured output to produce a typed assessment of detected technologies
and areas that could not be evaluated due to missing specialist agents.
"""

from __future__ import annotations

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from fackel.agents.config import get_model
from fackel.agents.prompts import load_prompt


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


def run_triage(findings: list[str], model_name: str | None = None) -> TriageResult:
    """Analyse accumulated findings and return a structured triage result."""
    llm = ChatOpenAI(model=model_name or get_model("triage"))
    structured_llm = llm.with_structured_output(TriageResult)

    context = "\n\n---\n\n".join(findings) if findings else "No findings collected."

    return structured_llm.invoke([
        SystemMessage(content=load_prompt("triage")),
        HumanMessage(content=f"Analyse these scan findings:\n\n{context}"),
    ])
