"""Report specialist — LLM-based pentest report generation.

No tools needed: the LLM synthesises accumulated findings into a
professional Markdown report in a single call.
"""

from __future__ import annotations

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from fackel.agents.config import get_model
from fackel.agents.prompts import load_prompt


def generate_report(
    target: str,
    active_scan: bool,
    findings: list[str],
    unassessed_areas: list[dict] | None = None,
    model_name: str | None = None,
) -> str:
    """Render a Markdown pentest report from accumulated agent findings."""
    llm = ChatOpenAI(model=model_name or get_model("report"))

    context = "\n\n---\n\n".join(findings) if findings else "No findings collected."

    parts = [
        f"Target: {target}",
        f"Active scanning: {'enabled' if active_scan else 'disabled'}",
        f"\nAgent findings:\n\n{context}",
    ]

    if unassessed_areas:
        areas_text = "\n".join(
            f"- **{a['technology']}** (detected by {a['detected_by']}): "
            f"{a['reason']}. Recommendation: {a['recommendation']}"
            for a in unassessed_areas
        )
        parts.append(f"\nUnassessed Areas:\n\n{areas_text}")

    response = llm.invoke([
        SystemMessage(content=load_prompt("report")),
        HumanMessage(content="\n".join(parts)),
    ])
    return response.content
