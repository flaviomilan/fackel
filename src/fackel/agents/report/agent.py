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
    findings: list[dict],
    unassessed_areas: list[dict] | None = None,
    model_name: str | None = None,
) -> str:
    """Render a Markdown pentest report from accumulated agent findings.

    Parameters
    ----------
    findings:
        List of ``Finding`` dicts with keys: phase, title, detail,
        (optional) severity, source_tool, confidence.
    """
    llm = ChatOpenAI(model=model_name or get_model("report"))

    # Serialise structured findings into Markdown sections for the LLM.
    sections: list[str] = []
    for f in findings:
        if isinstance(f, dict):
            header = f.get("title", f.get("phase", "Finding"))
            detail = f.get("detail", "")
            sev = f.get("severity", "")
            sev_tag = f" [severity: {sev}]" if sev else ""
            sections.append(f"## {header}{sev_tag}\n\n{detail}")
        else:
            # Backward-compat: raw string
            sections.append(str(f))
    context = "\n\n---\n\n".join(sections) if sections else "No findings collected."

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
