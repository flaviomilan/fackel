"""Report specialist — LLM-based pentest report generation.

No tools needed: the LLM synthesises accumulated findings into a
professional Markdown report in a single call.
"""

from __future__ import annotations

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from fackel.agents.config import get_model

SYSTEM_PROMPT = """\
You are a pentest report writer for the Fackel framework.

Generate a professional, concise **Markdown** report based on the findings
provided.

## Structure
1. **Executive Summary** — high-level overview for stakeholders.
2. **Scope** — what was tested and scan configuration.
3. **Discovered Assets** — IPs, domains, infrastructure.
4. **Open Ports & Services** — detailed per-host findings.
5. **Recommendations** — actionable security improvements.

## Rules
- Be factual.  Only report what was actually discovered.
- Do not speculate or invent findings.
- Use tables where appropriate.
"""


def generate_report(
    target: str,
    active_scan: bool,
    findings: list[str],
    model_name: str | None = None,
) -> str:
    """Render a Markdown pentest report from accumulated agent findings."""
    llm = ChatOpenAI(model=model_name or get_model("report"))

    context = "\n\n---\n\n".join(findings) if findings else "No findings collected."

    response = llm.invoke([
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=(
            f"Target: {target}\n"
            f"Active scanning: {'enabled' if active_scan else 'disabled'}\n\n"
            f"Agent findings:\n\n{context}"
        )),
    ])
    return response.content
