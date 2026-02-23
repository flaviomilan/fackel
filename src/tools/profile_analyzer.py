"""Professional profile analysis via web search."""

from __future__ import annotations

import re

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from .utils import DDGS, format_tool_output

_TECH_PATTERNS = [
    r"\b(Python|Java|JavaScript|C\+\+|PHP|Ruby|Go|Rust|Swift|Kotlin)\b",
    r"\b(React|Angular|Vue|Django|Flask|Spring|Laravel|Node\.js|Express)\b",
    r"\b(SQL|MySQL|PostgreSQL|MongoDB|Oracle|Redis|Cassandra)\b",
    r"\b(AWS|Azure|GCP|Docker|Kubernetes|Jenkins|Git|Linux|Windows Server)\b",
    r"\b(Cybersecurity|Pentest|SIEM|Firewall|IDS|IPS|SOC|ISO 27001)\b",
    r"\b(Agile|Scrum|Kanban|DevOps|CI/CD)\b",
    r"\b(SAP|Oracle|Totvs|Protheus|Microsoft Dynamics|Salesforce)\b",
    r"\b(PLC|SCADA|Industrial Automation|IoT|Sensors|Modbus|OPC)\b",
]

_ROLES_RE = re.compile(
    r"(Engineer|Developer|Manager|Director|Coordinator|Analyst|Architect|Lead|"
    r"Head of|CTO|CIO|CEO|VP|Supervisor)\s+(?:of|at|in)?\s+[\w\s]+",
    re.IGNORECASE,
)

_EDU_RE = re.compile(
    r"(Bachelor|Master|PhD|MBA|Graduation|Degree|Certified)\s+(?:in|of)?\s+[\w\s]+",
    re.IGNORECASE,
)


def _extract_skills(text: str) -> list[str]:
    """Extract technology keywords from free text."""
    skills: set[str] = set()
    for pattern in _TECH_PATTERNS:
        skills.update(m.group(0) for m in re.finditer(pattern, text, re.IGNORECASE))
    return sorted(skills)


def _search_professional_info(name: str, company: str) -> dict:
    """Search the web for professional information about a person."""
    results: dict = {
        "profile_summary": [],
        "skills": set(),
        "roles": set(),
        "education": set(),
    }

    if DDGS is None:
        return results

    queries = [
        f'"{name}" "{company}" site:linkedin.com',
        f'"{name}" curriculum vitae OR resume',
        f'"{name}" "{company}" conference OR speaker OR article',
    ]

    with DDGS() as ddgs:
        for query in queries:
            for r in ddgs.text(query, max_results=3):
                title = r.get("title", "")
                body = r.get("body", "")
                combined = f"{title} {body}"

                results["skills"].update(_extract_skills(combined))
                results["roles"].update(m.group(0) for m in _ROLES_RE.finditer(combined))
                results["education"].update(m.group(0) for m in _EDU_RE.finditer(body))

                results["profile_summary"].append({
                    "title": title,
                    "summary": body[:300] + "..." if len(body) > 300 else body,
                    "url": r.get("href", ""),
                })

    results["skills"] = sorted(results["skills"])
    results["roles"] = sorted(results["roles"])
    results["education"] = sorted(results["education"])
    return results


class ProfileAnalyzerInput(BaseModel):
    """Input schema for professional profile analysis."""

    name: str = Field(description="Full name of the person to analyse.")
    company: str = Field(default="", description="Company or organisation for context.")


@tool(args_schema=ProfileAnalyzerInput)
def analyze_professional_profile(name: str, company: str = "") -> dict:
    """Analyse a person's professional profile — career, skills, education."""
    try:
        data = _search_professional_info(name, company)
        return format_tool_output(
            "analyze_professional_profile", f"{name} ({company})", "ok",
            data=data,
        )
    except Exception as e:
        return format_tool_output(
            "analyze_professional_profile", f"{name} ({company})", "error",
            error=str(e),
        )
