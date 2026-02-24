"""Job posting search for tech stack discovery."""

from __future__ import annotations

from typing import Any

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from fackel.tooling import DDGS, format_tool_output


class JobSearchInput(BaseModel):
    """Input schema for job posting search."""

    company_name: str = Field(
        description="Company or organisation name to search job postings for.",
    )


@tool(args_schema=JobSearchInput)
def job_search(company_name: str) -> dict[str, Any]:
    """Search job postings to identify technologies and systems used by the target organisation.

    Reveals tech stack, cloud providers, frameworks, and internal tools from
    public job listings — pure passive OSINT.
    """
    company_name = company_name.strip()
    if not company_name:
        return format_tool_output(
            "job_search",
            company_name,
            "error",
            error="company name is empty",
        )
    if DDGS is None:
        return format_tool_output(
            "job_search",
            company_name,
            "error",
            error="ddgs not installed. pip install ddgs",
        )
    try:
        with DDGS() as ddgs:
            query = (
                f'"{company_name}" (vagas OR trabalhe-conosco OR carreiras) '
                f"(site:linkedin.com/jobs OR site:gupy.io OR site:vagas.com.br "
                f"OR site:indeed.com.br)"
            )
            results = ddgs.text(query, max_results=5)

            job_posts = [
                {
                    "title": r.get("title", ""),
                    "body": r.get("body", ""),
                    "url": r.get("href", ""),
                    "type": "job",
                }
                for r in results
            ]

            careers_query = (
                f'"{company_name}" (trabalhe-conosco OR carreiras OR opportunities OR careers)'
            )
            career_results = ddgs.text(careers_query, max_results=2)
            career_keywords = {"trabalhe", "carreira", "vaga", "opportunit", "career"}
            for r in career_results:
                title = r.get("title", "")
                if any(kw in title.lower() for kw in career_keywords):
                    job_posts.append(
                        {
                            "title": title,
                            "body": r.get("body", ""),
                            "url": r.get("href", ""),
                            "type": "career_page",
                        }
                    )

            return format_tool_output(
                "job_search",
                company_name,
                "ok",
                data={"results": job_posts},
            )
    except Exception as e:
        return format_tool_output(
            "job_search",
            company_name,
            "error",
            error=f"Job search failed: {e}",
        )
