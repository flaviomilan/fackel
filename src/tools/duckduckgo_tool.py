"""DuckDuckGo OSINT search."""

from __future__ import annotations

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from .utils import DDGS, format_tool_output


class DuckDuckGoInput(BaseModel):
    """Input schema for DuckDuckGo search."""

    domain: str = Field(description="Domain or query to search for OSINT information.")


@tool(args_schema=DuckDuckGoInput)
def duckduckgo_lookup(domain: str) -> dict:
    """Search DuckDuckGo for OSINT information about a domain or query."""
    if DDGS is None:
        return format_tool_output(
            "duckduckgo_lookup", domain, "error",
            error="ddgs not installed. pip install ddgs",
        )
    try:
        with DDGS() as ddgs:
            results = ddgs.text(domain, max_results=5)
            normalised = [
                {
                    "title": r.get("title", ""),
                    "snippet": r.get("body", ""),
                    "link": r.get("href", ""),
                }
                for r in results
            ]
            return format_tool_output(
                "duckduckgo_lookup", domain, "ok",
                data={"results": normalised},
            )
    except Exception as e:
        return format_tool_output(
            "duckduckgo_lookup", domain, "error",
            error=f"DuckDuckGo search failed: {e}",
        )
