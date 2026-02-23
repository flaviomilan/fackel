"""Google search via SerpAPI."""

from __future__ import annotations

import os

from langchain_core.tools import tool
from pydantic import BaseModel, Field
from serpapi import GoogleSearch

from .utils import format_tool_output


class SerpApiInput(BaseModel):
    """Input schema for SerpAPI Google search."""

    query: str = Field(description="Search query to run on Google via SerpAPI.")


@tool(args_schema=SerpApiInput)
def serp_search(query: str) -> dict:
    """Search Google via SerpAPI and return structured organic results."""
    api_key = os.getenv("SERPAPI_API_KEY")
    if not api_key:
        return format_tool_output(
            "serp_search", query, "error",
            error="SERPAPI_API_KEY not configured.",
        )

    try:
        params = {"q": query, "num": 10, "gl": "br", "api_key": api_key}
        search = GoogleSearch(params)
        results = search.get_dict()

        organic = [
            {
                "title": r.get("title"),
                "snippet": r.get("snippet"),
                "link": r.get("link"),
            }
            for r in results.get("organic_results", [])
        ]

        return format_tool_output("serp_search", query, "ok", data={"results": organic})
    except Exception as e:
        return format_tool_output("serp_search", query, "error", error=f"SerpAPI search failed: {e}")
