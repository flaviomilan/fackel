"""LinkedIn employee discovery via SerpAPI."""

from __future__ import annotations

import os

from langchain_core.tools import tool
from pydantic import BaseModel, Field
from serpapi import GoogleSearch

from .utils import format_tool_output


class LinkedInEmployeeInput(BaseModel):
    """Input schema for LinkedIn employee search."""

    company_name: str = Field(
        description="Company name to search for employees on LinkedIn.",
    )


@tool(args_schema=LinkedInEmployeeInput)
def search_linkedin_for_employees(company_name: str) -> dict:
    """Search for employees of a company on LinkedIn via SerpAPI.

    Discovers key personnel, their roles, and LinkedIn profile links.
    """
    api_key = os.getenv("SERPAPI_API_KEY")
    if not api_key:
        return format_tool_output(
            "search_linkedin_for_employees",
            company_name,
            "error",
            error="SERPAPI_API_KEY not found in environment variables.",
        )

    try:

        query = f'site:linkedin.com/in "people" "works at {company_name}" OR "worked at {company_name}"'

        params = {"q": query, "engine": "google", "num": 20, "api_key": api_key}

        search = GoogleSearch(params)
        results = search.get_dict()

        profiles = results.get("organic_results", [])

        if not profiles:
            return format_tool_output(
                "search_linkedin_for_employees",
                company_name,
                "ok",
                message=f"No employee profiles found for {company_name} on LinkedIn via Google search.",
                data={"profiles": []},
            )

        output_profiles = []
        for profile in profiles:
            title = profile.get("title", "No title found")
            link = profile.get("link", "No link found")
            snippet = profile.get("snippet", "No snippet found")

            name_and_role = title.replace(" - LinkedIn", "").strip()
            output_profiles.append(
                {
                    "name_and_role": name_and_role,
                    "link": link,
                    "snippet": snippet,
                }
            )

        return format_tool_output(
            "search_linkedin_for_employees",
            company_name,
            "ok",
            data={"profiles": output_profiles},
        )

    except Exception as e:
        return format_tool_output(
            "search_linkedin_for_employees",
            company_name,
            "error",
            error=f"An unexpected error occurred while searching for employees on LinkedIn: {e}",
        )
