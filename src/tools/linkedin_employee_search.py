import os


from langchain.tools import tool
from serpapi import GoogleSearch

from .utils import format_tool_output


@tool
def search_linkedin_for_employees(company_name: str) -> dict:
    """Searches for employees of a given company on LinkedIn using SerpApi.
    This tool is highly effective for discovering key personnel, their roles, and their LinkedIn profiles.
    The input should be the company name.
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
