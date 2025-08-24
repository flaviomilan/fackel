import os
from serpapi import GoogleSearch
from langchain.tools import tool

@tool
def search_linkedin_for_employees(company_name: str) -> str:
    """Searches for employees of a given company on LinkedIn using SerpApi.
    This tool is highly effective for discovering key personnel, their roles, and their LinkedIn profiles.
    The input should be the company name.
    """
    api_key = os.getenv("SERPAPI_API_KEY")
    if not api_key:
        return "SERPAPI_API_KEY not found in environment variables."

    try:

        query = f'site:linkedin.com/in "people" "works at {company_name}" OR "worked at {company_name}"'

        params = {
            "q": query,
            "engine": "google",
            "num": 20,
            "api_key": api_key
        }

        search = GoogleSearch(params)
        results = search.get_dict()

        profiles = results.get("organic_results", [])

        if not profiles:
            return f"No employee profiles found for {company_name} on LinkedIn via Google search."

        output = [f"Found {len(profiles)} potential employee profiles for {company_name}:\n"]
        for profile in profiles:
            title = profile.get("title", "No title found")
            link = profile.get("link", "No link found")
            snippet = profile.get("snippet", "No snippet found")
            

            name_and_role = title.replace(" - LinkedIn", "").strip()
            output.append(f"- Profile: {name_and_role}")
            output.append(f"  Link: {link}")
            output.append(f"  Summary: {snippet}")
            output.append("---")

        return "\n".join(output)

    except Exception as e:
        return f"An unexpected error occurred while searching for employees on LinkedIn: {e}"
