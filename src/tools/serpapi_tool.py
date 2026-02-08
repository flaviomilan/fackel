
import os

from langchain.tools import tool
from serpapi import GoogleSearch

from .utils import format_tool_output


@tool
def serp_search(query: str):
    """Realiza busca no Google via SerpAPI e retorna resultados estruturados."""
    api_key = os.getenv("SERPAPI_API_KEY")
    if not api_key:
        return format_tool_output(
            "serp_search",
            query,
            "error",
            error="SERPAPI_API_KEY não configurada.",
        )

    try:
        params = {"q": query, "num": 10, "gl": "br", "api_key": api_key}
        search = GoogleSearch(params)
        results = search.get_dict()

        organic = []
        for result in results.get("organic_results", []):
            organic.append(
                {
                    "title": result.get("title"),
                    "snippet": result.get("snippet"),
                    "link": result.get("link"),
                }
            )

        return format_tool_output(
            "serp_search",
            query,
            "ok",
            data={"results": organic},
        )
    except Exception as e:
        return format_tool_output(
            "serp_search",
            query,
            "error",
            error=f"Erro ao consultar SerpAPI: {e}",
        )
