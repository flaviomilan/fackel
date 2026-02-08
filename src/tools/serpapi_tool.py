import os

from langchain.tools import tool
from serpapi import GoogleSearch


@tool
def serp_search(query: str):
    """Realiza busca no Google via SerpAPI e retorna resultados estruturados."""
    api_key = os.getenv("SERPAPI_API_KEY")
    if not api_key:
        return {
            "tool": "serp_search",
            "status": "error",
            "query": query,
            "error": "SERPAPI_API_KEY não configurada.",
        }

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

        return {
            "tool": "serp_search",
            "status": "ok",
            "query": query,
            "results": organic,
        }
    except Exception as e:
        return {
            "tool": "serp_search",
            "status": "error",
            "query": query,
            "error": f"Erro ao consultar SerpAPI: {e}",
        }
