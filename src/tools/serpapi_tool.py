from langchain.tools import tool
import os
from serpapi import GoogleSearch

@tool
def serp_search(query: str) -> str:
    """Realiza uma busca avançada usando SerpAPI (Google Search)."""
    api_key = os.getenv("SERPAPI_API_KEY")
    if not api_key:
        return "SERPAPI_API_KEY não configurada nas variáveis de ambiente."

    try:

        params = {
            "q": query,
            "num": 10,
            "gl": "br",
            "api_key": api_key
        }


        search = GoogleSearch(params)
        results = search.get_dict()

        output = []


        if "organic_results" in results:
            for result in results["organic_results"]:
                title = result.get("title", "")
                snippet = result.get("snippet", "")
                link = result.get("link", "")
                output.append(f"Título: {title}\nResumo: {snippet}\nURL: {link}\n---")


        if "knowledge_graph" in results:
            kg = results["knowledge_graph"]
            output.append("\nInformações do Knowledge Graph:")
            for key, value in kg.items():
                if isinstance(value, str) and key not in ["image"]:
                    output.append(f"{key}: {value}")

        return "\n".join(output) if output else f"Nenhum resultado encontrado para: {query}"
    except Exception as e:
        return f"Erro ao consultar SerpAPI: {e}"
