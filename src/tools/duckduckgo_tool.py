from langchain.tools import tool

try:
    from ddgs import DDGS
except ImportError:
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        DDGS = None


@tool
def duckduckgo_lookup(domain: str):
    """Busca OSINT no DuckDuckGo e retorna resultados estruturados."""
    if DDGS is None:
        return {
            "tool": "duckduckgo_lookup",
            "status": "error",
            "query": domain,
            "error": "ddgs não está instalado. pip install ddgs",
        }
    try:
        with DDGS() as ddgs:
            results = ddgs.text(domain, max_results=5)
            normalized = []
            for r in results:
                normalized.append(
                    {
                        "title": r.get("title", ""),
                        "snippet": r.get("body", ""),
                        "link": r.get("href", ""),
                    }
                )
            return {
                "tool": "duckduckgo_lookup",
                "status": "ok",
                "query": domain,
                "results": normalized,
            }
    except Exception as e:
        return {
            "tool": "duckduckgo_lookup",
            "status": "error",
            "query": domain,
            "error": f"Erro ao buscar no DuckDuckGo: {e}",
        }
