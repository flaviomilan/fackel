from langchain.tools import tool

try:
    from ddgs import DDGS
except ImportError:
    try:
        from duckduckgo_search import DDGS

    except ImportError:
        DDGS = None

from .utils import format_tool_output


@tool
def duckduckgo_lookup(domain: str):
    """Busca OSINT no DuckDuckGo e retorna resultados estruturados."""
    if DDGS is None:
        return format_tool_output(
            "duckduckgo_lookup",
            domain,
            "error",
            error="ddgs não está instalado. pip install ddgs",
        )
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
            return format_tool_output(
                "duckduckgo_lookup",
                domain,
                "ok",
                data={"results": normalized},
            )
    except Exception as e:
        return format_tool_output(
            "duckduckgo_lookup",
            domain,
            "error",
            error=f"Erro ao buscar no DuckDuckGo: {e}",
        )
