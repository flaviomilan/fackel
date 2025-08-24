from langchain.tools import tool
try:
    from ddgs import DDGS
except ImportError:
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        DDGS = None

@tool
def duckduckgo_lookup(domain: str) -> str:
    """Busca informações OSINT no DuckDuckGo para o domínio informado."""
    if DDGS is None:
        return "ddgs não está instalado. Execute: pip install ddgs"
    try:
        with DDGS() as ddgs:
            results = ddgs.text(domain, max_results=5)
            output = []
            for r in results:
                title = r.get('title', '')
                body = r.get('body', '')
                url = r.get('href', '')
                output.append(f"Título: {title}\nResumo: {body}\nURL: {url}\n---")
            return '\n'.join(output) if output else f"Nenhum resultado encontrado para: {domain}"
    except Exception as e:
        return f"Erro ao buscar no DuckDuckGo: {e}"
