import os

import shodan
from langchain.tools import tool


@tool
def shodan_lookup(query: str):
    """Busca informações OSINT no Shodan para o domínio ou IP informado (retorna payload estruturado)."""
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return {
            "tool": "shodan_lookup",
            "status": "error",
            "query": query,
            "error": "SHODAN_API_KEY não configurada nas variáveis de ambiente.",
        }

    api = shodan.Shodan(api_key)
    try:
        result = api.search(query)
        matches = []
        for match in result.get("matches", []):
            matches.append(
                {
                    "ip": match.get("ip_str"),
                    "port": match.get("port"),
                    "org": match.get("org"),
                    "data": match.get("data"),
                    "service": match.get("product"),
                }
            )

        return {
            "tool": "shodan_lookup",
            "status": "ok",
            "query": query,
            "total": result.get("total", 0),
            "matches": matches,
        }
    except Exception as e:
        return {
            "tool": "shodan_lookup",
            "status": "error",
            "query": query,
            "error": f"Erro ao consultar Shodan: {e}",
        }
