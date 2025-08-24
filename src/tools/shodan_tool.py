import os

import shodan
from langchain.tools import tool


@tool
def shodan_lookup(query: str) -> str:
    """Busca informações OSINT no Shodan para o domínio ou IP informado."""
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return "SHODAN_API_KEY não configurada nas variáveis de ambiente."
    api = shodan.Shodan(api_key)
    try:
        result = api.search(query)
        if not result["matches"]:
            return f"Nenhum resultado encontrado para: {query}"
        output = []
        for match in result["matches"]:
            ip = match.get("ip_str", "")
            port = match.get("port", "")
            org = match.get("org", "")
            data = match.get("data", "")
            output.append(f"IP: {ip}, Port: {port}, Org: {org}\nData: {data}\n---")
        return "\n".join(output)
    except Exception as e:
        return f"Erro ao consultar Shodan: {e}"
