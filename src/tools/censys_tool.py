import os


from censys.search import CensysHosts
from langchain_core.tools import tool

from .utils import format_tool_output


@tool
def censys_lookup(domain: str):
    """Busca na API do Censys e retorna hosts/serviços de forma estruturada."""
    api_id = os.getenv("CENSYS_API_ID")
    api_secret = os.getenv("CENSYS_API_SECRET")

    if not api_id or not api_secret:
        return format_tool_output(
            "censys_lookup",
            domain,
            "error",
            error="CENSYS_API_ID e CENSYS_API_SECRET não configurados.",
        )

    try:
        h = CensysHosts(api_id=api_id, api_secret=api_secret)
        query = f"services.tls.certificates.leaf_data.subject.common_name: {domain} OR services.tls.certificates.leaf_data.subject.organization: {domain}"
        results = h.search(query, per_page=5)

        hosts: list[dict] = []
        for host in results:
            services = []
            for service in host.get("services", []):
                svc = {
                    "port": service.get("port"),
                    "protocol": service.get("transport_protocol"),
                    "name": service.get("service_name"),
                }
                services.append(svc)

            hosts.append(
                {
                    "ip": host.get("ip"),
                    "services": services,
                }
            )

        return format_tool_output(
            "censys_lookup",
            domain,
            "ok",
            data={"hosts": hosts},
        )

    except Exception as e:
        return format_tool_output(
            "censys_lookup",
            domain,
            "error",
            error=f"Erro ao consultar Censys: {e}",
        )
