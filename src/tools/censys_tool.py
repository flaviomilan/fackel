import os
from langchain.tools import tool
from typing import Dict, Any
from censys.search import CensysHosts

@tool
def censys_lookup(domain: str) -> str:
    """Busca na API do Censys por hosts, endereços IP, serviços, portas abertas e certificados SSL/TLS associados a um domínio. É uma ferramenta essencial para o reconhecimento de infraestrutura técnica."""
    api_id = os.getenv("CENSYS_API_ID")
    api_secret = os.getenv("CENSYS_API_SECRET")

    if not api_id or not api_secret:
        return "CENSYS_API_ID e CENSYS_API_SECRET não configurados nas variáveis de ambiente."

    try:

        h = CensysHosts(api_id=api_id, api_secret=api_secret)


        query = f"services.tls.certificates.leaf_data.subject.common_name: {domain} OR services.tls.certificates.leaf_data.subject.organization: {domain}"
        results = h.search(query, per_page=5)

        output = []


        for host in results:
            ip = host.get("ip", "Desconhecido")
            output.append(f"\nIP: {ip}")


            if "services" in host:
                output.append("Serviços:")
                for service in host["services"]:
                    port = service.get("port", "Desconhecido")
                    service_name = service.get("service_name", "Desconhecido")
                    transport_protocol = service.get("transport_protocol", "Desconhecido")

                    output.append(f"  - Porto: {port}")
                    output.append(f"    Serviço: {service_name}")
                    output.append(f"    Protocolo: {transport_protocol}")


                    if "tls" in service:
                        tls = service["tls"]
                        if "certificates" in tls and "leaf_data" in tls["certificates"]:
                            cert = tls["certificates"]["leaf_data"]
                            output.append("    Certificado SSL/TLS:")
                            if "subject" in cert:
                                output.append(f"      - Emitido para: {cert['subject'].get('common_name', 'N/A')}")
                            if "issuer" in cert:
                                output.append(f"      - Emitido por: {cert['issuer'].get('common_name', 'N/A')}")
                            if "validity" in cert:
                                output.append(f"      - Válido até: {cert['validity'].get('end', 'N/A')}")


            if "operating_system" in host:
                os_info = host["operating_system"]
                output.append("\nSistema Operacional:")
                output.append(f"  - Nome: {os_info.get('product', 'Desconhecido')}")
                output.append(f"  - Versão: {os_info.get('version', 'Desconhecida')}")


            if "software" in host:
                output.append("\nSoftware:")
                for software in host["software"]:
                    output.append(f"  - {software.get('product', 'Desconhecido')} {software.get('version', '')}")

            output.append("-" * 50)

        return "\n".join(output) if output else f"Nenhum resultado encontrado para: {domain}"

    except Exception as e:
        return f"Erro ao consultar Censys: {e}"
