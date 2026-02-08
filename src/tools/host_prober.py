import socket

import requests
from langchain.tools import tool


@tool
def probe_host(domain: str):
    """Resolve IP and probe HTTP/HTTPS with timeouts; returns structured payload."""
    try:
        ip_address = socket.gethostbyname(domain)
    except socket.gaierror:
        return {
            "tool": "probe_host",
            "status": "error",
            "domain": domain,
            "error": "DNS resolution failed. Host may not exist.",
        }
    except Exception as e:
        return {
            "tool": "probe_host",
            "status": "error",
            "domain": domain,
            "error": f"Unexpected DNS resolution error: {e}",
        }

    services = []
    ports_to_check = {80: "http", 443: "https"}
    for port, scheme in ports_to_check.items():
        url = f"{scheme}://{domain}"
        try:
            response = requests.get(
                url, timeout=5, verify=(scheme == "https"), allow_redirects=True
            )
            services.append(
                {
                    "scheme": scheme,
                    "port": port,
                    "status": "up",
                    "status_code": response.status_code,
                    "server": response.headers.get("Server", "N/A"),
                }
            )
        except requests.exceptions.RequestException:
            services.append(
                {
                    "scheme": scheme,
                    "port": port,
                    "status": "down",
                    "status_code": None,
                }
            )

    return {
        "tool": "probe_host",
        "status": "ok",
        "host": domain,
        "ip": ip_address,
        "services": services,
    }
