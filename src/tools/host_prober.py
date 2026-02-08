import socket
from urllib.parse import urlparse


import requests
from langchain.tools import tool

from .utils import format_tool_output


@tool
def probe_host(domain: str):
    """Resolve IP and probe HTTP/HTTPS with timeouts; returns structured payload."""
    parsed = urlparse(domain)
    target = parsed.netloc or parsed.path or domain
    if not target:
        return format_tool_output(
            "probe_host",
            domain,
            "error",
            error="alvo inválido",
        )
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        return format_tool_output(
            "probe_host",
            domain,
            "error",
            error="DNS resolution failed. Host may not exist.",
        )
    except Exception as e:
        return format_tool_output(
            "probe_host",
            domain,
            "error",
            error=f"Unexpected DNS resolution error: {e}",
        )

    services = []
    ports_to_check = {80: "http", 443: "https"}
    for port, scheme in ports_to_check.items():
        url = f"{scheme}://{target}"
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

    return format_tool_output(
        "probe_host",
        domain,
        "ok",
        data={
            "host": target,
            "ip": ip_address,
            "services": services,
        },
    )
