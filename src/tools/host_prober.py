import socket

import requests
from langchain.tools import tool


@tool
def probe_host(domain: str) -> str:
    """Takes a domain/subdomain, resolves its IP address, and checks for active HTTP/HTTPS web servers.
    Use this to quickly validate if a discovered subdomain is a live web target before running a full Nmap scan.
    WARNING: This is an ACTIVE scanning tool. It directly connects to the target.
    """
    output = [f"Probing results for {domain}:"]

    try:
        ip_address = socket.gethostbyname(domain)
        output.append(f"- IP Address: {ip_address}")
    except socket.gaierror:
        return f"DNS resolution failed for {domain}. Host may not exist."
    except Exception as e:
        return f"An unexpected error occurred during DNS resolution: {e}"

    ports_to_check = {80: "http", 443: "https"}
    found_services = False

    for port, scheme in ports_to_check.items():
        url = f"{scheme}://{domain}"
        try:
            response = requests.get(
                url, timeout=5, verify=(scheme == "https"), allow_redirects=True
            )
            output.append(
                f"- {scheme.upper()} (Port {port}): Found - Status Code: {response.status_code}"
            )

            server_header = response.headers.get("Server", "N/A")
            output.append(f"  - Server: {server_header}")
            found_services = True
        except requests.exceptions.RequestException as e:
            output.append(
                f"- {scheme.upper()} (Port {port}): Not found or no response."
            )

    if not found_services:
        output.append("- No common web services found on ports 80 or 443.")

    return "\n".join(output)
