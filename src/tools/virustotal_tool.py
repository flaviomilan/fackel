
import os

import requests
from langchain.tools import tool

from .utils import format_tool_output


@tool
def virustotal_subdomain_enum(domain: str):
    """Enumerates subdomains using VirusTotal API (structured payload)."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return format_tool_output(
            "virustotal_subdomain_enum",
            domain,
            "error",
            error="VIRUSTOTAL_API_KEY not found in environment variables.",
        )

    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()

        data = response.json()
        subdomains = [item.get("id") for item in data.get("data", []) if item.get("id")]

        return format_tool_output(
            "virustotal_subdomain_enum",
            domain,
            "ok",
            data={
                "count": len(subdomains),
                "subdomains": subdomains,
            },
        )

    except requests.exceptions.HTTPError as http_err:
        return format_tool_output(
            "virustotal_subdomain_enum",
            domain,
            "error",
            error=f"HTTP {http_err.response.status_code}: {http_err.response.text}",
        )
    except Exception as e:
        return format_tool_output(
            "virustotal_subdomain_enum",
            domain,
            "error",
            error=f"Unexpected error while querying VirusTotal: {e}",
        )
