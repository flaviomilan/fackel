
import os

import requests
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from .utils import format_tool_output
from .validators import TargetType, guard_target


class VirusTotalSubdomainInput(BaseModel):
    """Input for VirusTotal subdomain enumeration."""

    domain: str = Field(
        description=(
            "Root domain to enumerate (e.g. 'example.com'). "
            "Must be a plain domain name — do NOT pass subdomains, IPs, or URLs."
        ),
    )


@tool(args_schema=VirusTotalSubdomainInput)
def virustotal_subdomain_enum(domain: str) -> dict:
    """Enumerate subdomains passively via VirusTotal's global sensor network.

    Queries VirusTotal's passive DNS dataset.  Returns up to 40 subdomains.
    Requires VIRUSTOTAL_API_KEY environment variable.
    """
    domain, err = guard_target(domain, "virustotal_subdomain_enum", TargetType.DOMAIN)
    if err:
        return err

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
