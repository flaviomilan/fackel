"""VirusTotal passive subdomain enumeration."""

from __future__ import annotations

from typing import Any

import requests
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target, require_env

_TIMEOUT = 20  # seconds


class VirusTotalSubdomainInput(BaseModel):
    """Input for VirusTotal subdomain enumeration."""

    domain: str = Field(
        description=(
            "Root domain to enumerate (e.g. 'example.com'). "
            "Must be a plain domain name — do NOT pass subdomains, IPs, or URLs."
        ),
    )


@tool(args_schema=VirusTotalSubdomainInput)
def virustotal_subdomain_enum(domain: str) -> dict[str, Any]:
    """Enumerate subdomains passively via VirusTotal's global sensor network.

    Queries VirusTotal's passive DNS dataset.  Returns up to 40 subdomains.
    Requires VIRUSTOTAL_API_KEY environment variable.
    """
    domain, err = guard_target(domain, "virustotal_subdomain_enum", TargetType.DOMAIN)
    if err:
        return err

    api_key, env_err = require_env("VIRUSTOTAL_API_KEY", "virustotal_subdomain_enum", domain)
    if env_err:
        return env_err

    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=_TIMEOUT)
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
