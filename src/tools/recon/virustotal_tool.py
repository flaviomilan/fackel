"""VirusTotal passive subdomain enumeration."""

from __future__ import annotations

from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    format_tool_output,
    get_tool_timeout,
    guard_target,
    require_env,
)
from tools.circuit_breaker import circuit_breaker
from tools.http_client import get_session

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
    domain = guard_target(domain, "virustotal_subdomain_enum", TargetType.DOMAIN)
    api_key = require_env("VIRUSTOTAL_API_KEY", "virustotal_subdomain_enum")

    import requests

    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    headers = {"x-apikey": api_key}

    with circuit_breaker("virustotal"):
        try:
            response = get_session().get(
                url,
                headers=headers,
                timeout=get_tool_timeout("virustotal_subdomain_enum", _TIMEOUT),
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise ToolException(f"virustotal_subdomain_enum: request failed: {exc}") from exc

        try:
            data = response.json()
        except ValueError:
            raise ToolException("virustotal_subdomain_enum: returned non-JSON response") from None

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


virustotal_subdomain_enum.handle_tool_error = True
