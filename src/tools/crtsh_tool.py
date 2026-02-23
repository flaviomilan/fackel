"""Certificate Transparency subdomain enumeration tool.

Queries crt.sh (Comodo CT log aggregator) for SSL/TLS certificates
issued for a domain, extracting unique subdomains from certificate
name_value fields.  Free, no API key required.
"""

from __future__ import annotations

import requests
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from .utils import format_tool_output


class CrtShInput(BaseModel):
    """Input for crt.sh Certificate Transparency lookup."""

    domain: str = Field(
        description=(
            "Root domain to search (e.g. 'example.com'). "
            "Queries Certificate Transparency logs for all certificates "
            "issued to *.domain, revealing subdomains that had TLS certs."
        ),
    )


@tool(args_schema=CrtShInput)
def crtsh_subdomain_enum(domain: str) -> dict:
    """Enumerate subdomains via Certificate Transparency logs (crt.sh).

    Searches Comodo's CT log aggregator for certificates matching
    *.domain.  Every subdomain that ever had a TLS certificate appears
    here — often reveals staging, internal, and forgotten subdomains.
    Free, no API key required.  Most reliable passive subdomain source.
    """
    domain = domain.strip().lstrip("*.")

    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=45,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        return format_tool_output(
            "crtsh_subdomain_enum", domain, "error",
            error=f"crt.sh request failed: {exc}",
        )

    try:
        entries = resp.json()
    except ValueError:
        return format_tool_output(
            "crtsh_subdomain_enum", domain, "error",
            error="crt.sh returned non-JSON response (service may be overloaded).",
        )

    subdomains: set[str] = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lstrip("*.")
            if name and name != domain:
                subdomains.add(name.lower())

    return format_tool_output(
        "crtsh_subdomain_enum",
        domain,
        "ok",
        data={
            "count": len(subdomains),
            "subdomains": sorted(subdomains),
        },
    )
