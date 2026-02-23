
import ipaddress
import os

import shodan
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from .utils import format_tool_output


def _is_ip(value: str) -> bool:
    """Check if value is a valid IP address."""
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


class ShodanInput(BaseModel):
    """Input for Shodan passive intelligence lookup."""

    query: str = Field(
        description=(
            "An IP address (e.g. '104.21.36.250') for the host API — returns "
            "organization, ISP, open ports, banners, hostnames, and known CVEs. "
            "Or a Shodan search query (e.g. 'hostname:example.com', 'apache country:BR') "
            "for broader discovery across Shodan's indexed database. "
            "Always prefer IP addresses for richer per-host data."
        ),
    )


@tool(args_schema=ShodanInput)
def shodan_lookup(query: str) -> dict:
    """Query Shodan for passive intelligence — no packets sent to the target.

    Uses the host API for IP lookups (services, banners, ports, org, ISP,
    hostnames, CVEs) or the search API for query strings.
    Requires SHODAN_API_KEY environment variable.
    """
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return format_tool_output(
            "shodan_lookup",
            query,
            "error",
            error="SHODAN_API_KEY environment variable not configured.",
        )

    api = shodan.Shodan(api_key)
    try:
        if _is_ip(query):
            # Direct host lookup — much richer data than search
            host = api.host(query.strip())
            services = []
            for item in host.get("data", []):
                services.append({
                    "port": item.get("port"),
                    "transport": item.get("transport", "tcp"),
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                    "banner": (item.get("data", ""))[:300],
                    "module": item.get("_shodan", {}).get("module", ""),
                })

            return format_tool_output(
                "shodan_lookup",
                query,
                "ok",
                data={
                    "ip": host.get("ip_str"),
                    "org": host.get("org"),
                    "isp": host.get("isp"),
                    "os": host.get("os"),
                    "hostnames": host.get("hostnames", []),
                    "ports": host.get("ports", []),
                    "city": host.get("city"),
                    "country_name": host.get("country_name"),
                    "last_update": host.get("last_update"),
                    "vulns": host.get("vulns", []),
                    "services": services,
                },
            )
        else:
            # Generic search
            result = api.search(query)
            matches = []
            for match in result.get("matches", []):
                matches.append({
                    "ip": match.get("ip_str"),
                    "port": match.get("port"),
                    "org": match.get("org"),
                    "data": (match.get("data", ""))[:300],
                    "service": match.get("product"),
                })

            return format_tool_output(
                "shodan_lookup",
                query,
                "ok",
                data={"total": result.get("total", 0), "matches": matches},
            )
    except Exception as e:
        return format_tool_output(
            "shodan_lookup",
            query,
            "error",
            error=f"Shodan query failed: {e}",
        )
