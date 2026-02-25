"""Shodan passive intelligence lookup."""

from __future__ import annotations

from typing import Any

import shodan
from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target, is_valid_ip, require_env


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
def shodan_lookup(query: str) -> dict[str, Any]:
    """Query Shodan for passive intelligence — no packets sent to the target.

    Uses the host API for IP lookups (services, banners, ports, org, ISP,
    hostnames, CVEs) or the search API for query strings.
    Requires SHODAN_API_KEY environment variable.
    """
    query = guard_target(query, "shodan_lookup", TargetType.HOST)

    api_key = require_env("SHODAN_API_KEY", "shodan_lookup")

    api = shodan.Shodan(api_key)
    try:
        if is_valid_ip(query):
            host = api.host(query.strip())
            services = []
            for item in host.get("data", []):
                services.append(
                    {
                        "port": item.get("port"),
                        "transport": item.get("transport", "tcp"),
                        "product": item.get("product", ""),
                        "version": item.get("version", ""),
                        "banner": (item.get("data", ""))[:300],
                        "module": item.get("_shodan", {}).get("module", ""),
                    }
                )

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
            result = api.search(query)
            matches = []
            for match in result.get("matches", []):
                matches.append(
                    {
                        "ip": match.get("ip_str"),
                        "port": match.get("port"),
                        "org": match.get("org"),
                        "data": (match.get("data", ""))[:300],
                        "service": match.get("product"),
                    }
                )

            return format_tool_output(
                "shodan_lookup",
                query,
                "ok",
                data={"total": result.get("total", 0), "matches": matches},
            )
    except Exception as e:
        raise ToolException(f"shodan_lookup: Shodan query failed: {e}") from e


shodan_lookup.handle_tool_error = True
