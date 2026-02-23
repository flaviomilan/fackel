"""DNS resolution tool for passive OSINT reconnaissance."""

from __future__ import annotations

import ipaddress
import socket

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from .utils import format_tool_output


class DnsResolveInput(BaseModel):
    """Input for DNS resolution."""

    target: str = Field(
        description=(
            "Domain name (e.g. 'example.com') to resolve to IPv4/IPv6 addresses, "
            "or a bare IP address to validate. Do NOT pass URLs."
        ),
    )


@tool(args_schema=DnsResolveInput)
def dns_resolve(target: str) -> dict:
    """Resolve a domain to its IP addresses (A + AAAA records), or validate an IP.

    Use as the **first tool** in OSINT to discover the target's IP infrastructure.
    Returns both IPv4 and IPv6 addresses.  Feed discovered IPs into shodan_lookup
    for deeper passive intelligence.
    """
    target = target.strip()

    try:
        ipaddress.ip_address(target)
        return format_tool_output(
            "dns_resolve", target, "ok",
            data={"target": target, "ips": [target], "type": "ip"},
        )
    except ValueError:
        pass

    try:
        resolved: set[str] = set()
        for result in socket.getaddrinfo(target, None):
            resolved.add(result[4][0])
        return format_tool_output(
            "dns_resolve", target, "ok",
            data={"target": target, "ips": sorted(resolved), "type": "domain"},
        )
    except Exception as exc:
        return format_tool_output(
            "dns_resolve", target, "error",
            error=str(exc),
        )
