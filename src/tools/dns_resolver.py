"""DNS resolution tool for passive OSINT reconnaissance."""

from __future__ import annotations

import ipaddress
import socket

from langchain_core.tools import tool

from .utils import format_tool_output


@tool
def dns_resolve(target: str) -> dict:
    """Resolve a domain to its IP addresses (A + AAAA records), or validate an IP.

    Use as the **first tool** in OSINT to discover the target's IP infrastructure.
    Returns both IPv4 and IPv6 addresses. Feed discovered IPs into whois_lookup
    and shodan_lookup for deeper passive intelligence.

    Args:
        target: Domain name (e.g. "example.com") or IP address to validate.

    Returns:
        target, list of resolved IPs (IPv4 + IPv6), and type ("domain" or "ip").
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
