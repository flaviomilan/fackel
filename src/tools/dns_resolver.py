"""DNS resolution tool for passive OSINT reconnaissance."""

from __future__ import annotations

import ipaddress
import socket

from langchain.tools import tool


@tool
def dns_resolve(target: str) -> dict:
    """Resolve a domain name to its IP addresses, or validate an IP.

    For domains: performs a DNS lookup and returns all resolved IPs.
    For IPs: returns the IP itself unchanged.
    """
    target = target.strip()

    try:
        ipaddress.ip_address(target)
        return {"target": target, "ips": [target], "type": "ip"}
    except ValueError:
        pass

    try:
        resolved: set[str] = set()
        for result in socket.getaddrinfo(target, None):
            resolved.add(result[4][0])
        return {"target": target, "ips": sorted(resolved), "type": "domain"}
    except Exception as exc:
        return {"target": target, "ips": [], "type": "domain", "error": str(exc)}
