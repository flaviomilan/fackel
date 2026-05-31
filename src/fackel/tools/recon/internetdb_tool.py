"""Shodan InternetDB — free, key-less passive host data.

Queries ``https://internetdb.shodan.io/<ip>`` which returns Shodan's
last-known open ports, CPEs, known CVEs, hostnames, and tags for an IP
**without any API key**.  This is the free counterpart to ``shodan_lookup``
and makes passive port/vulnerability intelligence available out of the box.

The request goes to Shodan's API (a fixed third-party endpoint), never to
the target, so it stays fully passive.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, get_tool_timeout, guard_target
from fackel.tooling.circuit_breaker import circuit_breaker
from fackel.tooling.http_client import get_session

_INTERNETDB_URL = "https://internetdb.shodan.io"
_TIMEOUT = 15


class InternetDbInput(BaseModel):
    """Input for the Shodan InternetDB lookup."""

    ip: str = Field(
        description=(
            "IPv4 address to look up (e.g. '104.21.36.250'). Returns Shodan's "
            "last-known open ports, CPEs, known CVEs, hostnames, and tags — no "
            "API key required. Free alternative to shodan_lookup; call once per "
            "discovered IP for passive port/vulnerability intelligence."
        ),
    )


@tool(args_schema=InternetDbInput)
def internetdb_lookup(ip: str) -> dict[str, Any]:
    """Look up an IP's open ports, CPEs, and known CVEs via Shodan InternetDB.

    Free and key-less.  Returns passive, last-known data Shodan has observed
    for the IP — open ports, software CPEs, associated CVE IDs, reverse
    hostnames, and tags.  Use it as the no-key alternative to shodan_lookup
    to surface likely services and vulnerabilities before any active scan.
    """
    ip = guard_target(ip, "internetdb_lookup", TargetType.IP)

    import requests

    with circuit_breaker("internetdb"):
        try:
            resp = get_session().get(
                f"{_INTERNETDB_URL}/{ip}",
                timeout=get_tool_timeout("internetdb_lookup", _TIMEOUT),
                headers={"Accept": "application/json"},
            )
        except requests.RequestException as exc:
            raise ToolException(f"internetdb_lookup: request failed: {exc}") from exc

    # InternetDB returns 404 for IPs it has no data on — a valid empty result.
    if resp.status_code == 404:
        return format_tool_output(
            "internetdb_lookup",
            ip,
            "ok",
            data={
                "ip": ip,
                "ports": [],
                "cpes": [],
                "vulns": [],
                "hostnames": [],
                "tags": [],
                "message": "no InternetDB data for this IP",
            },
        )

    try:
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise ToolException(f"internetdb_lookup: request failed: {exc}") from exc

    try:
        data = resp.json()
    except ValueError:
        raise ToolException("internetdb_lookup: returned non-JSON response") from None

    return format_tool_output(
        "internetdb_lookup",
        ip,
        "ok",
        data={
            "ip": data.get("ip", ip),
            "ports": data.get("ports", []),
            "cpes": data.get("cpes", []),
            "vulns": data.get("vulns", []),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []),
        },
    )


internetdb_lookup.handle_tool_error = True
