"""Passive subdomain enumeration via the ProjectDiscovery Chaos dataset.

Chaos is a continuously-updated DNS dataset.  Querying it returns known
subdomains for a domain without ever touching the target — pure passive
recon that complements the active resolvers (subfinder/amass) and the other
passive sources (crt.sh, VirusTotal, DNSDumpster).

Requires ``CHAOS_API_KEY`` (free for registered users).
"""

from __future__ import annotations

from typing import Any

import requests
from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    format_tool_output,
    get_tool_timeout,
    guard_target,
    require_env,
)
from fackel.tooling.circuit_breaker import circuit_breaker
from fackel.tooling.http_client import get_session

_API_URL = "https://dns.projectdiscovery.io/dns/{domain}/subdomains"
_TIMEOUT = 20
_MAX_SUBDOMAINS = 1000


class ChaosInput(BaseModel):
    """Input for Chaos subdomain enumeration."""

    domain: str = Field(
        description=(
            "Domain to enumerate subdomains for (e.g. 'example.com'). "
            "Returns known subdomains from the ProjectDiscovery Chaos dataset "
            "— passive, no packets sent to the target."
        ),
    )


@tool(args_schema=ChaosInput)
def chaos_enum(domain: str) -> dict[str, Any]:
    """Enumerate a domain's subdomains from the ProjectDiscovery Chaos dataset.

    Returns a deduplicated list of fully-qualified subdomains.  Pure passive
    OSINT — the dataset is queried, never the target.  Requires
    CHAOS_API_KEY (free for registered users).
    """
    domain = guard_target(domain, "chaos_enum", TargetType.DOMAIN)
    api_key = require_env("CHAOS_API_KEY", "chaos_enum")

    with circuit_breaker("chaos"):
        try:
            resp = get_session().get(
                _API_URL.format(domain=domain),
                headers={"Authorization": api_key, "Accept": "application/json"},
                timeout=get_tool_timeout("chaos_enum", _TIMEOUT),
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise ToolException(f"chaos_enum: request failed: {exc}") from exc

    try:
        payload = resp.json()
    except ValueError:
        raise ToolException("chaos_enum: returned non-JSON response") from None

    base = domain.lower().rstrip(".")
    subdomains: list[str] = []
    seen: set[str] = set()
    for entry in payload.get("subdomains", []) or []:
        label = str(entry).strip().lower().rstrip(".")
        if not label:
            continue
        fqdn = base if label in ("", "@") else f"{label}.{base}"
        if fqdn not in seen:
            seen.add(fqdn)
            subdomains.append(fqdn)
        if len(subdomains) >= _MAX_SUBDOMAINS:
            break

    return format_tool_output(
        "chaos_enum",
        domain,
        "ok",
        data={"domain": base, "subdomains": subdomains, "count": len(subdomains)},
    )


chaos_enum.handle_tool_error = True
