"""Reverse DNS and reverse IP lookup tool.

Performs PTR record lookups via system resolver and queries HackerTarget's
free reverse IP API to discover other domains hosted on the same IP
(shared hosting detection).
"""

from __future__ import annotations

import logging
import socket
from typing import Any

import requests
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target

logger = logging.getLogger(__name__)

_TIMEOUT = 15  # seconds


class ReverseDnsInput(BaseModel):
    """Input for reverse DNS / reverse IP lookup."""

    ip: str = Field(
        description=(
            "IPv4 address to look up (e.g. '104.21.36.250'). "
            "Returns the PTR hostname and other domains sharing this IP. "
            "Call once per discovered IP to detect shared hosting."
        ),
    )


@tool(args_schema=ReverseDnsInput)
def reverse_dns_lookup(ip: str) -> dict[str, Any]:
    """Reverse-resolve an IP to its PTR hostname and discover co-hosted domains.

    Combines two passive techniques: system PTR lookup (instant) and
    HackerTarget's reverse IP database (shared hosting discovery).
    Reveals if the IP hosts other domains — critical for shared-hosting
    environments where one compromised neighbour affects all tenants.
    No API key required.
    """
    ip, err = guard_target(ip, "reverse_dns_lookup", TargetType.IP)
    if err:
        return err

    ptr_hostname: str | None = None
    ptr_aliases: list[str] = []
    shared_domains: list[str] = []

    # --- PTR record via system resolver ---
    try:
        result = socket.gethostbyaddr(ip)
        ptr_hostname = result[0]
        ptr_aliases = list(result[1]) if result[1] else []
    except socket.herror:
        logger.debug("No PTR record for %s", ip)
    except Exception:
        logger.debug("PTR lookup failed for %s", ip)

    # --- HackerTarget reverse IP (free, no key) ---
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            text = resp.text.strip()
            if not text.startswith("error") and not text.startswith("API count"):
                shared_domains = [line.strip() for line in text.split("\n") if line.strip()]
    except requests.RequestException:
        pass  # Best-effort — continue with PTR data alone

    return format_tool_output(
        "reverse_dns_lookup",
        ip,
        "ok",
        data={
            "ptr_hostname": ptr_hostname,
            "ptr_aliases": ptr_aliases,
            "shared_domains": shared_domains,
            "shared_domain_count": len(shared_domains),
        },
    )
