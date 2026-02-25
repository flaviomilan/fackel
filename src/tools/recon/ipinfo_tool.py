"""IP geolocation and ASN lookup via ipinfo.io.

Free tier: 50 000 requests/month without an API key for basic fields.
Returns organisation, ASN, CIDR, city, country, and anycast flag.
"""

from __future__ import annotations

from typing import Any

import requests
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target

_IPINFO_URL = "https://ipinfo.io"
_TIMEOUT = 15


class IpInfoInput(BaseModel):
    """Input for ipinfo.io IP lookup."""

    ip: str = Field(
        description=(
            "IPv4 address to look up (e.g. '104.21.36.250'). "
            "Returns ASN, organisation, CIDR, geolocation, and anycast flag. "
            "Call once per discovered IP to classify infrastructure."
        ),
    )


@tool(args_schema=IpInfoInput)
def ipinfo_lookup(ip: str) -> dict[str, Any]:
    """Look up IP geolocation, ASN, and organisation via ipinfo.io.

    Free, no API key required for basic fields.  Returns the AS number,
    organisation name, CIDR block, city, region, country, and whether the
    IP is an anycast address (common for CDNs like Cloudflare).
    Use this to classify IPs as CDN, cloud, ISP, or direct-host.
    """
    ip, err = guard_target(ip, "ipinfo_lookup", TargetType.IP)
    if err:
        return err

    try:
        resp = requests.get(
            f"{_IPINFO_URL}/{ip}/json",
            timeout=_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        return format_tool_output(
            "ipinfo_lookup",
            ip,
            "error",
            error=f"ipinfo.io request failed: {exc}",
        )

    try:
        data = resp.json()
    except ValueError:
        return format_tool_output(
            "ipinfo_lookup",
            ip,
            "error",
            error="ipinfo.io returned non-JSON response.",
        )

    # The "org" field from ipinfo has the format "AS13335 Cloudflare, Inc."
    raw_org = data.get("org", "")
    asn = ""
    org_name = raw_org
    if raw_org.startswith("AS"):
        parts = raw_org.split(" ", 1)
        asn = parts[0]
        org_name = parts[1] if len(parts) > 1 else ""

    return format_tool_output(
        "ipinfo_lookup",
        ip,
        "ok",
        data={
            "ip": data.get("ip", ip),
            "hostname": data.get("hostname", ""),
            "city": data.get("city", ""),
            "region": data.get("region", ""),
            "country": data.get("country", ""),
            "org": org_name.strip(),
            "asn": asn,
            "anycast": data.get("anycast", False),
        },
    )
