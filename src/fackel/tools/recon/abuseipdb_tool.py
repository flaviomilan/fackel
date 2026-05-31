"""IP abuse reputation via the AbuseIPDB API.

AbuseIPDB aggregates community-reported abuse (spam, brute-force, scanning).
For a given IP it returns an abuse-confidence score (0-100), the number of
reports, and usage metadata.  Queries the AbuseIPDB API only — never the
target — so it stays passive.

Requires ``ABUSEIPDB_API_KEY`` (free tier: 1 000 checks/day).
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

_API_URL = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT = 15
_MAX_AGE_DAYS = 90


class AbuseIPDBInput(BaseModel):
    """Input for AbuseIPDB reputation lookup."""

    ip: str = Field(
        description=(
            "IPv4 address to check abuse reputation for (e.g. '1.2.3.4'). "
            "Returns an abuse-confidence score (0-100), report count, and usage "
            "type. Passive — only the AbuseIPDB dataset is queried."
        ),
    )


@tool(args_schema=AbuseIPDBInput)
def abuseipdb_lookup(ip: str) -> dict[str, Any]:
    """Check an IP's abuse reputation via AbuseIPDB.

    Returns the abuse-confidence score (0-100), total community reports, usage
    type, and a Tor-exit flag.  Pure passive OSINT — the AbuseIPDB dataset is
    queried, never the target.  Requires ABUSEIPDB_API_KEY (free tier:
    1 000 checks/day).
    """
    ip = guard_target(ip, "abuseipdb_lookup", TargetType.IP)
    api_key = require_env("ABUSEIPDB_API_KEY", "abuseipdb_lookup")

    with circuit_breaker("abuseipdb"):
        try:
            resp = get_session().get(
                _API_URL,
                params={"ipAddress": ip, "maxAgeInDays": str(_MAX_AGE_DAYS)},
                headers={"Key": api_key, "Accept": "application/json"},
                timeout=get_tool_timeout("abuseipdb_lookup", _TIMEOUT),
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise ToolException(f"abuseipdb_lookup: request failed: {exc}") from exc

    try:
        payload = resp.json()
    except ValueError:
        raise ToolException("abuseipdb_lookup: returned non-JSON response") from None

    data = payload.get("data") or {}
    return format_tool_output(
        "abuseipdb_lookup",
        ip,
        "ok",
        data={
            "ip": str(data.get("ipAddress", ip)),
            "abuse_score": int(data.get("abuseConfidenceScore", 0) or 0),
            "abuse_reports": int(data.get("totalReports", 0) or 0),
            "abuse_usage_type": str(data.get("usageType", "") or ""),
            "abuse_tor": bool(data.get("isTor", False)),
        },
    )


abuseipdb_lookup.handle_tool_error = True
