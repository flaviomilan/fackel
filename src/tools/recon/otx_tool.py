"""AlienVault OTX passive DNS lookup.

Free tier with API key.  Returns historical passive DNS records for a
domain — IP resolutions with first-seen / last-seen timestamps.
Complements SecurityTrails with broader community-sourced passive DNS data.
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
from tools.circuit_breaker import circuit_breaker
from tools.http_client import get_session

_BASE_URL = "https://otx.alienvault.com/api/v1"
_TIMEOUT = 20


class OtxInput(BaseModel):
    """Input for AlienVault OTX passive DNS lookup."""

    domain: str = Field(
        description=(
            "Domain name to query (e.g. 'example.com'). "
            "Returns historical passive DNS records — IP resolutions with "
            "first-seen / last-seen timestamps.  Complements SecurityTrails "
            "and other passive DNS sources for broader coverage."
        ),
    )


@tool(args_schema=OtxInput)
def otx_passive_dns(domain: str) -> dict[str, Any]:
    """Look up passive DNS records via AlienVault OTX.

    Returns historical A/AAAA/CNAME records with first-seen / last-seen
    timestamps from OTX's global threat intelligence platform.  Useful for
    discovering previous IPs, hosting changes, and domain associations.
    Requires OTX_API_KEY environment variable (free registration).
    """
    domain = guard_target(domain, "otx_passive_dns", TargetType.DOMAIN)
    api_key = require_env("OTX_API_KEY", "otx_passive_dns")

    url = f"{_BASE_URL}/indicators/domain/{domain}/passive_dns"
    with circuit_breaker("otx"):
        try:
            resp = get_session().get(
                url,
                headers={
                    "X-OTX-API-KEY": api_key,
                    "Accept": "application/json",
                },
                timeout=get_tool_timeout("otx_passive_dns", _TIMEOUT),
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise ToolException(f"otx_passive_dns: request failed: {exc}") from exc

        try:
            data = resp.json()
        except ValueError:
            raise ToolException("otx_passive_dns: returned non-JSON response") from None

    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in data.get("passive_dns", []):
        address = str(entry.get("address", "")).strip()
        record_type = entry.get("record_type", "")
        hostname = str(entry.get("hostname", "")).strip().rstrip(".")

        dedup_key = f"{address}|{record_type}|{hostname}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        records.append(
            {
                "address": address,
                "hostname": hostname,
                "record_type": record_type,
                "first_seen": entry.get("first", ""),
                "last_seen": entry.get("last", ""),
                "asn": entry.get("asn", ""),
            }
        )

    return format_tool_output(
        "otx_passive_dns",
        domain,
        "ok",
        data={
            "count": len(records),
            "records": records,
        },
    )


otx_passive_dns.handle_tool_error = True


otx_passive_dns.handle_tool_error = True
