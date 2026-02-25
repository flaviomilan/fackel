"""AlienVault OTX passive DNS lookup.

Free tier with API key.  Returns historical passive DNS records for a
domain — IP resolutions with first-seen / last-seen timestamps.
Complements SecurityTrails with broader community-sourced passive DNS data.
"""

from __future__ import annotations

from typing import Any

import requests
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target, require_env

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
    domain, err = guard_target(domain, "otx_passive_dns", TargetType.DOMAIN)
    if err:
        return err

    api_key, env_err = require_env("OTX_API_KEY", "otx_passive_dns", domain)
    if env_err:
        return env_err

    url = f"{_BASE_URL}/indicators/domain/{domain}/passive_dns"
    try:
        resp = requests.get(
            url,
            headers={
                "X-OTX-API-KEY": api_key,
                "Accept": "application/json",
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        return format_tool_output(
            "otx_passive_dns",
            domain,
            "error",
            error=f"OTX passive DNS request failed: {exc}",
        )

    try:
        data = resp.json()
    except ValueError:
        return format_tool_output(
            "otx_passive_dns",
            domain,
            "error",
            error="OTX returned non-JSON response.",
        )

    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in data.get("passive_dns", []):
        address = str(entry.get("address", "")).strip()
        record_type = entry.get("record_type", "")
        hostname = str(entry.get("hostname", "")).strip().rstrip(".")

        # Deduplicate by (address, record_type, hostname)
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
