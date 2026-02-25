"""Historical DNS records via SecurityTrails API.

Free tier: 50 queries/month.  Reveals previous A, MX, and NS records
— old IPs that may bypass CDN protection, former hosting providers,
and nameserver migrations.
"""

from __future__ import annotations

from typing import Any

import requests
from langchain_core.tools import tool
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

_BASE_URL = "https://api.securitytrails.com/v1"
_TIMEOUT = 20


class SecurityTrailsInput(BaseModel):
    """Input for SecurityTrails historical DNS lookup."""

    domain: str = Field(
        description=(
            "Domain name to query (e.g. 'example.com'). "
            "Returns historical A, MX, and NS records — reveals previous "
            "IPs, hosting provider changes, and nameserver migrations. "
            "Old IPs may still be reachable and bypass CDN protection."
        ),
    )


def _fetch_history(
    api_key: str,
    domain: str,
    record_type: str,
) -> list[dict[str, Any]]:
    """Fetch DNS history for a single record type.

    Returns a flat list of ``{value, first_seen, last_seen, org}`` dicts.
    """
    url = f"{_BASE_URL}/history/{domain}/dns/{record_type}"
    try:
        resp = get_session().get(
            url,
            headers={"APIKEY": api_key, "Accept": "application/json"},
            timeout=get_tool_timeout("securitytrails_history", _TIMEOUT),
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        return [{"error": f"{record_type} history request failed: {exc}"}]

    try:
        data = resp.json()
    except ValueError:
        return [{"error": f"{record_type}: non-JSON response"}]

    records: list[dict[str, Any]] = []
    for entry in data.get("records", []):
        values = entry.get("values", [])
        first_seen = entry.get("first_seen", "")
        last_seen = entry.get("last_seen", "")
        for val in values:
            ip_or_host = val.get("ip", "") or val.get("host", "") or val.get("nameserver", "")
            if not ip_or_host:
                # fallback: some records have the value directly
                ip_or_host = val.get("value", str(val))
            records.append(
                {
                    "value": ip_or_host.strip().rstrip("."),
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "org": val.get("ip_organization", ""),
                }
            )
    return records


@tool(args_schema=SecurityTrailsInput)
def securitytrails_history(domain: str) -> dict[str, Any]:
    """Look up historical DNS records via SecurityTrails.

    Returns previous A (IPv4), MX (mail), and NS (nameserver) records with
    first-seen / last-seen timestamps and organisation names.  Useful for
    discovering old IPs that may still be live and bypass CDN protection,
    detecting hosting migrations, and understanding infrastructure evolution.
    Requires SECURITYTRAILS_API_KEY environment variable (free tier: 50 queries/month).
    """
    domain = guard_target(domain, "securitytrails_history", TargetType.DOMAIN)
    api_key = require_env("SECURITYTRAILS_API_KEY", "securitytrails_history")

    with circuit_breaker("securitytrails"):
        a_records = _fetch_history(api_key, domain, "a")
        mx_records = _fetch_history(api_key, domain, "mx")
        ns_records = _fetch_history(api_key, domain, "ns")

    return format_tool_output(
        "securitytrails_history",
        domain,
        "ok",
        data={
            "a_records": a_records,
            "mx_records": mx_records,
            "ns_records": ns_records,
        },
    )


securitytrails_history.handle_tool_error = True
