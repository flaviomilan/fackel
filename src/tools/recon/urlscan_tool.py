"""Urlscan.io passive scan results lookup.

Free, no API key required for the search endpoint.  Returns cached scan
results for a domain — URLs, IPs, server headers, technologies, and ASN
information from previous community scans.
"""

from __future__ import annotations

from typing import Any

import requests
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target

_BASE_URL = "https://urlscan.io/api/v1"
_TIMEOUT = 20
_MAX_RESULTS = 10


class UrlscanInput(BaseModel):
    """Input for Urlscan.io domain search."""

    domain: str = Field(
        description=(
            "Domain name to search (e.g. 'example.com'). "
            "Returns cached scan results from Urlscan.io community scans — "
            "URLs, IPs, server headers, technologies, ASN info.  Useful for "
            "discovering JS endpoints, third-party resources, and page content "
            "without touching the target directly."
        ),
    )


@tool(args_schema=UrlscanInput)
def urlscan_search(domain: str) -> dict[str, Any]:
    """Search Urlscan.io for cached scan results of a domain.

    Returns up to 10 most recent community scan results with URLs, resolved
    IPs, server headers, detected technologies, and ASN data.  Free, no API
    key required.  Useful for discovering JS endpoints, third-party resources,
    page structure, and technology stack from historical scans.
    """
    domain, err = guard_target(domain, "urlscan_search", TargetType.DOMAIN)
    if err:
        return err

    try:
        resp = requests.get(
            f"{_BASE_URL}/search/",
            params={"q": f"domain:{domain}", "size": _MAX_RESULTS},
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json",
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        return format_tool_output(
            "urlscan_search",
            domain,
            "error",
            error=f"urlscan.io request failed: {exc}",
        )

    try:
        data = resp.json()
    except ValueError:
        return format_tool_output(
            "urlscan_search",
            domain,
            "error",
            error="urlscan.io returned non-JSON response.",
        )

    results: list[dict[str, Any]] = []
    for entry in data.get("results", [])[:_MAX_RESULTS]:
        page = entry.get("page", {})
        task = entry.get("task", {})
        stats = entry.get("stats", {})

        results.append(
            {
                "url": page.get("url", ""),
                "domain": page.get("domain", ""),
                "ip": page.get("ip", ""),
                "server": page.get("server", ""),
                "asn": page.get("asn", ""),
                "asnname": page.get("asnname", ""),
                "title": page.get("title", ""),
                "status": page.get("status", ""),
                "mime_type": page.get("mimeType", ""),
                "country": page.get("country", ""),
                "technologies": _extract_technologies(stats),
                "scan_time": task.get("time", ""),
                "visibility": task.get("visibility", ""),
            }
        )

    return format_tool_output(
        "urlscan_search",
        domain,
        "ok",
        data={
            "total": data.get("total", 0),
            "results": results,
        },
    )


def _extract_technologies(stats: dict[str, Any]) -> list[str]:
    """Pull technology names from the stats section if available."""
    techs: list[str] = []
    for proto_stat in stats.get("protocolStats", []):
        protocol = proto_stat.get("protocol", "")
        if protocol and protocol not in techs:
            techs.append(protocol)
    return techs
