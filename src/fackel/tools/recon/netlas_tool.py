"""Passive host/service search via the Netlas API.

Netlas is an internet-wide scan database (Shodan/Censys class).  Querying it
returns hosts, IPs, open ports, and hostnames indexed for a domain without ever
touching the target — passive recon that complements Shodan, Censys, and FOFA.

Requires ``NETLAS_API_KEY`` (free tier available).
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

_API_URL = "https://app.netlas.io/api/responses/"
_TIMEOUT = 25
_MAX_HOSTS = 50


class NetlasInput(BaseModel):
    """Input for Netlas host/service search."""

    domain: str = Field(
        description=(
            "Domain or IP to search in the Netlas scan database "
            "(e.g. 'example.com'). Returns indexed hosts with IPs, ports, and "
            "hostnames. Passive — only the Netlas dataset is queried."
        ),
    )


def _host_from_item(item: dict[str, Any]) -> dict[str, Any] | None:
    """Normalise one Netlas response item into a ``{ip, hostname, port}`` dict."""
    record = item.get("data") if isinstance(item.get("data"), dict) else item
    if not isinstance(record, dict):
        return None
    ip = str(record.get("ip") or record.get("a") or "").strip()
    hostname = str(record.get("host") or record.get("domain") or "").strip().lower()
    port = record.get("port")
    if not ip and not hostname:
        return None
    return {"ip": ip, "hostname": hostname, "port": port}


@tool(args_schema=NetlasInput)
def netlas_lookup(domain: str) -> dict[str, Any]:
    """Search host and service data for a domain via the Netlas scan database.

    Returns indexed hosts with their IPs, hostnames, and open ports.  Pure
    passive OSINT — the Netlas dataset is queried, never the target.  Requires
    NETLAS_API_KEY (free tier available).
    """
    domain = guard_target(domain, "netlas_lookup", TargetType.HOST)
    api_key = require_env("NETLAS_API_KEY", "netlas_lookup")

    with circuit_breaker("netlas"):
        try:
            resp = get_session().get(
                _API_URL,
                params={"q": f"domain:{domain}", "page": "0"},
                headers={"X-API-Key": api_key, "Accept": "application/json"},
                timeout=get_tool_timeout("netlas_lookup", _TIMEOUT),
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise ToolException(f"netlas_lookup: request failed: {exc}") from exc

    try:
        payload = resp.json()
    except ValueError:
        raise ToolException("netlas_lookup: returned non-JSON response") from None

    hosts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in payload.get("items", []) or []:
        if not isinstance(item, dict):
            continue
        host = _host_from_item(item)
        if host is None:
            continue
        key = f"{host['ip']}|{host['hostname']}"
        if key in seen:
            continue
        seen.add(key)
        hosts.append(host)
        if len(hosts) >= _MAX_HOSTS:
            break

    return format_tool_output(
        "netlas_lookup",
        domain,
        "ok",
        data={"domain": domain, "hosts": hosts, "count": len(hosts)},
    )


netlas_lookup.handle_tool_error = True
