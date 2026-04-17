"""DNSDumpster subdomain enumeration tool.

Queries the DNSDumpster HTMX API (JWT-authenticated) to enumerate
subdomains, DNS/MX/NS/TXT records, and hosting providers.
"""

from __future__ import annotations

import re
from typing import Any

import requests
from bs4 import BeautifulSoup
from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, get_tool_timeout, guard_target
from fackel.tooling.circuit_breaker import circuit_breaker
from fackel.tooling.http_client import get_session

_API_URL = "https://api.dnsdumpster.com/htmld/"
_PAGE_URL = "https://dnsdumpster.com/"
_JWT_TIMEOUT = 15
_API_TIMEOUT = 30


class DnsDumpsterInput(BaseModel):
    """Input for DNSDumpster subdomain enumeration."""

    domain: str = Field(
        description=(
            "Root domain to enumerate (e.g. 'example.com'). "
            "Must be a plain domain name — do NOT pass IPs, URLs, or subdomains."
        ),
    )


def _fetch_jwt() -> str:
    """Fetch a short-lived JWT from the DNSDumpster landing page."""
    resp = get_session().get(
        _PAGE_URL,
        headers={"User-Agent": "Mozilla/5.0"},
        timeout=_JWT_TIMEOUT,
    )
    resp.raise_for_status()
    match = re.search(r'"Authorization":\s*"(eyJ[^"]+)"', resp.text)
    if not match:
        raise RuntimeError("DNSDumpster page no longer contains an Authorization JWT.")
    return match.group(1)


def _parse_host_table(table: BeautifulSoup) -> list[dict[str, Any]]:
    """Extract host records (subdomains) from a DNSDumpster HTML table."""
    hosts: list[dict[str, Any]] = []
    for row in table.find_all("tr"):
        cols = row.find_all("td")
        if len(cols) < 2:
            continue
        hostname = cols[0].get_text(strip=True)
        ip_text = cols[1].get_text(strip=True)
        asn_info = cols[2].get_text(strip=True) if len(cols) > 2 else ""
        provider = cols[3].get_text(strip=True) if len(cols) > 3 else ""
        ip_match = re.match(r"(\d{1,3}(?:\.\d{1,3}){3})", ip_text)
        ip_addr = ip_match.group(1) if ip_match else ip_text
        hosts.append(
            {
                "hostname": hostname,
                "ip": ip_addr,
                "asn": asn_info,
                "provider": provider,
            }
        )
    return hosts


def _parse_simple_table(table: BeautifulSoup) -> list[str]:
    """Extract plain-text rows from a DNS/MX/TXT table."""
    rows: list[str] = []
    for row in table.find_all("tr"):
        cols = row.find_all("td")
        texts = [c.get_text(strip=True) for c in cols if c.get_text(strip=True)]
        if texts:
            rows.append(" | ".join(texts))
    return rows


@tool(args_schema=DnsDumpsterInput)
def dnsdumpster_lookup(domain: str) -> dict[str, Any]:
    """Discover subdomains, DNS records, and hosting via DNSDumpster.

    Fetches a short-lived JWT from dnsdumpster.com, then queries their
    HTMX API to enumerate Host Records (A) — including subdomains with
    IPs and hosting providers — plus NS, MX, and TXT records.
    No API key required.
    """
    domain = guard_target(domain, "dnsdumpster_lookup", TargetType.DOMAIN)

    with circuit_breaker("dnsdumpster"):
        try:
            jwt = _fetch_jwt()
        except Exception as exc:
            raise ToolException(
                f"dnsdumpster_lookup: failed to obtain auth token: {exc}",
            ) from exc

        try:
            resp = get_session().post(
                _API_URL,
                headers={
                    "Authorization": jwt,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0",
                },
                data={"target": domain},
                timeout=get_tool_timeout("dnsdumpster_lookup", _API_TIMEOUT),
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise ToolException(
                f"dnsdumpster_lookup: request failed: {exc}",
            ) from exc

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            tables = soup.find_all("table")

            if not tables:
                return format_tool_output(
                    "dnsdumpster_lookup",
                    domain,
                    "ok",
                    data={"hosts": [], "dns_servers": [], "mx_records": [], "txt_records": []},
                )

            hosts = _parse_host_table(tables[1]) if len(tables) > 1 else []
            mx_records = _parse_simple_table(tables[2]) if len(tables) > 2 else []
            dns_servers = _parse_simple_table(tables[3]) if len(tables) > 3 else []
            txt_records = _parse_simple_table(tables[4]) if len(tables) > 4 else []

            return format_tool_output(
                "dnsdumpster_lookup",
                domain,
                "ok",
                data={
                    "hosts": hosts,
                    "dns_servers": dns_servers,
                    "mx_records": mx_records,
                    "txt_records": txt_records,
                },
            )
        except Exception as exc:
            raise ToolException(
                f"dnsdumpster_lookup: failed to parse response: {exc}",
            ) from exc


dnsdumpster_lookup.handle_tool_error = True
