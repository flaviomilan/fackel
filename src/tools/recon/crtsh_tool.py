"""Certificate Transparency subdomain enumeration tool.

Queries crt.sh (Comodo CT log aggregator) for SSL/TLS certificates
issued for a domain, extracting unique subdomains from certificate
name_value fields.  Free, no API key required.
"""

from __future__ import annotations

import time

import requests
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target

_CRTSH_URL = "https://crt.sh/"
_MAX_RETRIES = 2
_RETRY_DELAY = 3  # seconds


class CrtShInput(BaseModel):
    """Input for crt.sh Certificate Transparency lookup."""

    domain: str = Field(
        description=(
            "Root domain to search (e.g. 'example.com'). "
            "Queries Certificate Transparency logs for all certificates "
            "issued to *.domain, revealing subdomains that had TLS certs."
        ),
    )


def _fetch_crtsh(domain: str) -> requests.Response:
    """GET crt.sh with simple retry for transient failures."""
    last_exc: requests.RequestException | None = None
    for attempt in range(_MAX_RETRIES + 1):
        if attempt:
            time.sleep(_RETRY_DELAY)
        try:
            resp = requests.get(
                _CRTSH_URL,
                params={"q": f"%.{domain}", "output": "json"},
                timeout=45,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            resp.raise_for_status()
            return resp
        except requests.RequestException as exc:
            last_exc = exc
            # 404 from crt.sh means no certificates found — not transient.
            if isinstance(exc, requests.HTTPError) and exc.response is not None:
                if exc.response.status_code == 404:
                    raise
    raise last_exc  # type: ignore[misc]


@tool(args_schema=CrtShInput)
def crtsh_subdomain_enum(domain: str) -> dict:
    """Enumerate subdomains via Certificate Transparency logs (crt.sh).

    Searches Comodo's CT log aggregator for certificates matching
    *.domain.  Every subdomain that ever had a TLS certificate appears
    here — often reveals staging, internal, and forgotten subdomains.
    Free, no API key required.  Most reliable passive subdomain source.
    """
    domain, err = guard_target(domain, "crtsh_subdomain_enum", TargetType.DOMAIN)
    if err:
        return err
    domain = domain.lstrip("*.")

    try:
        resp = _fetch_crtsh(domain)
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            # crt.sh returns 404 when no certificates exist for the domain.
            return format_tool_output(
                "crtsh_subdomain_enum", domain, "ok",
                data={"count": 0, "subdomains": []},
            )
        return format_tool_output(
            "crtsh_subdomain_enum", domain, "error",
            error=f"crt.sh request failed: {exc}",
        )
    except requests.RequestException as exc:
        return format_tool_output(
            "crtsh_subdomain_enum", domain, "error",
            error=f"crt.sh request failed: {exc}",
        )

    try:
        entries = resp.json()
    except ValueError:
        return format_tool_output(
            "crtsh_subdomain_enum", domain, "error",
            error="crt.sh returned non-JSON response (service may be overloaded).",
        )

    subdomains: set[str] = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lstrip("*.")
            if name and name != domain:
                subdomains.add(name.lower())

    return format_tool_output(
        "crtsh_subdomain_enum",
        domain,
        "ok",
        data={
            "count": len(subdomains),
            "subdomains": sorted(subdomains),
        },
    )
