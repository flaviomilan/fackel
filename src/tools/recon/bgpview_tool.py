"""ASN and IP prefix lookup via BGPView API.

Free public API, no authentication required.  Returns ASN number, ASN
name, CIDR prefix, RIR, and allocation date.  Complements ipinfo.io
with richer BGP-level context.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import requests
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target

logger = logging.getLogger(__name__)

_API_BASE = "https://api.bgpview.io"
_TIMEOUT = 15
_MAX_RETRIES = 2
_RETRY_DELAY = 3  # seconds


class BgpViewInput(BaseModel):
    """Input for BGPView IP/ASN lookup."""

    ip: str = Field(
        description=(
            "IPv4 address (e.g. '104.21.36.250'). Returns ASN, ASN "
            "description, CIDR prefix, RIR allocation, and country code. "
            "Call once per discovered IP to get BGP-level context."
        ),
    )


def _fetch_bgpview(ip: str) -> requests.Response:
    """GET BGPView API with retry for transient DNS/connection failures."""
    last_exc: requests.RequestException | None = None
    for attempt in range(_MAX_RETRIES + 1):
        if attempt:
            logger.debug("BGPView retry %d/%d for %s", attempt, _MAX_RETRIES, ip)
            time.sleep(_RETRY_DELAY)
        try:
            resp = requests.get(
                f"{_API_BASE}/ip/{ip}",
                timeout=_TIMEOUT,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
            )
            resp.raise_for_status()
            return resp
        except requests.RequestException as exc:
            last_exc = exc
    raise last_exc  # type: ignore[misc]


@tool(args_schema=BgpViewInput)
def bgpview_lookup(ip: str) -> dict[str, Any]:
    """Look up ASN and prefix information for an IP via BGPView.

    Free public API — returns the AS number, AS name/description, the
    announcing CIDR prefix, RIR (ARIN, RIPE, etc.), and country code.
    Use alongside ipinfo to cross-reference ASN data and classify
    infrastructure as CDN, cloud, ISP, or direct-host.
    """
    ip, err = guard_target(ip, "bgpview_lookup", TargetType.IP)
    if err:
        return err

    try:
        resp = _fetch_bgpview(ip)
    except requests.RequestException as exc:
        return format_tool_output(
            "bgpview_lookup",
            ip,
            "error",
            error=f"BGPView request failed after {_MAX_RETRIES + 1} attempts: {exc}",
        )

    try:
        body = resp.json()
    except ValueError:
        return format_tool_output(
            "bgpview_lookup",
            ip,
            "error",
            error="BGPView returned non-JSON response.",
        )

    if body.get("status") != "ok":
        return format_tool_output(
            "bgpview_lookup",
            ip,
            "error",
            error=f"BGPView returned status: {body.get('status_message', 'unknown')}",
        )

    payload = body.get("data", {})
    prefixes = payload.get("prefixes", [])
    rir_alloc = payload.get("rir_allocation", {})

    # Take the most-specific prefix (longest mask).
    best_prefix: dict = {}
    if prefixes:
        best_prefix = max(prefixes, key=lambda p: p.get("cidr", 0))

    asn_info = best_prefix.get("asn", {})

    return format_tool_output(
        "bgpview_lookup",
        ip,
        "ok",
        data={
            "ip": payload.get("ip", ip),
            "ptr_record": payload.get("ptr_record"),
            "asn": asn_info.get("asn"),
            "asn_name": asn_info.get("name", ""),
            "asn_description": asn_info.get("description", ""),
            "asn_country": asn_info.get("country_code", ""),
            "prefix": best_prefix.get("prefix", ""),
            "cidr": best_prefix.get("cidr", 0),
            "rir": rir_alloc.get("rir_name", ""),
            "rir_country": rir_alloc.get("country_code", ""),
            "allocation_date": rir_alloc.get("date_allocated", ""),
        },
    )
