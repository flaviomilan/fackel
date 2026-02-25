"""ASN and IP prefix lookup via RIPEstat API.

Free public API, no authentication required.  Returns ASN number, ASN
holder/name, CIDR prefix, and RIR allocation.  Complements ipinfo.io
with richer BGP-level context.

Previously used the now-defunct BGPView API (api.bgpview.io).
Migrated to RIPEstat ``prefix-overview`` endpoint which provides
equivalent data without authentication.
"""

from __future__ import annotations

import contextlib
import logging
import re
from typing import Any

import requests
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target

logger = logging.getLogger(__name__)

_API_BASE = "https://stat.ripe.net/data"
_TIMEOUT = 15


class BgpLookupInput(BaseModel):
    """Input for BGP/ASN lookup via RIPEstat."""

    ip: str = Field(
        description=(
            "IPv4 address (e.g. '104.21.36.250'). Returns ASN, ASN "
            "holder, CIDR prefix, and RIR allocation. "
            "Call once per discovered IP to get BGP-level context."
        ),
    )


def _parse_rir(block: dict[str, Any]) -> str:
    """Extract RIR name from block description.

    RIPEstat returns descriptions like ``"ARIN (Status: ALLOCATED)"`` or
    ``"Administered by ARIN"``.  We extract just the RIR name.
    """
    desc = block.get("desc", "")
    # "ARIN (Status: ALLOCATED)" → "ARIN"
    match = re.match(r"(\w+)\s*\(", desc)
    if match:
        return match.group(1)
    # "Administered by ARIN" → "ARIN"
    admin_match = re.search(r"Administered by (\w+)", desc)
    if admin_match:
        return admin_match.group(1)
    return desc


def _parse_holder(holder: str) -> tuple[str, str]:
    """Split a RIPEstat ASN holder into short name and description.

    Holders use the format ``"CLOUDFLARENET - Cloudflare, Inc."``.
    Returns ``(short_name, description)`` — or ``(holder, "")`` when
    no separator is present.
    """
    parts = holder.split(" - ", 1)
    short = parts[0].strip()
    desc = parts[1].strip() if len(parts) > 1 else ""
    return short, desc


@tool(args_schema=BgpLookupInput)
def bgp_lookup(ip: str) -> dict[str, Any]:
    """Look up ASN and prefix information for an IP via RIPEstat.

    Free public API — returns the AS number, AS holder name, the
    announcing CIDR prefix, and RIR (ARIN, RIPE, APNIC, etc.).
    Use alongside ipinfo to cross-reference ASN data and classify
    infrastructure as CDN, cloud, ISP, or direct-host.
    """
    ip, err = guard_target(ip, "bgp_lookup", TargetType.IP)
    if err:
        return err

    try:
        resp = requests.get(
            f"{_API_BASE}/prefix-overview/data.json",
            params={"resource": ip},
            timeout=_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        return format_tool_output(
            "bgp_lookup",
            ip,
            "error",
            error=f"RIPEstat request failed: {exc}",
        )

    try:
        body = resp.json()
    except ValueError:
        return format_tool_output(
            "bgp_lookup",
            ip,
            "error",
            error="RIPEstat returned non-JSON response.",
        )

    data = body.get("data", {})
    asns = data.get("asns", [])
    block = data.get("block", {})

    best_asn: dict[str, Any] = asns[0] if asns else {}
    holder = best_asn.get("holder", "")
    asn_name, asn_description = _parse_holder(holder)

    prefix = data.get("resource", "")
    cidr = 0
    if "/" in prefix:
        with contextlib.suppress(ValueError):
            cidr = int(prefix.split("/")[1])

    return format_tool_output(
        "bgp_lookup",
        ip,
        "ok",
        data={
            "ip": ip,
            "asn": best_asn.get("asn"),
            "asn_name": asn_name,
            "asn_description": asn_description,
            "prefix": prefix,
            "cidr": cidr,
            "rir": _parse_rir(block),
        },
    )
