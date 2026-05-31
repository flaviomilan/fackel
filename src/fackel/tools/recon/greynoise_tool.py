"""IP reputation via the GreyNoise Community API.

GreyNoise observes internet-wide scan traffic.  For a given IP it reports
whether the address is "noise" (mass-scanning / opportunistic), whether it is
in the RIOT set (known-benign common business services), and a benign /
malicious / unknown classification.  Queries the GreyNoise API only — never
the target — so it stays passive.

The Community endpoint requires ``GREYNOISE_API_KEY`` (free community tier), so
the key is mandatory.
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

_API_URL = "https://api.greynoise.io/v3/community/{ip}"
_TIMEOUT = 15


class GreyNoiseInput(BaseModel):
    """Input for GreyNoise IP reputation lookup."""

    ip: str = Field(
        description=(
            "IPv4 address to check reputation for (e.g. '1.2.3.4'). Returns "
            "GreyNoise noise/RIOT flags and a benign/malicious classification. "
            "Passive — only the GreyNoise dataset is queried."
        ),
    )


@tool(args_schema=GreyNoiseInput)
def greynoise_lookup(ip: str) -> dict[str, Any]:
    """Check an IP's internet-scan reputation via GreyNoise Community.

    Returns whether the IP is mass-scanning "noise", in the known-benign RIOT
    set, and its benign/malicious/unknown classification.  Pure passive OSINT —
    the GreyNoise dataset is queried, never the target.  Requires
    GREYNOISE_API_KEY (free community tier).
    """
    ip = guard_target(ip, "greynoise_lookup", TargetType.IP)
    api_key = require_env("GREYNOISE_API_KEY", "greynoise_lookup")

    with circuit_breaker("greynoise"):
        try:
            resp = get_session().get(
                _API_URL.format(ip=ip),
                headers={"key": api_key, "Accept": "application/json"},
                timeout=get_tool_timeout("greynoise_lookup", _TIMEOUT),
            )
            # 404 = IP not observed; still a valid, useful answer.
            if resp.status_code != 404:
                resp.raise_for_status()
        except requests.RequestException as exc:
            raise ToolException(f"greynoise_lookup: request failed: {exc}") from exc

    try:
        payload = resp.json()
    except ValueError:
        raise ToolException("greynoise_lookup: returned non-JSON response") from None

    return format_tool_output(
        "greynoise_lookup",
        ip,
        "ok",
        data={
            "ip": ip,
            "gn_noise": bool(payload.get("noise", False)),
            "gn_riot": bool(payload.get("riot", False)),
            "gn_classification": str(payload.get("classification", "unknown")),
            "gn_actor": str(payload.get("name", "")),
        },
    )


greynoise_lookup.handle_tool_error = True
