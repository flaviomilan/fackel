"""Amass — comprehensive attack surface enumeration.

OWASP Amass performs deep DNS enumeration using certificate transparency,
APIs, brute-forcing, and scraping.  Provides broader coverage than subfinder
for complex targets.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    format_tool_output,
    get_tool_timeout,
    guard_target,
    require_binary,
    run_command,
)

_TIMEOUT = 600


class AmassInput(BaseModel):
    """Input for Amass subdomain enumeration."""

    target: str = Field(
        description=(
            "Domain name to enumerate subdomains for "
            "(e.g. 'example.com'). Amass combines certificate "
            "transparency, DNS brute-forcing, web scraping, and APIs "
            "for comprehensive subdomain discovery."
        ),
    )
    passive: bool = Field(
        default=True,
        description=(
            "If true, use only passive sources (no DNS brute-forcing). "
            "Default true — safe for non-intrusive reconnaissance."
        ),
    )


@tool(args_schema=AmassInput)
def amass_enum(target: str, passive: bool = True) -> dict[str, Any]:
    """Enumerate subdomains for a domain using OWASP Amass.

    Combines certificate transparency logs, search engines, web archives,
    and API integrations for the broadest possible subdomain coverage.
    Passive mode sends no traffic to the target.
    """
    require_binary("amass", "amass_enum")

    target = guard_target(target, "amass_enum", TargetType.DOMAIN)

    cmd = [
        "amass",
        "enum",
        "-d",
        target,
        "-json",
        "-timeout",
        "10",
    ]

    if passive:
        cmd.append("-passive")

    try:
        code, out, stderr = run_command(cmd, timeout=get_tool_timeout("amass_enum", _TIMEOUT))
    except Exception as exc:
        raise ToolException(f"amass_enum: {exc}") from exc

    subdomains: list[dict[str, Any]] = []
    seen: set[str] = set()

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue

        name = entry.get("name", "").lower()
        if not name or name in seen:
            continue
        seen.add(name)

        record: dict[str, Any] = {
            "subdomain": name,
            "sources": entry.get("sources", []),
        }
        addresses = entry.get("addresses")
        if addresses and isinstance(addresses, list):
            record["ips"] = [
                a.get("ip", "") for a in addresses if isinstance(a, dict) and a.get("ip")
            ]
        subdomains.append(record)

    if not subdomains:
        if code:
            raise ToolException(f"amass_enum: {stderr.strip() or 'enumeration failed'}")
        return format_tool_output(
            "amass_enum",
            target,
            "ok",
            data={
                "subdomains": [],
                "count": 0,
                "message": "no subdomains found",
            },
        )

    return format_tool_output(
        "amass_enum",
        target,
        "ok",
        data={
            "subdomains": subdomains,
            "count": len(subdomains),
        },
    )


amass_enum.handle_tool_error = True  # type: ignore[attr-defined]
