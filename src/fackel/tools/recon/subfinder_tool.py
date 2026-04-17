"""Passive subdomain enumeration via ProjectDiscovery's subfinder.

Aggregates 40+ passive sources (Censys, SecurityTrails, crt.sh, …) for
comprehensive subdomain discovery in a single call.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target, require_binary, run_command


class SubfinderInput(BaseModel):
    """Input schema for subfinder subdomain enumeration."""

    domain: str = Field(
        description="Root domain to enumerate subdomains for (e.g. 'example.com').",
    )
    all_sources: bool = Field(
        default=False,
        description=(
            "Use all available sources (slower but more thorough). "
            "Default uses a curated subset for speed."
        ),
    )
    timeout: int = Field(
        default=30,
        description="Maximum seconds to wait for enumeration (default 30).",
    )


@tool(args_schema=SubfinderInput)
def subfinder_enum(
    domain: str,
    all_sources: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    """Enumerate subdomains passively using subfinder (40+ sources).

    Discovers subdomains via Certificate Transparency, DNS datasets,
    search engines, and security intelligence feeds — all without
    sending traffic to the target.
    """
    domain = guard_target(domain, "subfinder_enum", TargetType.DOMAIN)

    require_binary("subfinder", "subfinder_enum")

    cmd = [
        "subfinder",
        "-d",
        domain,
        "-json",
        "-silent",
        "-timeout",
        str(timeout),
    ]

    if all_sources:
        cmd.append("-all")

    try:
        _code, out, _stderr = run_command(cmd, timeout=timeout + 30)
    except Exception as exc:
        raise ToolException(f"subfinder_enum: {exc}") from exc

    subdomains: list[str] = []
    sources_seen: set[str] = set()
    details: list[dict[str, Any]] = []

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            host = record.get("host", "").strip().lower().rstrip(".")
            source = record.get("source", "unknown")
            if host and host not in subdomains:
                subdomains.append(host)
                details.append({"subdomain": host, "source": source})
                sources_seen.add(source)
        except (json.JSONDecodeError, TypeError):
            host = line.strip().lower().rstrip(".")
            if host and host not in subdomains:
                subdomains.append(host)
                details.append({"subdomain": host, "source": "unknown"})

    return format_tool_output(
        "subfinder_enum",
        domain,
        "ok",
        data={
            "subdomains": sorted(subdomains),
            "count": len(subdomains),
            "sources": sorted(sources_seen),
            "details": details,
        },
    )


subfinder_enum.handle_tool_error = True
