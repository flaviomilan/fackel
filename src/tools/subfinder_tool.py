"""Passive subdomain enumeration via ProjectDiscovery's subfinder.

Aggregates 40+ passive sources (Censys, SecurityTrails, crt.sh, …) for
comprehensive subdomain discovery in a single call.
"""

from __future__ import annotations

import json
import shutil
from typing import Any

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from .utils import format_tool_output
from .validators import TargetType, guard_target


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
    domain, err = guard_target(domain, "subfinder_enum", TargetType.DOMAIN)
    if err:
        return err

    if not shutil.which("subfinder"):
        return format_tool_output(
            "subfinder_enum",
            domain,
            "error",
            error="subfinder not found in PATH. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        )

    cmd = [
        "subfinder",
        "-d", domain,
        "-json",
        "-silent",
        "-timeout", str(timeout),
    ]

    if all_sources:
        cmd.append("-all")

    try:
        from .utils import run_command
        code, out, err = run_command(cmd, timeout=timeout + 30)
    except Exception as exc:
        return format_tool_output(
            "subfinder_enum",
            domain,
            "error",
            error=str(exc),
        )

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
            # Fallback: plain text line (one subdomain per line)
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
