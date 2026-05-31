"""Amass — comprehensive attack surface enumeration.

OWASP Amass performs deep DNS enumeration using certificate transparency,
APIs, brute-forcing, and scraping.  Provides broader coverage than subfinder
for complex targets.

Amass v4.x removed the ``-json`` stdout flag.  We use ``-oA <prefix>`` to
get structured JSONL output written to ``<prefix>.json``, with a fallback
to plain-text stdout parsing (one FQDN per line).
"""

from __future__ import annotations

import json
import os
import tempfile
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


def _parse_jsonl(content: str) -> list[dict[str, Any]]:
    """Parse JSONL content into subdomain records.

    Each line is expected to be a JSON object with at least a ``name``
    key.  Duplicate names are suppressed.
    """
    subdomains: list[dict[str, Any]] = []
    seen: set[str] = set()

    for line in content.splitlines():
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

    return subdomains


def _parse_plain_text(content: str) -> list[dict[str, Any]]:
    """Parse plain-text output (one FQDN per line) into subdomain records."""
    subdomains: list[dict[str, Any]] = []
    seen: set[str] = set()

    for line in content.splitlines():
        name = line.strip().lower()
        if not name or name in seen:
            continue
        seen.add(name)
        subdomains.append({"subdomain": name})

    return subdomains


@tool(args_schema=AmassInput)
def amass_enum(target: str, passive: bool = True) -> dict[str, Any]:
    """Enumerate subdomains for a domain using OWASP Amass.

    Combines certificate transparency logs, search engines, web archives,
    and API integrations for the broadest possible subdomain coverage.
    Passive mode sends no traffic to the target.
    """
    require_binary("amass", "amass_enum")

    target = guard_target(target, "amass_enum", TargetType.DOMAIN)

    with tempfile.TemporaryDirectory(prefix="amass_") as tmpdir:
        oa_prefix = os.path.join(tmpdir, "out")

        cmd = [
            "amass",
            "enum",
            "-d",
            target,
            "-oA",
            oa_prefix,
            "-timeout",
            "10",
        ]

        if passive:
            cmd.append("-passive")

        try:
            code, out, stderr = run_command(
                cmd,
                timeout=get_tool_timeout("amass_enum", _TIMEOUT),
            )
        except Exception as exc:
            raise ToolException(f"amass_enum: {exc}") from exc

        # Prefer the structured JSON file written by ``-oA``.
        json_file = oa_prefix + ".json"
        json_content = ""
        if os.path.isfile(json_file):
            with open(json_file) as fh:
                json_content = fh.read()

        # Parse: JSON file → stdout JSONL → stdout plain text.
        subdomains = _parse_jsonl(json_content or out)
        if not subdomains:
            subdomains = _parse_plain_text(out)

    if not subdomains:
        if code:
            raise ToolException(
                f"amass_enum: {stderr.strip() or 'enumeration failed'}",
            )
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


amass_enum.handle_tool_error = True
