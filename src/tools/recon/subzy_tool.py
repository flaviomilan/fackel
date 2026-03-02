"""Subzy — subdomain takeover vulnerability detection.

Checks a list of subdomains against known fingerprints for dangling
DNS/CNAME records that could be claimed by an attacker.
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

_TIMEOUT = 180


class SubzyInput(BaseModel):
    """Input for Subzy subdomain takeover check."""

    target: str = Field(
        description=(
            "Domain name to check for subdomain takeover vulnerabilities "
            "(e.g. 'example.com'). Subzy tests the domain and known "
            "subdomains against takeover fingerprints (dangling CNAMEs, "
            "unclaimed cloud resources, expired services)."
        ),
    )


@tool(args_schema=SubzyInput)
def subzy_check(target: str) -> dict[str, Any]:
    """Check subdomains for takeover vulnerabilities.

    Tests DNS records against known fingerprints for services that can be
    claimed by an attacker (e.g. dangling CNAMEs pointing to unclaimed
    S3 buckets, Heroku apps, GitHub Pages).  Passive — only DNS lookups.
    """
    require_binary("subzy", "subzy_check")

    target = guard_target(target, "subzy_check", TargetType.DOMAIN)

    cmd = [
        "subzy",
        "run",
        "--target",
        target,
        "--hide_fails",
        "--concurrency",
        "10",
    ]

    try:
        code, out, stderr = run_command(cmd, timeout=get_tool_timeout("subzy_check", _TIMEOUT))
    except Exception as exc:
        raise ToolException(f"subzy_check: {exc}") from exc

    findings: list[dict[str, Any]] = []
    stripped = out.strip()

    if stripped:
        try:
            parsed = json.loads(stripped)
            items = parsed if isinstance(parsed, list) else [parsed]
            for raw in items:
                finding: dict[str, Any] = {
                    "subdomain": raw.get("subdomain", ""),
                    "cname": raw.get("cname", ""),
                    "service": raw.get("service", ""),
                    "status": raw.get("status", ""),
                    "vulnerable": raw.get("vulnerable", False),
                }
                findings.append(finding)
        except (json.JSONDecodeError, TypeError):
            pass

    vulnerable = [f for f in findings if f.get("vulnerable")]

    if not findings:
        if code:
            raise ToolException(f"subzy_check: {stderr.strip() or 'scan failed'}")
        return format_tool_output(
            "subzy_check",
            target,
            "ok",
            data={
                "total": 0,
                "vulnerable": 0,
                "findings": [],
                "message": "no takeover vulnerabilities detected",
            },
        )

    return format_tool_output(
        "subzy_check",
        target,
        "ok",
        data={
            "total": len(findings),
            "vulnerable": len(vulnerable),
            "findings": findings,
        },
    )


subzy_check.handle_tool_error = True  # type: ignore[attr-defined]
