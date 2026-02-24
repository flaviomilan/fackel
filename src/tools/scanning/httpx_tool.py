"""HTTP probing and web surface mapping via httpx."""

from __future__ import annotations

from typing import Any

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    format_tool_output,
    guard_target,
    parse_jsonl,
    require_binary,
    run_command,
)


class HttpxInput(BaseModel):
    """Input for ProjectDiscovery httpx HTTP prober."""

    domain: str = Field(
        description="IP address, domain, or full URL to probe for HTTP services.",
    )
    ports: str = Field(
        default="",
        description=(
            "Comma-separated ports to probe (e.g. '80,443,8080,8443'). "
            "Feed ports from naabu/nmap for thorough coverage. "
            "Leave empty for httpx defaults (80, 443)."
        ),
    )
    tech_detect: bool = Field(
        default=True,
        description="Enable technology fingerprinting (web frameworks, CMSs, etc.).",
    )
    follow_redirects: bool = Field(
        default=True,
        description="Follow HTTP redirects to the final destination.",
    )
    status_code: bool = Field(
        default=True,
        description="Include HTTP status codes in output.",
    )
    title: bool = Field(
        default=True,
        description="Include HTML page titles in output.",
    )


@tool(args_schema=HttpxInput)
def httpx_scan(
    domain: str,
    ports: str = "",
    tech_detect: bool = True,
    follow_redirects: bool = True,
    status_code: bool = True,
    title: bool = True,
) -> dict[str, Any]:
    """HTTP probing and web surface mapping using ProjectDiscovery's httpx.

    Discovers which ports serve HTTP/HTTPS, what technologies run behind them,
    CDN presence, TLS version, and redirect behavior.  Use before WAF detection
    and Nuclei targeting.
    """
    if err := require_binary("httpx", "httpx_scan", domain):
        return err

    target, verr = guard_target(domain, "httpx_scan", TargetType.HOST_OR_URL)
    if verr:
        return verr

    cmd = ["httpx", target, "-json", "-silent"]

    if ports.strip():
        cmd.extend(["-p", ports.strip()])
    if tech_detect:
        cmd.append("-td")
    if follow_redirects:
        cmd.append("-follow-redirects")
    if status_code:
        cmd.append("-sc")
    if title:
        cmd.append("-title")

    try:
        code, out, stderr = run_command(cmd)
    except Exception as exc:
        return format_tool_output("httpx_scan", domain, "error", error=str(exc))

    results = parse_jsonl(out)

    if not results:
        return format_tool_output(
            "httpx_scan", domain,
            "error" if code else "ok",
            error=stderr or "no HTTP services found",
        )

    return format_tool_output("httpx_scan", domain, "ok", data={"results": results})
