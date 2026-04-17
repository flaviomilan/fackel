"""HTTP probing and web surface mapping via httpx."""

from __future__ import annotations

import os
from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    format_tool_output,
    get_tool_timeout,
    guard_target,
    parse_jsonl,
    run_command,
)


def _find_pd_httpx() -> str:
    """Locate the ProjectDiscovery httpx binary.

    The Python ``encode/httpx`` package installs a CLI script with the
    same name.  Walk ``PATH`` and return the first ``httpx`` that is a
    compiled (ELF) binary rather than a Python script.
    """
    seen: set[str] = set()
    for directory in os.get_exec_path():
        candidate = os.path.join(directory, "httpx")
        real = os.path.realpath(candidate)
        if real in seen or not os.path.isfile(candidate) or not os.access(candidate, os.X_OK):
            continue
        seen.add(real)
        # Python scripts start with '#!' and contain 'python'.
        try:
            with open(candidate, "rb") as fh:
                head = fh.read(64)
            if head[:2] == b"#!" and b"python" in head:
                continue
        except OSError:
            continue
        return candidate
    raise ToolException(
        "httpx_scan: ProjectDiscovery httpx not found in PATH "
        "(only the Python encode/httpx was found)"
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
    httpx_bin = _find_pd_httpx()

    target = guard_target(domain, "httpx_scan", TargetType.HOST_OR_URL)

    cmd = [httpx_bin, "-u", target, "-json", "-silent"]

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
        code, out, stderr = run_command(cmd, timeout=get_tool_timeout("httpx_scan", 180))
    except Exception as exc:
        raise ToolException(f"httpx_scan: {exc}") from exc

    results = parse_jsonl(out)

    if not results:
        if code:
            raise ToolException(f"httpx_scan: {stderr or 'scan failed'}")
        return format_tool_output(
            "httpx_scan",
            domain,
            "ok",
            data={"results": [], "message": stderr or "no HTTP services found"},
        )

    return format_tool_output("httpx_scan", domain, "ok", data={"results": results})


httpx_scan.handle_tool_error = True
