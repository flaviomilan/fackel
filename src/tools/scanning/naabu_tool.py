"""Fast TCP port discovery via naabu."""

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
    sanitize_ports,
    sanitize_top_ports,
)


class NaabuInput(BaseModel):
    """Input for naabu port scanner."""

    host: str = Field(
        description="IP address or domain to scan. One target per call.",
    )
    ports: str = Field(
        default="",
        description=(
            "Comma-separated ports or ranges (e.g. '80,443,8000-9000'). "
            "Leave empty to use naabu's default port list. "
            "Mutually exclusive with top_ports."
        ),
    )
    top_ports: str = Field(
        default="",
        description=(
            "Scan only the N most common ports. '100' for quick sweep, "
            "'1000' for thorough coverage. Ignored when ports is set."
        ),
    )
    rate: int = Field(
        default=0,
        description=(
            "Packets per second (0 = naabu default ~1000). "
            "Lower for stealth, higher (e.g. 5000) on reliable networks."
        ),
    )
    skip_cdn: bool = Field(
        default=False,
        description=(
            "Skip ports belonging to CDNs (Cloudflare, Akamai, etc.). "
            "Use when the target is known to be behind a CDN proxy."
        ),
    )


@tool(args_schema=NaabuInput)
def naabu_scan(
    host: str,
    ports: str = "",
    top_ports: str = "",
    rate: int = 0,
    skip_cdn: bool = False,
) -> dict[str, Any]:
    """Fast SYN-based TCP port discovery using naabu.

    Use for breadth-first port enumeration — fast sweep to find open ports
    before deeper nmap analysis.  Feed discovered ports into nmap_port_scan.
    """
    if err := require_binary("naabu", "naabu_scan", host):
        return err

    target, verr = guard_target(host, "naabu_scan", TargetType.HOST)
    if verr:
        return verr

    cmd = ["naabu", "-host", target, "-json"]

    ports, ports_err = sanitize_ports(ports)
    if ports_err:
        return format_tool_output("naabu_scan", host, "error", error=ports_err)

    top_ports, tp_err = sanitize_top_ports(top_ports)
    if tp_err:
        return format_tool_output("naabu_scan", host, "error", error=tp_err)

    if ports:
        cmd.extend(["-p", ports])
    elif top_ports:
        cmd.extend(["-top-ports", top_ports])

    if rate > 0:
        cmd.extend(["-rate", str(rate)])

    if skip_cdn:
        cmd.append("-cdn")

    try:
        code, out, stderr = run_command(cmd)
    except Exception as exc:
        return format_tool_output("naabu_scan", host, "error", error=str(exc))

    results = parse_jsonl(out)

    if not results:
        return format_tool_output(
            "naabu_scan",
            host,
            "error" if code else "ok",
            error=stderr or "no open ports found",
        )

    return format_tool_output("naabu_scan", host, "ok", data={"results": results})
