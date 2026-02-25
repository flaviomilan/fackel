"""Recursive directory discovery via feroxbuster."""

from __future__ import annotations

from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    format_tool_output,
    get_tool_timeout,
    guard_target,
    parse_jsonl,
    require_binary,
    run_command,
)

_TIMEOUT = 300  # seconds


class FeroxbusterInput(BaseModel):
    """Input for feroxbuster directory scanner."""

    target: str = Field(
        description=(
            "URL or domain to scan (e.g. 'https://example.com' or 'example.com'). "
            "Scheme is auto-added if missing. Discovers hidden admin panels, "
            "backup files (.bak, .sql, .zip), config endpoints, and unlinked content."
        ),
    )


@tool(args_schema=FeroxbusterInput)
def feroxbuster_scan(target: str) -> dict[str, Any]:
    """Recursive directory and content discovery via feroxbuster.

    Brute-forces web paths using a wordlist to find hidden content that
    crawling cannot reach: admin panels, backup files, config endpoints.
    """
    require_binary("feroxbuster", "feroxbuster_scan")

    target = guard_target(target, "feroxbuster_scan", TargetType.HOST_OR_URL)

    # feroxbuster needs a URL; if guard_target returned a bare host, add scheme
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    cmd = ["feroxbuster", "-u", target, "--json", "-q", "--no-state"]
    try:
        code, out, stderr = run_command(cmd, timeout=get_tool_timeout("feroxbuster_scan", _TIMEOUT))
    except Exception as exc:
        raise ToolException(f"feroxbuster_scan: {exc}") from exc

    results = [
        {
            "url": d.get("url"),
            "status": d.get("status"),
            "length": d.get("content_length"),
            "mime": d.get("content_type"),
            "words": d.get("words"),
            "lines": d.get("lines"),
        }
        for d in parse_jsonl(out)
    ]

    if not results:
        if code:
            raise ToolException(f"feroxbuster_scan: {stderr or 'scan failed'}")
        return format_tool_output(
            "feroxbuster_scan",
            target,
            "ok",
            data={"results": [], "message": stderr or "no results"},
        )

    return format_tool_output("feroxbuster_scan", target, "ok", data={"results": results})


feroxbuster_scan.handle_tool_error = True
