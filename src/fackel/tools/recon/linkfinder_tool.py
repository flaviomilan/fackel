"""LinkFinder — JavaScript endpoint extraction.

Parses JavaScript files to discover API endpoints, routes, and hidden
paths embedded in client-side code.  Essential for modern SPAs that
hide their API surface in bundled JS.
"""

from __future__ import annotations

import re
from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    ensure_scheme,
    format_tool_output,
    get_tool_timeout,
    guard_target,
    require_binary,
    run_command,
)

_TIMEOUT = 120


_URL_PATTERN = re.compile(r"((?:https?://|/)[^\s\"'<>]+)")


class LinkFinderInput(BaseModel):
    """Input for LinkFinder endpoint extraction."""

    target: str = Field(
        description=(
            "URL of a JavaScript file or web page to extract endpoints "
            "from (e.g. 'https://example.com/app.js' or "
            "'https://example.com'). Discovers API endpoints, routes, "
            "and hidden paths from JS source code."
        ),
    )


@tool(args_schema=LinkFinderInput)
def linkfinder_extract(target: str) -> dict[str, Any]:
    """Extract API endpoints and paths from JavaScript files.

    Parses JS source for embedded URLs, API routes, and hidden paths.
    SPAs bundle their entire API surface in JS — this tool uncovers it.
    """
    require_binary("linkfinder", "linkfinder_extract")

    target = guard_target(target, "linkfinder_extract", TargetType.HOST_OR_URL)

    target = ensure_scheme(target)

    cmd = [
        "linkfinder",
        "-i",
        target,
        "-o",
        "cli",
    ]

    try:
        code, out, stderr = run_command(
            cmd, timeout=get_tool_timeout("linkfinder_extract", _TIMEOUT)
        )
    except Exception as exc:
        raise ToolException(f"linkfinder_extract: {exc}") from exc

    # Parse endpoints from output lines.
    endpoints: set[str] = set()
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        matches = _URL_PATTERN.findall(line)
        for match in matches:
            # Skip common noise.
            if match in ("/", "//") or len(match) > 500:
                continue
            endpoints.add(match)

    # Separate absolute URLs from relative paths.
    absolute_urls = sorted(e for e in endpoints if e.startswith("http"))
    relative_paths = sorted(e for e in endpoints if not e.startswith("http"))

    if not endpoints:
        if code:
            raise ToolException(f"linkfinder_extract: {stderr.strip() or 'extraction failed'}")
        return format_tool_output(
            "linkfinder_extract",
            target,
            "ok",
            data={
                "endpoints": [],
                "absolute_urls": [],
                "relative_paths": [],
                "total": 0,
                "message": "no endpoints found in JavaScript",
            },
        )

    return format_tool_output(
        "linkfinder_extract",
        target,
        "ok",
        data={
            "endpoints": sorted(endpoints),
            "absolute_urls": absolute_urls,
            "relative_paths": relative_paths,
            "total": len(endpoints),
        },
    )


linkfinder_extract.handle_tool_error = True
