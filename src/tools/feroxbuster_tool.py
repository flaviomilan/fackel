"""Recursive directory discovery via feroxbuster."""

from __future__ import annotations

from typing import Any

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from .utils import format_tool_output, parse_jsonl, require_binary, run_command
from .validators import TargetType, guard_target


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
    if err := require_binary("feroxbuster", "feroxbuster_scan", target):
        return err

    target, verr = guard_target(target, "feroxbuster_scan", TargetType.HOST_OR_URL)
    if verr:
        return verr

    # feroxbuster needs a URL; if guard_target returned a bare host, add scheme
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    cmd = ["feroxbuster", "-u", target, "--json", "-q", "--no-state"]
    try:
        code, out, err = run_command(cmd, timeout=300)
    except Exception as exc:
        return format_tool_output("feroxbuster_scan", target, "error", error=str(exc))

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
        return format_tool_output(
            "feroxbuster_scan", target,
            "error" if code else "ok",
            error=err or "no results",
        )

    return format_tool_output("feroxbuster_scan", target, "ok", data={"results": results})
