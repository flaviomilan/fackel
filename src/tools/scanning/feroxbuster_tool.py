"""Recursive directory discovery via feroxbuster.

Wraps feroxbuster to discover hidden directories, backup files, admin
panels, and unlinked content via recursive brute-forcing.  Supports
custom wordlists, file extensions, response filtering, and rate control.
"""

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
from tools.scanning._wordlists import find_wordlist as _find_wordlist

_TIMEOUT = 300


class FeroxbusterInput(BaseModel):
    """Input for feroxbuster directory scanner."""

    target: str = Field(
        description=(
            "URL or domain to scan (e.g. 'https://example.com' or 'example.com'). "
            "Scheme is auto-added if missing. Discovers hidden admin panels, "
            "backup files (.bak, .sql, .zip), config endpoints, and unlinked content."
        ),
    )
    wordlist: str = Field(
        default="",
        description=(
            "Path to a custom wordlist file. If empty, the tool looks for "
            "SecLists/common.txt or dirb/common.txt in standard locations, "
            "then falls back to a bundled minimal wordlist."
        ),
    )
    extensions: str = Field(
        default="",
        description=(
            "Comma-separated file extensions to probe alongside directory names. "
            "Example: 'php,html,js,json,txt,bak,conf,env'. Leave empty for "
            "directory-only discovery. Choose based on detected technology stack."
        ),
    )
    filter_status: str = Field(
        default="",
        description=(
            "Comma-separated HTTP status codes to exclude from results. "
            "Example: '404,500' to hide not-found and server error responses. "
            "Useful to suppress custom 404 pages with non-404 status codes."
        ),
    )
    filter_size: str = Field(
        default="",
        description=(
            "Comma-separated response sizes (in bytes) to exclude. "
            "Useful to filter repetitive error pages with identical size. "
            "Example: '0,1234' to exclude empty and known-size error responses."
        ),
    )
    filter_words: str = Field(
        default="",
        description=(
            "Comma-separated word counts to exclude from results. "
            "Useful when the target returns a custom error page with a "
            "consistent word count."
        ),
    )
    depth: int = Field(
        default=2,
        description=(
            "Recursion depth for directory brute-forcing (1-4). "
            "Default: 2. Higher values discover nested paths but increase "
            "scan time significantly."
        ),
    )
    threads: int = Field(
        default=20,
        description="Number of concurrent threads (default: 20, max: 50).",
    )
    rate: int = Field(
        default=0,
        description=(
            "Maximum requests per second (0 = unlimited). "
            "Use to avoid rate-limiting or WAF blocking."
        ),
    )


@tool(args_schema=FeroxbusterInput)
def feroxbuster_scan(
    target: str,
    wordlist: str = "",
    extensions: str = "",
    filter_status: str = "",
    filter_size: str = "",
    filter_words: str = "",
    depth: int = 2,
    threads: int = 20,
    rate: int = 0,
) -> dict[str, Any]:
    """Recursive directory and content discovery via feroxbuster.

    Brute-forces web paths using a wordlist to find hidden content that
    crawling cannot reach: admin panels, backup files, config endpoints,
    API routes.  Supports extensions, response filtering, recursion depth
    control, rate limiting, and configurable concurrency.
    """
    require_binary("feroxbuster", "feroxbuster_scan")

    target = guard_target(target, "feroxbuster_scan", TargetType.HOST_OR_URL)

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    wl = _find_wordlist(wordlist)
    if not wl:
        raise ToolException(
            "feroxbuster_scan: no wordlist found. Provide a custom wordlist "
            "path or install SecLists: apt install seclists"
        )

    threads = max(1, min(threads, 50))
    depth = max(1, min(depth, 4))

    scan_timeout = get_tool_timeout("feroxbuster_scan", _TIMEOUT)

    # Tell feroxbuster to stop gracefully *before* the subprocess hard-kill.
    # This lets it flush partial JSON results instead of being killed mid-scan.
    ferox_limit = max(scan_timeout - 30, 60)

    cmd = [
        "feroxbuster",
        "-u",
        target,
        "-w",
        wl,
        "--json",
        "--silent",
        "--no-state",
        "--depth",
        str(depth),
        "--threads",
        str(threads),
        "--time-limit",
        f"{ferox_limit}s",
    ]

    if extensions:
        cmd.extend(["--extensions", extensions])

    if filter_status:
        for code in filter_status.split(","):
            code = code.strip()
            if code.isdigit():
                cmd.extend(["--filter-status", code])

    if filter_size:
        for size in filter_size.split(","):
            size = size.strip()
            if size.isdigit():
                cmd.extend(["--filter-size", size])

    if filter_words:
        for wc in filter_words.split(","):
            wc = wc.strip()
            if wc.isdigit():
                cmd.extend(["--filter-words", wc])

    if rate > 0:
        cmd.extend(["--rate-limit", str(rate)])

    try:
        code, out, stderr = run_command(cmd, timeout=scan_timeout)
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
        if d.get("type") == "response"
    ]

    if not results:
        if code:
            raise ToolException(f"feroxbuster_scan: {stderr or 'scan failed'}")
        return format_tool_output(
            "feroxbuster_scan",
            target,
            "ok",
            data={"results": [], "message": stderr.strip()[:500] or "no results"},
        )

    return format_tool_output(
        "feroxbuster_scan",
        target,
        "ok",
        data={"total": len(results), "results": results},
    )


feroxbuster_scan.handle_tool_error = True
