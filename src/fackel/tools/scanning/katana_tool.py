"""Web crawling and endpoint discovery via katana."""

from __future__ import annotations

from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    ensure_scheme,
    format_tool_output,
    get_tool_timeout,
    guard_target,
    parse_jsonl,
    require_binary,
    run_command,
)

_TIMEOUT = 240


class KatanaInput(BaseModel):
    """Input for katana web crawler."""

    target: str = Field(
        description=(
            "URL or domain to crawl (e.g. 'https://example.com' or 'example.com'). "
            "Scheme is auto-added if missing. Spiders the site to discover "
            "JS-defined API endpoints, form actions, redirect chains, and links."
        ),
    )


@tool(args_schema=KatanaInput)
def katana_crawl(target: str) -> dict[str, Any]:
    """Crawl a web target to discover URLs, endpoints, and JavaScript routes.

    Uses ProjectDiscovery's katana to spider HTML, JavaScript, and API
    responses.  Complements feroxbuster with link-based discovery.
    """
    require_binary("katana", "katana_crawl")

    target = guard_target(target, "katana_crawl", TargetType.HOST_OR_URL)

    target = ensure_scheme(target)

    cmd = [
        "katana",
        "-u",
        target,
        "-jsonl",
        "-silent",
        "-d",
        "3",
        "-ct",
        "120s",
    ]
    try:
        code, out, stderr = run_command(cmd, timeout=get_tool_timeout("katana_crawl", _TIMEOUT))
    except Exception as exc:
        raise ToolException(f"katana_crawl: {exc}") from exc

    urls: list[str] = []
    for data in parse_jsonl(out):
        req = data.get("request")
        if isinstance(req, dict):
            url = req.get("endpoint") or req.get("url")
        else:
            url = data.get("url") or req
        if url:
            urls.append(url)

    if not urls:
        if code:
            raise ToolException(f"katana_crawl: {stderr or 'scan failed'}")
        return format_tool_output(
            "katana_crawl",
            target,
            "ok",
            data={"urls": [], "message": stderr or "no results"},
        )

    return format_tool_output(
        "katana_crawl",
        target,
        "ok",
        data={"urls": sorted(set(urls))},
    )


katana_crawl.handle_tool_error = True
