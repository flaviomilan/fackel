"""Web crawling and endpoint discovery via katana."""

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
    if err := require_binary("katana", "katana_crawl", target):
        return err

    target, verr = guard_target(target, "katana_crawl", TargetType.HOST_OR_URL)
    if verr:
        return verr

    # katana needs a URL; if guard_target returned a bare host, add scheme
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    cmd = [
        "katana", "-u", target,
        "-jsonl", "-silent",
        "-d", "3",
        "-ct", "120s",
    ]
    try:
        code, out, stderr = run_command(cmd, timeout=240)
    except Exception as exc:
        return format_tool_output("katana_crawl", target, "error", error=str(exc))

    urls: list[str] = []
    for data in parse_jsonl(out):
        # Newer katana uses request.endpoint; older used top-level url
        req = data.get("request")
        if isinstance(req, dict):
            url = req.get("endpoint") or req.get("url")
        else:
            url = data.get("url") or req
        if url:
            urls.append(url)

    if not urls:
        return format_tool_output(
            "katana_crawl", target,
            "error" if code else "ok",
            error=stderr or "no results",
        )

    return format_tool_output(
        "katana_crawl", target, "ok",
        data={"urls": sorted(set(urls))},
    )
