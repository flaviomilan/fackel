"""GetAllUrls (gau) — passive URL discovery from historical archives.

Fetches known URLs for a domain from multiple passive sources:
AlienVault OTX, Wayback Machine, Common Crawl, and URLScan.
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
    require_binary,
    run_command,
)

_TIMEOUT = 180


class GauInput(BaseModel):
    """Input for gau URL discovery."""

    target: str = Field(
        description=(
            "Domain name to fetch known URLs for (e.g. 'example.com'). "
            "Queries AlienVault OTX, Wayback Machine, Common Crawl, and "
            "URLScan for historically observed URLs. No packets sent to "
            "the target — purely passive."
        ),
    )


@tool(args_schema=GauInput)
def gau_urls(target: str) -> dict[str, Any]:
    """Fetch known URLs for a domain from passive historical sources.

    Uses gau (GetAllUrls) to query Wayback Machine, Common Crawl,
    AlienVault OTX, and URLScan.  Discovers forgotten endpoints,
    admin panels, API paths, and old versions that may still be live.
    """
    require_binary("gau", "gau_urls")

    target = guard_target(target, "gau_urls", TargetType.DOMAIN)

    cmd = [
        "gau",
        "--threads",
        "2",
        target,
    ]

    try:
        code, out, stderr = run_command(cmd, timeout=get_tool_timeout("gau_urls", _TIMEOUT))
    except Exception as exc:
        raise ToolException(f"gau_urls: {exc}") from exc

    urls = sorted({line.strip() for line in out.splitlines() if line.strip()})

    if not urls:
        if code:
            raise ToolException(f"gau_urls: {stderr.strip() or 'scan failed'}")
        return format_tool_output(
            "gau_urls",
            target,
            "ok",
            data={"urls": [], "count": 0, "message": "no URLs found in passive sources"},
        )

    return format_tool_output(
        "gau_urls",
        target,
        "ok",
        data={"urls": urls, "count": len(urls)},
    )


gau_urls.handle_tool_error = True  # type: ignore[attr-defined]
