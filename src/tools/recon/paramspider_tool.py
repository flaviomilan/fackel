"""ParamSpider — parameter discovery from web archives.

Mines web archives (Wayback Machine, Common Crawl) for URLs containing
query parameters.  Essential for feeding parameter-aware scanners like
DalFox with real-world injection points.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    format_tool_output,
    get_tool_timeout,
    guard_target,
    require_binary,
    run_command,
    sanitize_exclude_extensions,
)

_TIMEOUT = 180


class ParamSpiderInput(BaseModel):
    """Input for ParamSpider parameter discovery."""

    target: str = Field(
        description=(
            "Domain name to discover URL parameters for "
            "(e.g. 'example.com'). ParamSpider mines web archives for "
            "URLs with query parameters — ideal for finding XSS, SQLi, "
            "and SSRF injection points."
        ),
    )
    exclude: str = Field(
        default="png,jpg,jpeg,gif,svg,css,js,woff,woff2,ico,ttf,eot",
        description=(
            "Comma-separated list of file extensions to exclude "
            "from results (e.g. 'png,jpg,css,js')."
        ),
    )


@tool(args_schema=ParamSpiderInput)
def paramspider_crawl(
    target: str,
    exclude: str = "png,jpg,jpeg,gif,svg,css,js,woff,woff2,ico,ttf,eot",
) -> dict[str, Any]:
    """Discover URLs with query parameters from web archives.

    Mines Wayback Machine for URLs with parameters.  Purely passive —
    no requests to the target.  Use results to feed dalfox_scan for XSS
    testing or manual parameter analysis.
    """
    require_binary("paramspider", "paramspider_crawl")

    target = guard_target(target, "paramspider_crawl", TargetType.DOMAIN)

    clean_exclude, exclude_err = sanitize_exclude_extensions(exclude)
    if exclude_err:
        raise ToolException(f"paramspider_crawl: {exclude_err}")

    cmd = [
        "paramspider",
        "-d",
        target,
        "--exclude",
        clean_exclude or exclude,
        "--level",
        "high",
        "--quiet",
    ]

    try:
        code, out, stderr = run_command(
            cmd, timeout=get_tool_timeout("paramspider_crawl", _TIMEOUT)
        )
    except Exception as exc:
        raise ToolException(f"paramspider_crawl: {exc}") from exc

    urls = sorted({line.strip() for line in out.splitlines() if line.strip()})

    # Extract unique parameter names across all URLs.
    param_names: set[str] = set()
    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        param_names.update(params.keys())

    if not urls:
        if code:
            raise ToolException(f"paramspider_crawl: {stderr.strip() or 'scan failed'}")
        return format_tool_output(
            "paramspider_crawl",
            target,
            "ok",
            data={
                "urls": [],
                "count": 0,
                "unique_params": [],
                "message": "no parameterized URLs found",
            },
        )

    return format_tool_output(
        "paramspider_crawl",
        target,
        "ok",
        data={
            "urls": urls,
            "count": len(urls),
            "unique_params": sorted(param_names),
        },
    )


paramspider_crawl.handle_tool_error = True  # type: ignore[attr-defined]
