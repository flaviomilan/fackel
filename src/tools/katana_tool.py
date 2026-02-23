import json
import shutil
from typing import Any

from langchain_core.tools import tool
from pydantic import BaseModel, Field


from .utils import ensure_target, run_command, format_tool_output


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
    if not shutil.which("katana"):
        return format_tool_output(
            "katana_crawl",
            target,
            "error",
            error="katana não encontrado no PATH",
        )

    norm = ensure_target(target)
    if not norm:
        return format_tool_output(
            "katana_crawl",
            target,
            "error",
            error="alvo inválido",
        )

    cmd = ["katana", "-u", norm, "-json", "-silent"]
    try:
        code, out, err = run_command(cmd, timeout=240)
    except Exception as exc:
        return format_tool_output(
            "katana_crawl",
            target,
            "error",
            error=str(exc),
        )

    urls: list[str] = []
    for line in out.splitlines():
        try:
            data = json.loads(line)
            url = data.get("url") or data.get("request")
            if url:
                urls.append(url)
        except Exception:
            continue

    if not urls:
        return format_tool_output(
            "katana_crawl",
            target,
            "error" if code else "ok",
            error=err or "sem resultados",
        )

    return format_tool_output(
        "katana_crawl",
        target,
        "ok",
        data={"urls": list(sorted(set(urls)))},
    )
