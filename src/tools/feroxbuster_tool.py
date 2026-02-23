import json
import shutil
from typing import Any

from langchain_core.tools import tool
from pydantic import BaseModel, Field


from .utils import ensure_target, run_command, format_tool_output


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
    if not shutil.which("feroxbuster"):
        return format_tool_output(
            "feroxbuster_scan",
            target,
            "error",
            error="feroxbuster não encontrado no PATH",
        )

    norm = ensure_target(target)
    if not norm:
        return format_tool_output(
            "feroxbuster_scan",
            target,
            "error",
            error="alvo inválido",
        )

    cmd = ["feroxbuster", "-u", norm, "-json", "-q"]
    try:
        code, out, err = run_command(cmd, timeout=300)
    except Exception as exc:
        return format_tool_output(
            "feroxbuster_scan",
            target,
            "error",
            error=str(exc),
        )

    results: list[dict[str, Any]] = []
    for line in out.splitlines():
        try:
            data = json.loads(line)
            results.append(
                {
                    "url": data.get("url"),
                    "status": data.get("status"),
                    "length": data.get("content_length"),
                    "mime": data.get("content_type"),
                    "words": data.get("words"),
                    "lines": data.get("lines"),
                }
            )
        except Exception:
            continue

    if not results:
        return format_tool_output(
            "feroxbuster_scan",
            target,
            "error" if code else "ok",
            error=err or "sem resultados",
        )

    return format_tool_output(
        "feroxbuster_scan",
        target,
        "ok",
        data={"results": results},
    )
