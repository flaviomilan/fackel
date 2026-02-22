import json
import shutil
from typing import Any

from langchain_core.tools import tool


from .utils import ensure_target, run_command, format_tool_output


@tool
def katana_crawl(target: str) -> dict[str, Any]:
    """Crawl target with katana (URL discovery, JSON lines)."""
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
