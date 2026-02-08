import json
import shutil
from typing import Any

from langchain.tools import tool


from tools.utils import ensure_target, run_command, format_tool_output


@tool
def feroxbuster_scan(target: str) -> dict[str, Any]:
    """Directory/content discovery via feroxbuster (JSON lines)."""
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
