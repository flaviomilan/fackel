import json
import shutil
from typing import Any

from langchain.tools import tool


from tools.utils import run_command, extract_host, format_tool_output


@tool
def naabu_scan(host: str) -> dict[str, Any]:
    """Active TCP/UDP port scan via naabu (JSON lines)."""
    if not shutil.which("naabu"):
        return format_tool_output(
            "naabu_scan",
            host,
            "error",
            error="naabu não encontrado no PATH",
        )

    target = extract_host(host)
    if not target:
        return format_tool_output(
            "naabu_scan",
            host,
            "error",
            error="alvo inválido",
        )

    cmd = ["naabu", "-host", target, "-json"]
    try:
        code, out, err = run_command(cmd)
    except Exception as exc:
        return format_tool_output(
            "naabu_scan",
            host,
            "error",
            error=str(exc),
        )


    results: list[dict[str, Any]] = []
    for line in out.splitlines():
        try:
            data = json.loads(line)
            result = data.copy()
            result.update({
                "ip": data.get("ip"),
                "port": data.get("port"),
                "proto": data.get("protocol", "tcp"),
            })
            results.append(result)
        except Exception:
            continue

    if not results:
        return format_tool_output(
            "naabu_scan",
            host,
            "error" if code else "ok",
            error=err or "sem resultados",
        )

    return format_tool_output(
        "naabu_scan",
        host,
        "ok",
        data={"results": results},
    )
