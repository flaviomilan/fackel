import json
import shutil
from typing import Any

from langchain.tools import tool


from tools.utils import ensure_target, run_command, format_tool_output


@tool
def wafw00f_detect(target: str) -> dict[str, Any]:
    """Detect WAF/IPS via wafw00f (JSON)."""
    if not shutil.which("wafw00f"):
        return format_tool_output(
            "wafw00f_detect",
            target,
            "error",
            error="wafw00f não encontrado no PATH",
        )

    norm = ensure_target(target)
    if not norm:
        return format_tool_output(
            "wafw00f_detect",
            target,
            "error",
            error="alvo inválido",
        )

    cmd = ["wafw00f", norm, "-f", "json"]
    try:
        code, out, err = run_command(cmd, timeout=120)
    except Exception as exc:
        return format_tool_output(
            "wafw00f_detect",
            target,
            "error",
            error=str(exc),
        )

    try:
        data = json.loads(out)
    except Exception:
        data = None

    if not data:
        return format_tool_output(
            "wafw00f_detect",
            target,
            "error" if code else "ok",
            error=err or "sem resultados",
        )

    return format_tool_output(
        "wafw00f_detect",
        target,
        "ok",
        data={
            "identified": data.get("identified", []),
            "waf_name": data.get("waf_name"),
            "manufacturer": data.get("manufacturer"),
        },
    )
