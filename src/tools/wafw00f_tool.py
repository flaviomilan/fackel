import json
import shutil
from typing import Any

from langchain_core.tools import tool


from .utils import ensure_target, run_command, format_tool_output


@tool
def wafw00f_detect(
    target: str,
    check_all: bool = False,
) -> dict[str, Any]:
    """Detect Web Application Firewalls (WAF) and Intrusion Prevention Systems
    protecting a web target using wafw00f.

    Run **before Nuclei** so the vuln-scan agent knows whether scan probes may
    be blocked or rate-limited by a WAF.

    Args:
        target: IP address, domain, or URL to test for WAF presence.
        check_all: If True, test against ALL known WAF signatures (slower but
                   thorough). Default stops after the first match.

    Returns:
        Detected WAF name, manufacturer, and whether the target is protected.
        Returns empty results if no WAF is detected.
    """
    if not shutil.which("wafw00f"):
        return format_tool_output(
            "wafw00f_detect",
            target,
            "error",
            error="wafw00f not found in PATH",
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
    if check_all:
        cmd.append("-a")
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
            error=err or "no results",
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
