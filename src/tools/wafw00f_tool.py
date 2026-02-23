import json
import shutil
from typing import Any

from langchain_core.tools import tool
from pydantic import BaseModel, Field


from .utils import ensure_target, run_command, format_tool_output


class Wafw00fInput(BaseModel):
    """Input for wafw00f WAF detector."""

    target: str = Field(
        description=(
            "Domain name or URL to test for WAF presence. "
            "Use the domain name (not bare IPs) — SSL/SNI fails on "
            "IPs behind CDNs like Cloudflare."
        ),
    )
    check_all: bool = Field(
        default=False,
        description=(
            "Test against ALL known WAF signatures (slower but thorough). "
            "Default stops after the first match. Use True when initial "
            "scan returns no results but nuclei detected a WAF."
        ),
    )


@tool(args_schema=Wafw00fInput)
def wafw00f_detect(
    target: str,
    check_all: bool = False,
) -> dict[str, Any]:
    """Detect Web Application Firewalls (WAF) protecting a web target.

    Run before Nuclei to understand whether scan probes may be blocked or
    rate-limited by a WAF.  Uses the domain name for correct SSL/SNI.
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
