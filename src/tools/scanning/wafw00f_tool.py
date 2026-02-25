"""WAF detection via wafw00f."""

from __future__ import annotations

import json
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

_TIMEOUT = 120  # seconds


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
    require_binary("wafw00f", "wafw00f_detect")

    target = guard_target(target, "wafw00f_detect", TargetType.HOST_OR_URL)

    # wafw00f needs a URL; add scheme if bare host
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    cmd = ["wafw00f", target, "-f", "json"]
    if check_all:
        cmd.append("-a")

    try:
        code, out, stderr = run_command(cmd, timeout=get_tool_timeout("wafw00f_detect", _TIMEOUT))
    except Exception as exc:
        raise ToolException(f"wafw00f_detect: {exc}") from exc

    try:
        data = json.loads(out)
    except (json.JSONDecodeError, ValueError):
        data = None

    if not data:
        if code:
            raise ToolException(f"wafw00f_detect: {stderr or 'scan failed'}")
        return format_tool_output(
            "wafw00f_detect",
            target,
            "ok",
            data={"identified": [], "message": stderr or "no results"},
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


wafw00f_detect.handle_tool_error = True
