"""WhatWeb — web technology fingerprinting.

Identifies CMS platforms, frameworks, JavaScript libraries, server software,
analytics, and other technologies from HTTP responses and page content.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    ensure_scheme,
    format_tool_output,
    get_tool_timeout,
    guard_target,
    require_binary,
    run_command,
)

_TIMEOUT = 120


class WhatWebInput(BaseModel):
    """Input for WhatWeb technology fingerprinting."""

    target: str = Field(
        description=(
            "Domain, IP, or URL to fingerprint technologies for "
            "(e.g. 'example.com', 'https://example.com'). Identifies "
            "CMS (WordPress, Joomla, Drupal), frameworks (Laravel, "
            "Django, Rails), server software, JavaScript libraries, "
            "analytics, and more."
        ),
    )
    aggression: int = Field(
        default=1,
        description=(
            "Scan aggression level: 1 = stealthy (single HTTP request), "
            "3 = aggressive (extra requests for deeper fingerprinting). "
            "Default 1 for passive reconnaissance."
        ),
    )


@tool(args_schema=WhatWebInput)
def whatweb_scan(target: str, aggression: int = 1) -> dict[str, Any]:
    """Fingerprint web technologies on a target.

    Identifies CMS platforms, frameworks, server software, JavaScript
    libraries, analytics, and other technologies.  Aggression level 1
    sends a single HTTP request — safe for reconnaissance.
    """
    require_binary("whatweb", "whatweb_scan")

    target = guard_target(target, "whatweb_scan", TargetType.HOST_OR_URL)

    target = ensure_scheme(target)

    aggression = max(1, min(aggression, 3))

    cmd = [
        "whatweb",
        f"--aggression={aggression}",
        "--log-json=-",
        "--color=never",
        "--no-errors",
        target,
    ]

    try:
        code, out, stderr = run_command(cmd, timeout=get_tool_timeout("whatweb_scan", _TIMEOUT))
    except Exception as exc:
        raise ToolException(f"whatweb_scan: {exc}") from exc

    technologies: list[dict[str, Any]] = []
    stripped = out.strip()

    if stripped:
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue

            plugins = entry.get("plugins", {})
            for name, details in plugins.items():
                tech: dict[str, Any] = {"name": name}
                if isinstance(details, dict):
                    if details.get("version"):
                        version = details["version"]
                        tech["version"] = version[0] if isinstance(version, list) else version
                    if details.get("string"):
                        string = details["string"]
                        tech["detail"] = string[0] if isinstance(string, list) else string
                technologies.append(tech)

    if not technologies:
        if code:
            raise ToolException(f"whatweb_scan: {stderr.strip() or 'scan failed'}")
        return format_tool_output(
            "whatweb_scan",
            target,
            "ok",
            data={
                "technologies": [],
                "count": 0,
                "message": "no technologies identified",
            },
        )

    return format_tool_output(
        "whatweb_scan",
        target,
        "ok",
        data={
            "technologies": technologies,
            "count": len(technologies),
        },
    )


whatweb_scan.handle_tool_error = True
