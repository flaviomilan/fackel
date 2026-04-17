"""DalFox — parameter-based XSS vulnerability scanner.

Runs DalFox against a URL to detect reflected, stored, and DOM-based
XSS vulnerabilities via parameter analysis and payload injection.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    ensure_scheme,
    format_tool_output,
    get_tool_timeout,
    guard_target,
    parse_jsonl,
    require_binary,
    run_command,
)

_TIMEOUT = 300


class DalfoxInput(BaseModel):
    """Input for DalFox XSS scanner."""

    target: str = Field(
        description=(
            "URL to scan for XSS vulnerabilities. Must include scheme "
            "(e.g. 'https://example.com/search?q=test'). URLs with query "
            "parameters are ideal — DalFox analyses each parameter for "
            "injection points."
        ),
    )


@tool(args_schema=DalfoxInput)
def dalfox_scan(target: str) -> dict[str, Any]:
    """Scan a URL for XSS vulnerabilities using DalFox.

    Analyses URL parameters for reflected, stored, and DOM-based XSS.
    Tests with multiple payloads and evasion techniques.  Returns
    confirmed vulnerabilities with proof-of-concept payloads.
    """
    require_binary("dalfox", "dalfox_scan")

    target = guard_target(target, "dalfox_scan", TargetType.HOST_OR_URL)

    target = ensure_scheme(target)

    cmd = [
        "dalfox",
        "url",
        target,
        "--format",
        "json",
        "--silence",
        "--no-color",
        "--worker",
        "5",
        "--timeout",
        "10",
    ]

    try:
        code, out, stderr = run_command(cmd, timeout=get_tool_timeout("dalfox_scan", _TIMEOUT))
    except Exception as exc:
        raise ToolException(f"dalfox_scan: {exc}") from exc

    findings: list[dict[str, Any]] = []
    for raw in parse_jsonl(out):
        finding: dict[str, Any] = {
            "type": raw.get("type", ""),
            "severity": _map_severity(raw.get("severity", raw.get("type", ""))),
            "poc_url": raw.get("proof_of_concept", raw.get("data", "")),
            "param": raw.get("param", ""),
            "payload": raw.get("payload", ""),
            "message": raw.get("message_str", raw.get("message", "")),
            "cwe": raw.get("cwe", ""),
        }
        findings.append(finding)

    if not findings:
        msg = (
            "no XSS vulnerabilities found"
            if code == 0
            else (stderr.strip() or "scan produced no output")
        )
        return format_tool_output(
            "dalfox_scan", target, "ok", data={"findings": [], "message": msg}
        )

    return format_tool_output(
        "dalfox_scan",
        target,
        "ok",
        data={"total": len(findings), "findings": findings},
    )


def _map_severity(raw: str) -> str:
    """Normalise DalFox severity/type to standard severity levels."""
    raw_lower = raw.lower()
    if "verified" in raw_lower or "high" in raw_lower:
        return "high"
    if "reflected" in raw_lower or "medium" in raw_lower:
        return "medium"
    if "low" in raw_lower or "grep" in raw_lower:
        return "low"
    return "info"


dalfox_scan.handle_tool_error = True
