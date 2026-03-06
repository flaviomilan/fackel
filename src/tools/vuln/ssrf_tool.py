"""SSRF detection — nuclei-based Server-Side Request Forgery scanner.

Wraps Nuclei with SSRF-specific template tags to detect server-side
request forgery vulnerabilities including blind SSRF, partial SSRF,
and full read SSRF via known CVE templates and generic detection rules.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    format_tool_output,
    get_tool_timeout,
    guard_target,
    parse_jsonl,
    require_binary,
    run_command,
    sanitize_severity,
)

_TIMEOUT = 600

# Tags that cover SSRF-related nuclei templates.
_SSRF_TAGS = "ssrf,oast"


class SsrfDetectInput(BaseModel):
    """Input for SSRF detection scanner."""

    target: str = Field(
        description=(
            "URL or domain to scan for SSRF vulnerabilities. "
            "Example: 'https://example.com' or 'https://api.example.com'. "
            "The scanner uses nuclei templates tagged with SSRF-related "
            "detection patterns including blind SSRF via OOB callbacks."
        ),
    )
    severity: str = Field(
        default="",
        description=(
            "Comma-separated severity filter: 'critical', 'high', 'medium', "
            "'low', 'info'. Leave empty for all severities."
        ),
    )


@tool(args_schema=SsrfDetectInput)
def ssrf_detect(target: str, severity: str = "") -> dict[str, Any]:
    """Scan for Server-Side Request Forgery (SSRF) vulnerabilities.

    Uses Nuclei templates tagged with SSRF and OAST (Out-of-Band
    Application Security Testing) patterns.  Detects blind SSRF,
    partial read SSRF, and full-read SSRF via known CVEs and generic
    detection rules.
    """
    require_binary("nuclei", "ssrf_detect")

    target = guard_target(target, "ssrf_detect", TargetType.HOST_OR_URL)

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-tags", _SSRF_TAGS]

    severity, sev_err = sanitize_severity(severity)
    if sev_err:
        raise ToolException(f"ssrf_detect: {sev_err}")
    if severity:
        cmd.extend(["-severity", severity])

    try:
        code, out, stderr = run_command(
            cmd, timeout=get_tool_timeout("ssrf_detect", _TIMEOUT)
        )
    except Exception as exc:
        raise ToolException(f"ssrf_detect: {exc}") from exc

    findings: list[dict[str, Any]] = []
    for raw in parse_jsonl(out):
        info = raw.get("info", {})
        finding: dict[str, Any] = {
            "template_id": raw.get("template-id", ""),
            "name": info.get("name", ""),
            "severity": info.get("severity", "unknown"),
            "matched_at": raw.get("matched-at", ""),
            "type": raw.get("type", ""),
            "host": raw.get("host", ""),
            "ip": raw.get("ip", ""),
            "tags": info.get("tags", []),
            "description": info.get("description", ""),
            "matcher_name": raw.get("matcher-name", ""),
        }
        extracted = raw.get("extracted-results")
        if extracted:
            finding["extracted_results"] = extracted
        curl_cmd = raw.get("curl-command", "")
        if curl_cmd:
            finding["curl_command"] = curl_cmd
        findings.append(finding)

    if not findings:
        msg = (
            "no SSRF vulnerabilities found"
            if code == 0
            else (stderr.strip()[:500] or "scan produced no output")
        )
        return format_tool_output(
            "ssrf_detect", target, "ok",
            data={"findings": [], "message": msg},
        )

    return format_tool_output(
        "ssrf_detect", target, "ok",
        data={"total": len(findings), "findings": findings},
    )


ssrf_detect.handle_tool_error = True  # type: ignore[attr-defined]
