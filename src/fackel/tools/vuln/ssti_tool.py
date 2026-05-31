"""SSTI detection — nuclei-based Server-Side Template Injection scanner.

Wraps Nuclei with SSTI-specific template tags to detect template
injection vulnerabilities in Jinja2, Twig, Freemarker, Mako,
Smarty, Velocity and other server-side template engines.
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
    sanitize_severity,
)

_TIMEOUT = 300

# Tags covering SSTI-related nuclei templates.
_SSTI_TAGS = "ssti"


class SstiScanInput(BaseModel):
    """Input for SSTI detection scanner."""

    target: str = Field(
        description=(
            "URL to scan for Server-Side Template Injection. "
            "URLs with user-controlled parameters are ideal. "
            "Example: 'https://example.com/render?template=hello'. "
            "The scanner uses nuclei templates that inject template "
            "syntax payloads (e.g. {{7*7}}) and check for evaluation."
        ),
    )
    severity: str = Field(
        default="",
        description=(
            "Comma-separated severity filter: 'critical', 'high', 'medium', "
            "'low', 'info'. Leave empty for all severities."
        ),
    )


@tool(args_schema=SstiScanInput)
def ssti_scan(target: str, severity: str = "") -> dict[str, Any]:
    """Scan for Server-Side Template Injection (SSTI) vulnerabilities.

    Uses Nuclei templates tagged with SSTI patterns.  SSTI can lead to
    Remote Code Execution (RCE) when template engines evaluate
    attacker-controlled input.  Detects injection in Jinja2, Twig,
    Freemarker, Mako, Smarty, and other engines.
    """
    require_binary("nuclei", "ssti_scan")

    target = guard_target(target, "ssti_scan", TargetType.HOST_OR_URL)

    target = ensure_scheme(target)

    cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-tags", _SSTI_TAGS]

    severity, sev_err = sanitize_severity(severity)
    if sev_err:
        raise ToolException(f"ssti_scan: {sev_err}")
    if severity:
        cmd.extend(["-severity", severity])

    try:
        code, out, stderr = run_command(cmd, timeout=get_tool_timeout("ssti_scan", _TIMEOUT))
    except Exception as exc:
        raise ToolException(f"ssti_scan: {exc}") from exc

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
            "no SSTI vulnerabilities found"
            if code == 0
            else (stderr.strip()[:500] or "scan produced no output")
        )
        return format_tool_output(
            "ssti_scan",
            target,
            "ok",
            data={"findings": [], "message": msg},
        )

    return format_tool_output(
        "ssti_scan",
        target,
        "ok",
        data={"total": len(findings), "findings": findings},
    )


ssti_scan.handle_tool_error = True
