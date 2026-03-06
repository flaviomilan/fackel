"""Open Redirect detection — nuclei-based open redirect scanner.

Wraps Nuclei with redirect-specific template tags to detect open
redirect vulnerabilities that could be used for phishing, OAuth
token theft, and SSRF chaining.
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

_TIMEOUT = 300

# Tags covering open redirect templates in nuclei.
_REDIRECT_TAGS = "redirect,open-redirect"


class OpenRedirectInput(BaseModel):
    """Input for Open Redirect scanner."""

    target: str = Field(
        description=(
            "URL or domain to scan for open redirect vulnerabilities. "
            "URLs with parameters like 'url=', 'next=', 'redirect=' are ideal. "
            "Example: 'https://example.com/login?next=http://evil.com'."
        ),
    )
    severity: str = Field(
        default="",
        description=(
            "Comma-separated severity filter: 'critical', 'high', 'medium', "
            "'low', 'info'. Leave empty for all severities."
        ),
    )


@tool(args_schema=OpenRedirectInput)
def open_redirect_scan(target: str, severity: str = "") -> dict[str, Any]:
    """Scan for open redirect vulnerabilities using Nuclei templates.

    Detects URL-based, meta-refresh, JavaScript-based, and header-based
    open redirects.  These can be chained for phishing attacks, OAuth
    token theft, and SSRF escalation.
    """
    require_binary("nuclei", "open_redirect_scan")

    target = guard_target(target, "open_redirect_scan", TargetType.HOST_OR_URL)

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-tags", _REDIRECT_TAGS]

    severity, sev_err = sanitize_severity(severity)
    if sev_err:
        raise ToolException(f"open_redirect_scan: {sev_err}")
    if severity:
        cmd.extend(["-severity", severity])

    try:
        code, out, stderr = run_command(
            cmd, timeout=get_tool_timeout("open_redirect_scan", _TIMEOUT)
        )
    except Exception as exc:
        raise ToolException(f"open_redirect_scan: {exc}") from exc

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
            "no open redirect vulnerabilities found"
            if code == 0
            else (stderr.strip()[:500] or "scan produced no output")
        )
        return format_tool_output(
            "open_redirect_scan", target, "ok",
            data={"findings": [], "message": msg},
        )

    return format_tool_output(
        "open_redirect_scan", target, "ok",
        data={"total": len(findings), "findings": findings},
    )


open_redirect_scan.handle_tool_error = True  # type: ignore[attr-defined]
