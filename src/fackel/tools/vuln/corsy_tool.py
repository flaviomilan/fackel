"""Corsy — CORS misconfiguration detection.

Tests web targets for dangerous CORS configurations that could allow
cross-origin data theft, credential leakage, or session hijacking.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
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


class CorsyInput(BaseModel):
    """Input for Corsy CORS misconfiguration scanner."""

    target: str = Field(
        description=(
            "URL to test for CORS misconfigurations "
            "(e.g. 'https://example.com' or 'https://api.example.com'). "
            "Corsy tests various origin reflection patterns that could "
            "allow cross-origin attacks."
        ),
    )


@tool(args_schema=CorsyInput)
def corsy_scan(target: str) -> dict[str, Any]:
    """Test a URL for CORS misconfigurations.

    Checks for dangerous CORS patterns: wildcard origins, null origin
    reflection, subdomain reflection, pre-domain bypass, post-domain
    bypass, and credential exposure.  Detects configurations that could
    allow cross-origin data theft.
    """
    require_binary("corsy", "corsy_scan")

    target = guard_target(target, "corsy_scan", TargetType.HOST_OR_URL)

    target = ensure_scheme(target)

    cmd = [
        "corsy",
        "-u",
        target,
        "-q",
    ]

    json_dir = tempfile.mkdtemp()
    json_file = Path(json_dir) / "corsy_output.json"
    cmd.extend(["-o", str(json_file)])

    try:
        code, _out, stderr = run_command(cmd, timeout=get_tool_timeout("corsy_scan", _TIMEOUT))
    except Exception as exc:
        raise ToolException(f"corsy_scan: {exc}") from exc

    findings: list[dict[str, Any]] = []

    raw = ""
    if json_file.exists():
        raw = json_file.read_text().strip()
        json_file.unlink(missing_ok=True)
    Path(json_dir).rmdir()

    if raw:
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            parsed = None

        if isinstance(parsed, dict):
            for url, issues in parsed.items():
                if not isinstance(issues, list):
                    issues = [issues] if issues else []
                for issue in issues:
                    if isinstance(issue, dict):
                        findings.append(
                            {
                                "url": url,
                                "type": issue.get("type", issue.get("class", "")),
                                "description": issue.get("description", ""),
                                "severity": issue.get("severity", "medium"),
                                "acao_header": issue.get("acao_header", ""),
                                "acac_header": issue.get("acac_header", ""),
                            }
                        )
        elif isinstance(parsed, list):
            for issue in parsed:
                if isinstance(issue, dict):
                    findings.append(
                        {
                            "url": issue.get("url", target),
                            "type": issue.get("type", issue.get("class", "")),
                            "description": issue.get("description", ""),
                            "severity": issue.get("severity", "medium"),
                            "acao_header": issue.get("acao_header", ""),
                            "acac_header": issue.get("acac_header", ""),
                        }
                    )

    if not findings:
        if code:
            raise ToolException(f"corsy_scan: {stderr.strip() or 'scan failed'}")
        return format_tool_output(
            "corsy_scan",
            target,
            "ok",
            data={
                "total": 0,
                "findings": [],
                "message": "no CORS misconfigurations detected",
            },
        )

    return format_tool_output(
        "corsy_scan",
        target,
        "ok",
        data={
            "total": len(findings),
            "findings": findings,
        },
    )


corsy_scan.handle_tool_error = True
