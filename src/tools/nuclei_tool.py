"""Nuclei vulnerability scanner tool.

Runs Nuclei templates against a host/URL, returning structured findings
with severity, template ID, and matched location.
"""

from __future__ import annotations

import json
import shutil
from typing import Any

from langchain_core.tools import tool

from tools.utils import ensure_target, format_tool_output, run_command


@tool
def nuclei_scan(target: str, severity: str = "") -> dict[str, Any]:
    """Scan a host or URL for vulnerabilities, misconfigurations, and exposed technologies using Nuclei templates.

    Returns a list of findings, each with template_id, name, severity,
    matched URL, and detected technology type.

    Args:
        target: IP address, domain, or full URL to scan.
        severity: Comma-separated severity filter (critical,high,medium,low,info).
                  Leave empty to scan all severities.
    """
    if not shutil.which("nuclei"):
        return format_tool_output("nuclei_scan", target, "error", error="nuclei not in PATH")

    norm = ensure_target(target)
    if not norm:
        return format_tool_output("nuclei_scan", target, "error", error="invalid target")

    cmd = ["nuclei", "-u", norm, "-jsonl", "-silent"]
    if severity.strip():
        cmd.extend(["-severity", severity.strip()])

    try:
        code, out, err = run_command(cmd, timeout=3000)
    except Exception as exc:
        return format_tool_output("nuclei_scan", target, "error", error=str(exc))

    findings: list[dict[str, Any]] = []
    for line in out.splitlines():
        try:
            raw = json.loads(line)
            info = raw.get("info", {})
            findings.append({
                "template_id": raw.get("template-id", ""),
                "name": info.get("name", ""),
                "severity": info.get("severity", "unknown"),
                "matched_at": raw.get("matched-at", ""),
                "type": raw.get("type", ""),
                "host": raw.get("host", ""),
                "ip": raw.get("ip", ""),
                "tags": info.get("tags", []),
            })
        except (json.JSONDecodeError, TypeError):
            continue

    if not findings:
        msg = "no vulnerabilities found" if code == 0 else (err.strip() or "scan produced no output")
        return format_tool_output("nuclei_scan", target, "ok", data={"findings": [], "message": msg})

    return format_tool_output(
        "nuclei_scan",
        target,
        "ok",
        data={
            "total": len(findings),
            "findings": findings,
        },
    )
