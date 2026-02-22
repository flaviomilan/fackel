"""Nuclei vulnerability scanner tool.

Runs Nuclei templates against a host/URL, returning structured findings
with severity, template ID, and matched location.
"""

from __future__ import annotations

import json
import shutil
from typing import Any

from langchain_core.tools import tool

from .utils import ensure_target, format_tool_output, run_command


@tool
def nuclei_scan(target: str, severity: str = "", tags: str = "") -> dict[str, Any]:
    """Scan a host or URL for vulnerabilities, misconfigurations, and exposed
    technologies using Nuclei's template engine.

    Nuclei runs community-maintained templates that detect CVEs, default
    credentials, exposed panels, technology fingerprints, and misconfigurations.
    Use `severity` and `tags` to focus scans on what matters.

    Args:
        target: IP address, domain, or full URL to scan.
        severity: Comma-separated severity filter (e.g. "critical,high" or
                  "medium,low,info"). Leave empty to scan all severities.
        tags: Comma-separated template tags to filter (e.g. "cve,wordpress",
              "graphql,api", "tech,misconfig"). Leave empty to use all templates.
              Common tags: cve, wordpress, joomla, drupal, graphql, api,
              misconfig, exposure, tech, default-login, takeover, rce, xss,
              sqli, lfi, ssrf, redirect, nginx, apache, iis.

    Returns:
        List of findings with template_id, name, severity, matched URL, type,
        host, IP, and template tags.
    """
    if not shutil.which("nuclei"):
        return format_tool_output("nuclei_scan", target, "error", error="nuclei not in PATH")

    norm = ensure_target(target)
    if not norm:
        return format_tool_output("nuclei_scan", target, "error", error="invalid target")

    cmd = ["nuclei", "-u", norm, "-jsonl", "-silent"]
    if severity.strip():
        cmd.extend(["-severity", severity.strip()])
    if tags.strip():
        cmd.extend(["-tags", tags.strip()])

    try:
        code, out, err = run_command(cmd, timeout=3000)
    except Exception as exc:
        return format_tool_output("nuclei_scan", target, "error", error=str(exc))

    findings: list[dict[str, Any]] = []
    for line in out.splitlines():
        try:
            raw = json.loads(line)
            info = raw.get("info", {})
            finding: dict[str, Any] = {
                "template_id": raw.get("template-id", ""),
                "matcher_name": raw.get("matcher-name", ""),
                "name": info.get("name", ""),
                "severity": info.get("severity", "unknown"),
                "matched_at": raw.get("matched-at", ""),
                "type": raw.get("type", ""),
                "host": raw.get("host", ""),
                "ip": raw.get("ip", ""),
                "tags": info.get("tags", []),
                "description": info.get("description", ""),
            }
            # extracted-results contain the actual intelligence:
            # CSP policies, DKIM keys, SPF records, tenant IDs, TLS versions, etc.
            extracted = raw.get("extracted-results")
            if extracted:
                finding["extracted_results"] = extracted
            curl_cmd = raw.get("curl-command", "")
            if curl_cmd:
                finding["curl_command"] = curl_cmd
            findings.append(finding)
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
