"""TLS/SSL analysis via testssl.sh.

Provides deep TLS inspection: protocol versions, cipher suites, certificate
chain validation, HSTS, known vulnerabilities (POODLE, BEAST, Heartbleed,
ROBOT, DROWN, Logjam, etc.).

Requires ``testssl.sh`` in PATH.  Install via:
  git clone --depth 1 https://github.com/drwetter/testssl.sh.git
  ln -s $(pwd)/testssl.sh/testssl.sh ~/.local/bin/testssl.sh
"""

from __future__ import annotations

import json
import shutil
from typing import Any

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from .utils import format_tool_output


class TestSSLInput(BaseModel):
    """Input schema for testssl.sh TLS/SSL scanner."""

    target: str = Field(
        description=(
            "Target to scan. Can be hostname, hostname:port, or IP:port. "
            "Defaults to port 443 when omitted."
        ),
    )
    severity: str = Field(
        default="",
        description=(
            "Filter results by severity: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'. "
            "Comma-separated. Empty = all findings."
        ),
    )
    checks: str = Field(
        default="",
        description=(
            "Specific checks to run (faster than full scan). Options: "
            "'protocols' (TLS versions), 'ciphers' (cipher suites), "
            "'vulnerabilities' (known vulns), 'headers' (HTTP security headers), "
            "'certificate' (cert chain). Comma-separated, empty = full scan."
        ),
    )


def _parse_severity(finding: dict[str, Any]) -> str:
    """Normalise testssl.sh severity to a standard level."""
    sev = str(finding.get("severity", "INFO")).upper()
    mapping = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "WARN": "medium",
        "INFO": "info",
        "OK": "info",
        "DEBUG": "info",
        "FATAL": "critical",
    }
    return mapping.get(sev, "info")


@tool(args_schema=TestSSLInput)
def testssl_scan(
    target: str,
    severity: str = "",
    checks: str = "",
) -> dict[str, Any]:
    """Deep TLS/SSL analysis: protocols, ciphers, certificate chain, and known
    vulnerabilities (Heartbleed, POODLE, BEAST, ROBOT, DROWN, Logjam, etc.).

    Use after port scanning confirms port 443 (or another TLS port) is open.
    Provides cipher-level detail that nuclei SSL templates cannot match.
    """
    if not shutil.which("testssl.sh"):
        return format_tool_output(
            "testssl_scan",
            target,
            "error",
            error=(
                "testssl.sh not found in PATH. Install: "
                "git clone --depth 1 https://github.com/drwetter/testssl.sh.git && "
                "ln -s $(pwd)/testssl.sh/testssl.sh ~/.local/bin/testssl.sh"
            ),
        )

    host = target.strip()
    if not host:
        return format_tool_output(
            "testssl_scan", target, "error", error="empty target",
        )

    cmd = [
        "testssl.sh",
        "--jsonfile=-",  # JSON to stdout
        "--warnings", "off",
        "--color", "0",
        "--sneaky",  # less intrusive timing
    ]

    # Map check names to testssl.sh flags.
    check_flags = {
        "protocols": "-p",
        "ciphers": "-E",
        "vulnerabilities": "-U",
        "headers": "-h",
        "certificate": "-S",
    }
    if checks.strip():
        for check in checks.split(","):
            check = check.strip().lower()
            if check in check_flags:
                cmd.append(check_flags[check])

    cmd.append(host)

    try:
        from .utils import run_command
        code, out, err = run_command(cmd, timeout=300)
    except Exception as exc:
        return format_tool_output(
            "testssl_scan", target, "error", error=str(exc),
        )

    # Parse JSON output (testssl.sh outputs a JSON array to stdout with --jsonfile=-).
    findings: list[dict[str, Any]] = []
    severity_filter = {s.strip().lower() for s in severity.split(",") if s.strip()} if severity.strip() else set()

    try:
        records = json.loads(out) if out.strip() else []
        if isinstance(records, dict):
            records = records.get("scanResult", [{}])
            if records:
                records = records[0].get("findings", records)
    except json.JSONDecodeError:
        # Fallback: try line-by-line JSONL
        records = []
        for line in out.splitlines():
            try:
                records.append(json.loads(line))
            except (json.JSONDecodeError, TypeError):
                continue

    for record in records:
        if not isinstance(record, dict):
            continue

        finding_id = record.get("id", "")
        sev = _parse_severity(record)
        finding_text = record.get("finding", "")

        if severity_filter and sev not in severity_filter:
            continue

        findings.append({
            "id": finding_id,
            "severity": sev,
            "finding": finding_text,
            "cve": record.get("cve", ""),
            "cwe": record.get("cwe", ""),
        })

    # Categorise findings for the summary.
    protocols = [f for f in findings if f["id"].startswith(("SSLv", "TLS", "NPN", "ALPN"))]
    vulns = [f for f in findings if f["severity"] in ("critical", "high", "medium")]
    cert_findings = [f for f in findings if "cert" in f["id"].lower()]

    return format_tool_output(
        "testssl_scan",
        target,
        "ok",
        data={
            "findings": findings,
            "summary": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f["severity"] == "critical"),
                "high": sum(1 for f in findings if f["severity"] == "high"),
                "medium": sum(1 for f in findings if f["severity"] == "medium"),
                "low": sum(1 for f in findings if f["severity"] == "low"),
                "info": sum(1 for f in findings if f["severity"] == "info"),
                "protocols_checked": len(protocols),
                "cert_findings": len(cert_findings),
                "vulnerabilities": len(vulns),
            },
        },
    )
