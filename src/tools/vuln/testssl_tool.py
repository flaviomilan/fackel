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
import tempfile
from pathlib import Path
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
    sanitize_severity,
)

_TIMEOUT = 600


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
    fast: bool = Field(
        default=True,
        description=(
            "Use --fast mode for quicker results (skip some cipher checks). "
            "Default: True. Set to False for exhaustive TLS analysis when "
            "deep cipher enumeration is needed."
        ),
    )
    openssl_timeout: int = Field(
        default=10,
        description=(
            "Timeout in seconds for individual openssl connections (1-30). "
            "Increase for targets behind CDN/WAF with high latency. "
            "Default: 10."
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
    fast: bool = True,
    openssl_timeout: int = 10,
) -> dict[str, Any]:
    """Deep TLS/SSL analysis: protocols, ciphers, certificate chain, and known
    vulnerabilities (Heartbleed, POODLE, BEAST, ROBOT, DROWN, Logjam, etc.).

    Use after port scanning confirms port 443 (or another TLS port) is open.
    Provides cipher-level detail that nuclei SSL templates cannot match.
    """
    require_binary("testssl.sh", "testssl_scan")

    host = guard_target(target, "testssl_scan", TargetType.HOST_PORT)

    openssl_timeout = max(1, min(openssl_timeout, 30))

    # testssl.sh does not support streaming JSON to stdout via "--jsonfile=-";
    # it treats "-" as a literal filename and creates a file called "-" in cwd.
    # Use a temporary file and read it back after the scan completes.
    tmpdir = tempfile.mkdtemp(prefix="testssl_")
    json_path = Path(tmpdir) / "results.json"

    cmd = [
        "testssl.sh",
        "--jsonfile", str(json_path),
        "--overwrite",
        "--warnings", "off",
        "--color", "0",
        "--sneaky",
        f"--openssl-timeout={openssl_timeout}",
    ]

    if fast:
        cmd.append("--fast")

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
        _code, _stdout, _stderr = run_command(cmd, timeout=get_tool_timeout("testssl_scan", _TIMEOUT))
        out = json_path.read_text() if json_path.is_file() else ""
    except Exception as exc:
        raise ToolException(f"testssl_scan: {exc}") from exc
    finally:
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)

    findings: list[dict[str, Any]] = []

    severity, sev_err = sanitize_severity(severity)
    if sev_err:
        raise ToolException(f"testssl_scan: {sev_err}")

    severity_filter = {s.strip() for s in severity.split(",") if s.strip()} if severity else set()

    try:
        records = json.loads(out) if out.strip() else []
        if isinstance(records, dict):
            records = records.get("scanResult", [{}])
            if records:
                records = records[0].get("findings", records)
    except json.JSONDecodeError:
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

        findings.append(
            {
                "id": finding_id,
                "severity": sev,
                "finding": finding_text,
                "cve": record.get("cve", ""),
                "cwe": record.get("cwe", ""),
            }
        )

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


testssl_scan.handle_tool_error = True
