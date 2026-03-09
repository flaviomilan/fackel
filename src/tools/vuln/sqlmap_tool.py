"""SQLMap — automated SQL injection detection.

Runs SQLMap in safe batch mode against a URL to detect SQL injection
vulnerabilities in query parameters, POST data, cookies and headers.
"""

from __future__ import annotations

import shutil
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
)

_TIMEOUT = 300


class SqlmapInput(BaseModel):
    """Input for SQLMap SQL injection scanner."""

    target: str = Field(
        description=(
            "URL with query parameters to test for SQL injection. "
            "Example: 'https://example.com/page?id=1'. "
            "SQLMap analyses each parameter for injection points. "
            "URLs with GET parameters are ideal."
        ),
    )
    level: int = Field(
        default=1,
        description=(
            "Testing level (1-5). Higher levels test more injection points. "
            "Level 1: default (GET/POST params). "
            "Level 2: adds Cookie header. "
            "Level 3: adds User-Agent, Referer. "
            "Recommended: 1 or 2 for automated scans."
        ),
    )
    risk: int = Field(
        default=1,
        description=(
            "Risk level (1-3). Higher risks use more aggressive payloads. "
            "Risk 1: safe (only innocuous tests). "
            "Risk 2: adds time-based blind. "
            "Risk 3: adds OR-based tests (may alter data). "
            "Recommended: 1 for automated scans."
        ),
    )
    forms: bool = Field(
        default=False,
        description=(
            "When True, sqlmap automatically parses and tests HTML forms "
            "found on the target page. Useful for POST-based injection."
        ),
    )
    data: str = Field(
        default="",
        description=(
            "POST data string to test. Example: 'username=admin&password=test'. "
            "When provided, sqlmap sends POST requests with this data and "
            "tests each parameter for injection."
        ),
    )
    cookie: str = Field(
        default="",
        description=(
            "HTTP Cookie header value for authenticated scans. "
            "Example: 'PHPSESSID=abc123; token=xyz'. "
            "Required when testing endpoints behind authentication."
        ),
    )
    technique: str = Field(
        default="",
        description=(
            "SQL injection techniques to test. Combination of: "
            "B=Boolean-based blind, E=Error-based, U=UNION query, "
            "S=Stacked queries, T=Time-based blind, Q=Inline queries. "
            "Example: 'BEU' to skip time-based (faster). "
            "Leave empty (default) to test all techniques."
        ),
    )
    random_agent: bool = Field(
        default=True,
        description=(
            "Use a random User-Agent header per request to evade "
            "fingerprint-based WAF rules. Enabled by default."
        ),
    )
    threads: int = Field(
        default=1,
        description=(
            "Number of concurrent HTTP requests (1-5). Higher values "
            "speed up the scan but increase server load. "
            "Default: 1. Max allowed: 5 for safety."
        ),
    )


@tool(args_schema=SqlmapInput)
def sqlmap_scan(
    target: str,
    level: int = 1,
    risk: int = 1,
    forms: bool = False,
    data: str = "",
    cookie: str = "",
    technique: str = "",
    random_agent: bool = True,
    threads: int = 1,
) -> dict[str, Any]:
    """Scan a URL for SQL injection vulnerabilities using SQLMap.

    Runs in safe batch mode (--batch) with configurable level, risk,
    techniques, POST data, cookies, and threading.  Detects boolean-based,
    time-based, error-based, UNION-based, and stacked-query injection
    types.  Returns confirmed injection points with technique details
    and payload proof.
    """
    require_binary("sqlmap", "sqlmap_scan")

    target = guard_target(target, "sqlmap_scan", TargetType.HOST_OR_URL)

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    # Clamp level/risk to safe automated ranges.
    level = max(1, min(level, 3))
    risk = max(1, min(risk, 2))
    threads = max(1, min(threads, 5))

    output_dir = tempfile.mkdtemp(prefix="sqlmap_")

    cmd = [
        "sqlmap",
        "-u",
        target,
        "--batch",
        f"--level={level}",
        f"--risk={risk}",
        f"--threads={threads}",
        "--output-dir",
        output_dir,
        "--flush-session",
        "--disable-coloring",
    ]

    if forms:
        cmd.append("--forms")

    if data:
        cmd.extend(["--data", data])

    if cookie:
        cmd.extend(["--cookie", cookie])

    if technique:
        # Validate technique characters.
        valid_chars = set("BEUTQS")
        sanitized = "".join(c for c in technique.upper() if c in valid_chars)
        if sanitized:
            cmd.extend(["--technique", sanitized])

    if random_agent:
        cmd.append("--random-agent")

    try:
        code, out, stderr = run_command(cmd, timeout=get_tool_timeout("sqlmap_scan", _TIMEOUT))
    except Exception as exc:
        raise ToolException(f"sqlmap_scan: {exc}") from exc

    findings: list[dict[str, Any]] = []

    # Parse sqlmap text output for confirmed injections.
    _parse_sqlmap_text(out, findings)

    # Also attempt to parse log files in output dir.
    try:
        _parse_sqlmap_output_dir(output_dir, findings, target)
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)

    # Deduplicate by (parameter, technique).
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for f in findings:
        key = f"{f.get('parameter', '')}-{f.get('technique', '')}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = unique

    if not findings:
        msg = (
            "no SQL injection vulnerabilities found"
            if code == 0
            else (stderr.strip()[:500] or "scan produced no output")
        )
        return format_tool_output(
            "sqlmap_scan",
            target,
            "ok",
            data={"findings": [], "message": msg},
        )

    return format_tool_output(
        "sqlmap_scan",
        target,
        "ok",
        data={"total": len(findings), "findings": findings},
    )


def _parse_sqlmap_text(output: str, findings: list[dict[str, Any]]) -> None:
    """Extract injection findings from sqlmap stdout text."""
    lines = output.splitlines()
    current_param = ""

    for line in lines:
        stripped = line.strip()

        # Detect parameter context.
        if "parameter '" in stripped.lower() or 'parameter "' in stripped.lower():
            # Extract parameter name
            for quote in ("'", '"'):
                if f"parameter {quote}" in stripped.lower():
                    start = stripped.lower().index(f"parameter {quote}") + len(f"parameter {quote}")
                    rest = stripped[start:]
                    end = rest.find(quote)
                    if end > 0:
                        current_param = rest[:end]
                    break

        # Detect confirmed injection.
        if "is vulnerable" in stripped.lower() or "injectable" in stripped.lower():
            findings.append(
                {
                    "parameter": current_param,
                    "technique": "confirmed",
                    "severity": "high",
                    "detail": stripped,
                }
            )

        # Detect specific techniques.
        for technique in (
            "boolean-based blind",
            "time-based blind",
            "error-based",
            "UNION query",
            "stacked queries",
        ):
            if technique.lower() in stripped.lower():
                findings.append(
                    {
                        "parameter": current_param,
                        "technique": technique,
                        "severity": "high",
                        "detail": stripped,
                    }
                )


def _parse_sqlmap_output_dir(
    output_dir: str,
    findings: list[dict[str, Any]],
    target: str,
) -> None:
    """Attempt to read sqlmap's structured output files."""
    output_path = Path(output_dir)
    for log_file in output_path.rglob("log"):
        try:
            content = log_file.read_text()
            for line in content.splitlines():
                stripped = line.strip()
                if "is vulnerable" in stripped.lower():
                    findings.append(
                        {
                            "parameter": "",
                            "technique": "log",
                            "severity": "high",
                            "detail": stripped,
                        }
                    )
        except OSError:
            pass


sqlmap_scan.handle_tool_error = True  # type: ignore[attr-defined]
