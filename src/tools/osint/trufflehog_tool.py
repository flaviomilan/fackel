"""TruffleHog — credential and secret leak detection.

Scans public Git repositories and other data sources for accidentally
committed API keys, passwords, tokens, and other secrets.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field
from urllib.parse import urlparse

from fackel.tooling import (
    format_tool_output,
    get_tool_timeout,
    parse_jsonl,
    require_binary,
    run_command,
)

_TIMEOUT = 300


class TrufflehogInput(BaseModel):
    """Input for TruffleHog secret scanning."""

    target: str = Field(
        description=(
            "GitHub organization or repository URL to scan for leaked "
            "secrets (e.g. 'https://github.com/org/repo' or "
            "'github.com/org'). TruffleHog detects API keys, passwords, "
            "tokens, and credentials in commit history."
        ),
    )
    only_verified: bool = Field(
        default=True,
        description=(
            "If true, only report secrets that TruffleHog verified as "
            "currently active (e.g. valid API key). Default true for "
            "higher signal-to-noise ratio."
        ),
    )


@tool(args_schema=TrufflehogInput)
def trufflehog_scan(target: str, only_verified: bool = True) -> dict[str, Any]:
    """Scan a Git repository or GitHub org for leaked secrets.

    Detects API keys, passwords, tokens, and other credentials in
    commit history.  Verified mode confirms secrets are still active.
    """
    require_binary("trufflehog", "trufflehog_scan")

    target = target.strip()
    if not target:
        raise ToolException("trufflehog_scan: target must not be empty")

    # Normalise to full URL when a bare host path is given.
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    _GIT_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")

    # Determine scan mode from target format.
    parsed = urlparse(target if "://" in target else f"https://{target}")
    hostname = (parsed.hostname or "").lower()

    if hostname == "github.com":
        parts = parsed.path.lstrip("/").split("/")
        if len(parts) >= 2:
            # GitHub repository: use git scan against the repository URL.
            scan_type = "git"
            scan_target = target
        else:
            # GitHub organization scan.
            scan_type = "github"
            org = parts[0] if parts and parts[0] else ""
            if not org:
                raise ToolException("trufflehog_scan: github organization name is missing in target")
            scan_target = f"--org={org}"
    elif hostname in _GIT_HOSTS or parsed.path.rstrip("/").endswith(".git"):
        scan_type = "git"
        scan_target = target
    else:
        raise ToolException(
            "trufflehog_scan: target must be a Git repository URL "
            "(e.g. 'https://github.com/org/repo') or a GitHub org "
            "(e.g. 'github.com/org'). Plain domains are not supported."
        )

    cmd = ["trufflehog", scan_type, scan_target]

    cmd.extend(["--json", "--no-update"])

    if only_verified:
        cmd.append("--only-verified")

    try:
        code, out, stderr = run_command(cmd, timeout=get_tool_timeout("trufflehog_scan", _TIMEOUT))
    except Exception as exc:
        raise ToolException(f"trufflehog_scan: {exc}") from exc

    findings: list[dict[str, Any]] = []
    for raw in parse_jsonl(out):
        finding: dict[str, Any] = {
            "detector": raw.get(
                "DetectorType", raw.get("SourceMetadata", {}).get("DetectorType", "")
            ),
            "verified": raw.get("Verified", False),
            "raw": (raw.get("Raw", "") or "")[:100],
            "source": "",
            "file": "",
            "commit": "",
        }
        source_meta = raw.get("SourceMetadata", {})
        if isinstance(source_meta, dict):
            data = source_meta.get("Data", {})
            if isinstance(data, dict):
                git_data = data.get("Git", data.get("Github", {}))
                if isinstance(git_data, dict):
                    finding["source"] = git_data.get("repository", git_data.get("Repository", ""))
                    finding["file"] = git_data.get("file", git_data.get("File", ""))
                    finding["commit"] = git_data.get("commit", git_data.get("Commit", ""))
        findings.append(finding)

    if not findings:
        if code and not out.strip():
            raise ToolException(f"trufflehog_scan: {stderr.strip() or 'scan failed'}")
        return format_tool_output(
            "trufflehog_scan",
            target,
            "ok",
            data={
                "total": 0,
                "findings": [],
                "message": "no leaked secrets found",
            },
        )

    return format_tool_output(
        "trufflehog_scan",
        target,
        "ok",
        data={
            "total": len(findings),
            "verified": sum(1 for f in findings if f.get("verified")),
            "findings": findings,
        },
    )


trufflehog_scan.handle_tool_error = True  # type: ignore[attr-defined]
