"""WPScan — WordPress vulnerability scanner.

Scans WordPress installations for vulnerable plugins, themes, user
enumeration, and known WordPress core vulnerabilities via the WPVulnDB API.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    format_tool_output,
    get_tool_timeout,
    guard_target,
    require_binary,
    require_env,
    run_command,
)

_TIMEOUT = 300


class WPScanInput(BaseModel):
    """Input for WPScan WordPress vulnerability scanner."""

    target: str = Field(
        description=(
            "URL of the WordPress site to scan "
            "(e.g. 'https://example.com'). WPScan detects vulnerable "
            "plugins, themes, user enumeration, config backups, and "
            "known WordPress core vulnerabilities."
        ),
    )
    enumerate: str = Field(
        default="vp,vt,u",
        description=(
            "Comma-separated enumeration options: 'vp' (vulnerable plugins), "
            "'vt' (vulnerable themes), 'u' (users), 'ap' (all plugins), "
            "'at' (all themes). Default 'vp,vt,u'."
        ),
    )


@tool(args_schema=WPScanInput)
def wpscan_scan(target: str, enumerate: str = "vp,vt,u") -> dict[str, Any]:
    """Scan a WordPress site for vulnerabilities.

    Detects vulnerable plugins, themes, user enumeration, config backups,
    XML-RPC exposure, and known WordPress core vulnerabilities.
    Requires WPSCAN_API_TOKEN for vulnerability database lookups.
    """
    require_binary("wpscan", "wpscan_scan")
    api_token = require_env("WPSCAN_API_TOKEN", "wpscan_scan")

    target = guard_target(target, "wpscan_scan", TargetType.HOST_OR_URL)

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    cmd = [
        "wpscan",
        "--url",
        target,
        "--format",
        "json",
        "--no-banner",
        "--random-user-agent",
        "--api-token",
        api_token,
    ]

    if enumerate:
        cmd.extend(["--enumerate", enumerate])

    try:
        code, out, stderr = run_command(cmd, timeout=get_tool_timeout("wpscan_scan", _TIMEOUT))
    except Exception as exc:
        raise ToolException(f"wpscan_scan: {exc}") from exc

    stripped = out.strip()
    if not stripped:
        if code:
            raise ToolException(f"wpscan_scan: {stderr.strip() or 'scan failed'}")
        return format_tool_output(
            "wpscan_scan",
            target,
            "ok",
            data={"message": "no output from WPScan"},
        )

    try:
        data = json.loads(stripped)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ToolException(f"wpscan_scan: failed to parse output: {exc}") from exc

    # Extract WordPress version info.
    wp_version_info: dict[str, Any] = {}
    wp_version = data.get("version")
    if isinstance(wp_version, dict):
        wp_version_info = {
            "number": wp_version.get("number", ""),
            "status": wp_version.get("status", ""),
            "interesting_entries": wp_version.get("interesting_entries", []),
            "vulnerabilities": _extract_vulns(wp_version.get("vulnerabilities", [])),
        }

    # Extract plugins.
    plugins: list[dict[str, Any]] = []
    for name, info in (data.get("plugins") or {}).items():
        if not isinstance(info, dict):
            continue
        plugin: dict[str, Any] = {
            "name": name,
            "version": info.get("version", {}).get("number", "")
            if isinstance(info.get("version"), dict)
            else "",
            "outdated": info.get("outdated", False),
            "vulnerabilities": _extract_vulns(info.get("vulnerabilities", [])),
        }
        plugins.append(plugin)

    # Extract themes.
    themes: list[dict[str, Any]] = []
    for name, info in (data.get("themes") or {}).items():
        if not isinstance(info, dict):
            continue
        theme: dict[str, Any] = {
            "name": name,
            "version": info.get("version", {}).get("number", "")
            if isinstance(info.get("version"), dict)
            else "",
            "outdated": info.get("outdated", False),
            "vulnerabilities": _extract_vulns(info.get("vulnerabilities", [])),
        }
        themes.append(theme)

    # Extract users.
    users: list[str] = []
    for _uid, info in (data.get("users") or {}).items():
        if isinstance(info, dict):
            users.append(info.get("username", str(_uid)))

    total_vulns = (
        len(wp_version_info.get("vulnerabilities", []))
        + sum(len(p.get("vulnerabilities", [])) for p in plugins)
        + sum(len(t.get("vulnerabilities", [])) for t in themes)
    )

    return format_tool_output(
        "wpscan_scan",
        target,
        "ok",
        data={
            "wordpress_version": wp_version_info,
            "plugins": plugins,
            "themes": themes,
            "users": users,
            "total_vulnerabilities": total_vulns,
        },
    )


def _extract_vulns(vulns: list[Any]) -> list[dict[str, str]]:
    """Extract vulnerability summaries from WPScan vuln entries."""
    results: list[dict[str, str]] = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        results.append(
            {
                "title": v.get("title", ""),
                "type": v.get("vuln_type", ""),
                "cvss": str(v.get("cvss", {}).get("score", ""))
                if isinstance(v.get("cvss"), dict)
                else "",
                "references": str(v.get("references", {}).get("url", [])[:3]),
                "fixed_in": v.get("fixed_in", ""),
            }
        )
    return results


wpscan_scan.handle_tool_error = True  # type: ignore[attr-defined]
