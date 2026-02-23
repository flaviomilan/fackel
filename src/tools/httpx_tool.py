import json
import shutil
import subprocess
from typing import Any
from urllib.parse import urlparse


from langchain_core.tools import tool
from pydantic import BaseModel, Field

from .utils import run_command, extract_host, format_tool_output


def _normalize_target(domain: str) -> tuple[str | None, str | None]:
    parsed = urlparse(domain)
    # Use shared logic for host extraction
    host = extract_host(domain)
    # Preserve scheme if present for HTTP tools
    url = domain if parsed.scheme else None
    return host, url


class HttpxInput(BaseModel):
    """Input for ProjectDiscovery httpx HTTP prober."""

    domain: str = Field(
        description="IP address, domain, or full URL to probe for HTTP services.",
    )
    ports: str = Field(
        default="",
        description=(
            "Comma-separated ports to probe (e.g. '80,443,8080,8443'). "
            "Feed ports from naabu/nmap for thorough coverage. "
            "Leave empty for httpx defaults (80, 443)."
        ),
    )
    tech_detect: bool = Field(
        default=True,
        description="Enable technology fingerprinting (web frameworks, CMSs, etc.).",
    )
    follow_redirects: bool = Field(
        default=True,
        description="Follow HTTP redirects to the final destination.",
    )
    status_code: bool = Field(
        default=True,
        description="Include HTTP status codes in output.",
    )
    title: bool = Field(
        default=True,
        description="Include HTML page titles in output.",
    )


@tool(args_schema=HttpxInput)
def httpx_scan(
    domain: str,
    ports: str = "",
    tech_detect: bool = True,
    follow_redirects: bool = True,
    status_code: bool = True,
    title: bool = True,
) -> dict[str, Any]:
    """HTTP probing and web surface mapping using ProjectDiscovery's httpx.

    Discovers which ports serve HTTP/HTTPS, what technologies run behind them,
    CDN presence, TLS version, and redirect behavior.  Use before WAF detection
    and Nuclei targeting.
    """
    if not shutil.which("httpx"):
        return format_tool_output(
            "httpx_scan",
            domain,
            "error",
            error="httpx not found in PATH",
        )

    host, url = _normalize_target(domain)
    target = url or host
    if not target:
        return format_tool_output(
            "httpx_scan",
            domain,
            "error",
            error="invalid target",
        )

    # Detect whether httpx is the ProjectDiscovery version
    try:
        proc = subprocess.run(
            ["httpx", "-version"], capture_output=True, text=True, timeout=5
        )
        if proc.returncode != 0 or "projectdiscovery" not in proc.stdout.lower():
            return format_tool_output(
                "httpx_scan",
                domain,
                "error",
                error="httpx found is not ProjectDiscovery's (install https://github.com/projectdiscovery/httpx)",
            )
    except Exception:
        pass

    cmd = ["httpx", target, "-json", "-silent"]

    if ports.strip():
        cmd.extend(["-p", ports.strip()])
    if tech_detect:
        cmd.append("-td")
    if follow_redirects:
        cmd.append("-follow-redirects")
    if status_code:
        cmd.append("-sc")
    if title:
        cmd.append("-title")

    try:
        code, out, err = run_command(cmd)
    except Exception as exc:
        return format_tool_output(
            "httpx_scan",
            domain,
            "error",
            error=str(exc),
        )


    results: list[dict[str, Any]] = []
    for line in out.splitlines():
        try:
            data = json.loads(line)
            # Create a normalized result object but preserve all original data
            result = data.copy()
            
            # Ensure standard keys used by normalizers/reports are present
            result.update({
                "url": data.get("url"),
                "status": data.get("status_code"),
                "title": data.get("title"),
                "ip": data.get("ip"),
                "port": data.get("port"),
                "tech": data.get("tech"),
                "tls_version": data.get("tls_version"),
                "webserver": data.get("webserver"),
                "cdn": data.get("cdn"),
                "response_time": data.get("time"),
            })
            results.append(result)
        except Exception:
            continue

    if not results:
        return format_tool_output(
            "httpx_scan",
            domain,
            "error" if code else "ok",
            error=err or "no HTTP services found",
        )

    return format_tool_output(
        "httpx_scan",
        domain,
        "ok",
        data={"results": results},
    )
