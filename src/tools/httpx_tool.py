import json
import shutil
import subprocess
from typing import Any
from urllib.parse import urlparse


from langchain.tools import tool

from tools.utils import run_command, extract_host, format_tool_output


def _normalize_target(domain: str) -> tuple[str | None, str | None]:
    parsed = urlparse(domain)
    # Use shared logic for host extraction
    host = extract_host(domain)
    # Preserve scheme if present for HTTP tools
    url = domain if parsed.scheme else None
    return host, url


@tool
def httpx_scan(domain: str) -> dict[str, Any]:
    """Active HTTP probing with httpx (JSON output)."""
    if not shutil.which("httpx"):
        return format_tool_output(
            "httpx_scan",
            domain,
            "error",
            error="httpx não encontrado no PATH",
        )

    host, url = _normalize_target(domain)
    target = url or host
    if not target:
        return format_tool_output(
            "httpx_scan",
            domain,
            "error",
            error="alvo inválido",
        )

    # Detect se o httpx é o da ProjectDiscovery; caso contrário, explique
    try:
        proc = subprocess.run(
            ["httpx", "-version"], capture_output=True, text=True, timeout=5
        )
        if proc.returncode != 0 or "projectdiscovery" not in proc.stdout.lower():
            return format_tool_output(
                "httpx_scan",
                domain,
                "error",
                error="httpx encontrado não é o da ProjectDiscovery (instale https://github.com/projectdiscovery/httpx)",
            )
    except Exception:
        pass

    cmd = [
        "httpx",
        target,
        "-json",
        "-silent",
    ]
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
            error=err or "sem resultados",
        )

    return format_tool_output(
        "httpx_scan",
        domain,
        "ok",
        data={"results": results},
    )
