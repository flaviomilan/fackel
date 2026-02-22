import json
import shutil
from typing import Any

from langchain_core.tools import tool


from .utils import run_command, extract_host, format_tool_output


@tool
def naabu_scan(
    host: str,
    ports: str = "",
    top_ports: str = "",
    rate: int = 0,
    skip_cdn: bool = False,
) -> dict[str, Any]:
    """Fast SYN-based TCP port discovery using naabu.

    Use for **breadth-first** port enumeration — fast sweep to find open ports
    before deeper nmap analysis.

    Args:
        host: IP address or domain to scan.
        ports: Comma-separated ports or ranges to scan (e.g. "80,443,8000-9000").
               Leave empty to scan naabu's default port list.
        top_ports: Scan only the N most common ports. Use "100" for a quick
                   sweep or "1000" for thorough coverage. Ignored if `ports` is set.
        rate: Packets per second (0 = naabu default ~1000). Lower for stealth,
              higher (e.g. 5000) for speed on reliable networks.
        skip_cdn: Skip ports identified as belonging to CDN (Cloudflare, etc.).
                  Useful when you know the target is behind a CDN proxy.

    Returns:
        List of open ports with IP, port number, protocol, and timestamp.
    """
    if not shutil.which("naabu"):
        return format_tool_output(
            "naabu_scan",
            host,
            "error",
            error="naabu not found in PATH",
        )

    target = extract_host(host)
    if not target:
        return format_tool_output(
            "naabu_scan",
            host,
            "error",
            error="invalid target",
        )

    cmd = ["naabu", "-host", target, "-json"]

    if ports.strip():
        cmd.extend(["-p", ports.strip()])
    elif top_ports.strip():
        cmd.extend(["-top-ports", top_ports.strip()])

    if rate > 0:
        cmd.extend(["-rate", str(rate)])

    if skip_cdn:
        cmd.append("-cdn")

    try:
        code, out, err = run_command(cmd)
    except Exception as exc:
        return format_tool_output(
            "naabu_scan",
            host,
            "error",
            error=str(exc),
        )


    results: list[dict[str, Any]] = []
    for line in out.splitlines():
        try:
            data = json.loads(line)
            result = data.copy()
            result.update({
                "ip": data.get("ip"),
                "port": data.get("port"),
                "proto": data.get("protocol", "tcp"),
            })
            results.append(result)
        except Exception:
            continue

    if not results:
        return format_tool_output(
            "naabu_scan",
            host,
            "error" if code else "ok",
            error=err or "no open ports found",
        )

    return format_tool_output(
        "naabu_scan",
        host,
        "ok",
        data={"results": results},
    )
