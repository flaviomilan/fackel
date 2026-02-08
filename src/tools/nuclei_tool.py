import json
import shutil
from typing import Any

from langchain.tools import tool


from tools.utils import ensure_target, run_command, format_tool_output


@tool
def nuclei_scan(target: str) -> dict[str, Any]:
    """Run nuclei templates against a target (JSONL output)."""
    if not shutil.which("nuclei"):
        return format_tool_output(
            "nuclei_scan",
            target,
            "error",
            error="nuclei não encontrado no PATH",
        )

    norm = ensure_target(target)
    if not norm:
        return format_tool_output(
            "nuclei_scan",
            target,
            "error",
            error="alvo inválido",
        )

    cmd = [
        "nuclei",
        "-u",
        norm,
        "-jsonl",
        "-silent",
    ]
    try:
        code, out, err = run_command(cmd, timeout=3000)
    except Exception as exc:
        return format_tool_output(
            "nuclei_scan",
            target,
            "error",
            error=str(exc),
        )


    findings: list[dict[str, Any]] = []
    for line in out.splitlines():
        try:
            data = json.loads(line)
            # Create a normalized finding object but preserve all original data
            finding = data.copy()
            
            # Ensure standard keys used by normalizers/reports are present
            finding.update({
                "template_id": data.get("template-id"),
                "name": data.get("info", {}).get("name"),
                "severity": data.get("info", {}).get("severity"),
                "matched": data.get("matched-at"),
                "type": data.get("type"),
                "host": data.get("host"),
                "ip": data.get("ip"),
                "port": data.get("port"),
                "timestamp": data.get("timestamp"),
                "extracted_results": data.get("extracted-results"),
                "curl_command": data.get("curl-command"),
                "matcher_name": data.get("matcher-name"),
            })
            
            findings.append(finding)
        except Exception:
            continue

    if not findings:
        return format_tool_output(
            "nuclei_scan",
            target,
            "error" if code else "ok",
            error=err or "sem resultados",
        )

    return format_tool_output(
        "nuclei_scan",
        target,
        "ok",
        data={"findings": findings},
    )
