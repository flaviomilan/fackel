"""Tool execution helpers — subprocess runner, output envelope, and guards.

Functions here are infrastructure-level: subprocess execution, output
envelope formatting, binary / env-var precondition checks, and JSONL
parsing.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 180


def run_command(cmd: list[str], timeout: int = DEFAULT_TIMEOUT) -> tuple[int, str, str]:
    """Execute a subprocess command and return (returncode, stdout, stderr)."""
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def format_tool_output(
    tool: str,
    target: str,
    status: str,
    data: dict | list | None = None,
    error: str | None = None,
) -> dict:
    """Standardize tool output format."""
    return {
        "tool": tool,
        "target": target,
        "status": status,
        "data": data,
        "error": error,
    }


# ── DRY helpers for subprocess-based tools ─────────────────────────────


def require_binary(binary: str, tool_name: str, target: str) -> dict | None:
    """Return an error dict if *binary* is not on PATH, else ``None``."""
    if shutil.which(binary):
        return None
    return format_tool_output(
        tool_name, target, "error",
        error=f"{binary} not found in PATH",
    )


def require_env(key: str, tool_name: str, target: str) -> tuple[str | None, dict | None]:
    """Return ``(value, None)`` if env var is set, or ``(None, error_dict)``."""
    value = os.getenv(key, "").strip()
    if value:
        return value, None
    return None, format_tool_output(
        tool_name, target, "error",
        error=f"{key} environment variable not configured",
    )


def parse_jsonl(output: str) -> list[dict]:
    """Parse newline-delimited JSON, skipping malformed lines."""
    results: list[dict] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                results.append(data)
        except (json.JSONDecodeError, ValueError):
            continue
    return results
