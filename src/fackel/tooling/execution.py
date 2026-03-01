"""Tool execution helpers — subprocess runner, output envelope, and guards.

Functions here are infrastructure-level: subprocess execution, output
envelope formatting, binary / env-var precondition checks, configurable
per-tool timeouts, and JSONL parsing.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from typing import Any

from langchain_core.tools import ToolException

from fackel.settings import get_settings

logger = logging.getLogger(__name__)


_SECRET_ENV_PATTERNS: tuple[str, ...] = (
    "API_KEY",
    "API_SECRET",
    "API_TOKEN",
    "OPENAI_API",
    "LANGCHAIN_API",
    "FOFA_KEY",
    "WPSCAN_API",
    "SHODAN_API",
    "VIRUSTOTAL_API",
    "CENSYS_API",
    "SECURITYTRAILS_API",
    "OTX_API",
    "HIBP_API",
    "EMAILREP_API",
)

_secret_values: list[str] | None = None


def _get_secret_values() -> list[str]:
    """Collect non-empty values of secret-like env vars (cached)."""
    global _secret_values
    if _secret_values is not None:
        return _secret_values
    values: list[str] = []
    for key, val in os.environ.items():
        if not val or len(val) < 8:
            continue
        if any(pat in key.upper() for pat in _SECRET_ENV_PATTERNS):
            values.append(val)
    # Sort longest-first so longer secrets are matched before substrings.
    values.sort(key=len, reverse=True)
    _secret_values = values
    return _secret_values


def _reset_secret_cache() -> None:
    """Clear the cached secret values so the next call re-scans the env.

    Intended for **tests only** — production code should never call this.
    """
    global _secret_values
    _secret_values = None


def redact_secrets(text: str) -> str:
    """Replace known secret values in *text* with ``[REDACTED]``.

    Scans the environment for variables matching :data:`_SECRET_ENV_PATTERNS`
    and replaces their values in the output.  This prevents accidental
    leakage of API keys in tool error messages passed to the LLM.
    """
    for secret in _get_secret_values():
        text = text.replace(secret, "[REDACTED]")
    return text


def _default_timeout() -> int:
    """Return the default subprocess timeout from settings."""
    return get_settings().subprocess_timeout


def _max_output_bytes() -> int:
    """Return the max output bytes from settings."""
    return get_settings().subprocess_max_output


def _truncate(text: str, max_bytes: int) -> str:
    """Truncate *text* to at most *max_bytes* UTF-8 bytes."""
    encoded = text.encode()
    if len(encoded) <= max_bytes:
        return text
    # Decode safely to avoid splitting a multi-byte char
    return encoded[:max_bytes].decode(errors="ignore") + "\n[OUTPUT TRUNCATED]"


def run_command(
    cmd: list[str],
    timeout: int | None = None,
    max_output: int | None = None,
) -> tuple[int, str, str]:
    """Execute a subprocess command and return (returncode, stdout, stderr).

    Parameters
    ----------
    timeout:
        Seconds before killing the subprocess.  Defaults to
        ``FACKEL_SUBPROCESS_TIMEOUT``.
    max_output:
        Maximum bytes kept per stdout/stderr stream.  Prevents a
        single tool from consuming unbounded memory.  Set to ``0``
        to disable truncation.  Defaults to ``FACKEL_SUBPROCESS_MAX_OUTPUT``.
    """
    if timeout is None:
        timeout = _default_timeout()
    if max_output is None:
        max_output = _max_output_bytes()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)  # noqa: S603
    stdout = _truncate(proc.stdout, max_output) if max_output else proc.stdout
    stderr = _truncate(proc.stderr, max_output) if max_output else proc.stderr
    # Redact secrets from both streams to prevent leakage to the LLM.
    stdout = redact_secrets(stdout)
    stderr = redact_secrets(stderr)
    return proc.returncode, stdout, stderr


def format_tool_output(
    tool: str,
    target: str,
    status: str,
    data: dict[str, Any] | list[Any] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """Standardize tool output format."""
    return {
        "tool": tool,
        "target": target,
        "status": status,
        "data": data,
        "error": error,
    }


def require_binary(binary: str, tool_name: str) -> None:
    """Raise ``ToolException`` if *binary* is not on ``PATH``.

    Raises
    ------
    ToolException
        When the required binary cannot be found.
    """
    if shutil.which(binary):
        return
    raise ToolException(f"{tool_name}: {binary} not found in PATH")


def require_env(key: str, tool_name: str) -> str:
    """Return the value of env-var *key*, or raise ``ToolException``.

    Raises
    ------
    ToolException
        When the environment variable is empty or unset.
    """
    value = os.getenv(key, "").strip()
    if value:
        return value
    raise ToolException(f"{tool_name}: {key} environment variable not configured")


def get_tool_timeout(tool_name: str, default: int) -> int:
    """Return the timeout for *tool_name* from env or *default*.

    Reads ``FACKEL_TIMEOUT_{TOOL_NAME}`` (upper-cased).  This lets
    operators override per-tool timeouts at deploy time without code
    changes.

    Examples
    --------
    >>> os.environ["FACKEL_TIMEOUT_CRTSH"] = "60"
    >>> get_tool_timeout("crtsh", 45)
    60
    """
    env_var = f"FACKEL_TIMEOUT_{tool_name.upper()}"
    raw = os.getenv(env_var, "").strip()
    if raw:
        try:
            return int(raw)
        except ValueError:
            logger.warning(
                "%s=%r is not a valid integer — using default %d",
                env_var,
                raw,
                default,
            )
    return default


def parse_jsonl(output: str) -> list[dict[str, Any]]:
    """Parse newline-delimited JSON, skipping malformed lines."""
    results: list[dict[str, Any]] = []
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
