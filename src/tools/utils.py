import subprocess
from urllib.parse import urlparse

from fackel.utils.target import extract_host  # noqa: F401 — re-exported

DEFAULT_TIMEOUT = 180


def run_command(cmd: list[str], timeout: int = DEFAULT_TIMEOUT) -> tuple[int, str, str]:
    """Execute a subprocess command and return (returncode, stdout, stderr)."""
    # capture_output=True implies stdout=PIPE and stderr=PIPE
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def ensure_target(target: str) -> str | None:
    """Ensure target is valid, preserving scheme if present (e.g. for web tools)."""
    if not target:
        return None

    parsed = urlparse(target)
    if parsed.scheme:
        return target
    return parsed.netloc or parsed.path or target or None


def format_tool_output(
    tool: str,
    target: str,
    status: str,
    data: any = None,
    error: str = None,
    metadata: dict = None,
) -> dict:
    """Standardize tool output format."""
    return {
        "tool": tool,
        "target": target,
        "status": status,
        "data": data,
        "error": error,
        "metadata": metadata or {},
    }
