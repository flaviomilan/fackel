"""ffuf — Fast web fuzzer for directory/file discovery and API endpoint bruting.

Wraps ffuf to discover hidden directories, files, API endpoints, and
virtual hosts via response-based filtering.  Supports custom wordlists,
HTTP methods, and advanced matching/filtering.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    format_tool_output,
    get_tool_timeout,
    guard_target,
    parse_jsonl,
    require_binary,
    run_command,
)
from tools.scanning._wordlists import find_wordlist as _find_wordlist

_TIMEOUT = 300


class FfufInput(BaseModel):
    """Input for ffuf web fuzzer."""

    target: str = Field(
        description=(
            "Base URL with FUZZ keyword placeholder for the fuzzing point. "
            "Example: 'https://example.com/FUZZ' to fuzz directories, or "
            "'https://api.example.com/v1/FUZZ' for API endpoints. "
            "If FUZZ is not present, it will be appended as /FUZZ."
        ),
    )
    wordlist: str = Field(
        default="",
        description=(
            "Path to a custom wordlist file. If empty, the tool looks for "
            "SecLists/common.txt or dirb/common.txt in standard locations. "
            "Each line in the wordlist is tested as a replacement for FUZZ."
        ),
    )
    method: str = Field(
        default="GET",
        description=(
            "HTTP method to use: GET, POST, PUT, DELETE, PATCH, HEAD. "
            "Default is GET."
        ),
    )
    match_codes: str = Field(
        default="200,204,301,302,307,401,403,405",
        description=(
            "Comma-separated HTTP status codes to include in results. "
            "Default matches common interesting codes including redirects "
            "and authentication-required responses."
        ),
    )
    filter_codes: str = Field(
        default="",
        description=(
            "Comma-separated HTTP status codes to exclude from results. "
            "Opposite of match_codes. Example: '404,500' to hide not-found "
            "and error responses. Overrides match_codes for listed codes."
        ),
    )
    filter_size: str = Field(
        default="",
        description=(
            "Comma-separated response sizes (in bytes) to exclude. "
            "Useful to filter repetitive error pages with fixed size. "
            "Example: '0,1234' to exclude empty and known-size responses."
        ),
    )
    filter_words: str = Field(
        default="",
        description=(
            "Comma-separated word counts to exclude from results. "
            "Useful when the target returns a custom error page with a "
            "consistent word count. Example: '42' to exclude 42-word responses."
        ),
    )
    extensions: str = Field(
        default="",
        description=(
            "Comma-separated file extensions to append to each word. "
            "Example: 'php,html,js,json,txt'. Leave empty for directory-only."
        ),
    )
    headers: list[str] = Field(
        default_factory=list,
        description=(
            "Custom HTTP headers as 'Name: Value' strings. "
            "Example: ['Authorization: Bearer eyJ...', 'X-Custom: value']. "
            "Useful for testing authenticated endpoints or API routes."
        ),
    )
    recursion: bool = Field(
        default=False,
        description=(
            "Enable recursive discovery — when a directory is found, "
            "ffuf automatically fuzzes inside it. Can be slow on large "
            "targets. Default: False."
        ),
    )
    recursion_depth: int = Field(
        default=2,
        description=(
            "Maximum recursion depth when recursion is enabled (1-5). "
            "Default: 2. Only used when recursion=True."
        ),
    )
    rate: int = Field(
        default=0,
        description=(
            "Maximum requests per second (0 = unlimited). "
            "Use to avoid overwhelming the target or triggering WAF. "
            "Example: 100 for moderate rate limiting."
        ),
    )
    threads: int = Field(
        default=20,
        description="Number of concurrent threads (default: 20, max: 50).",
    )


@tool(args_schema=FfufInput)
def ffuf_scan(
    target: str,
    wordlist: str = "",
    method: str = "GET",
    match_codes: str = "200,204,301,302,307,401,403,405",
    filter_codes: str = "",
    filter_size: str = "",
    filter_words: str = "",
    extensions: str = "",
    headers: list[str] | None = None,
    recursion: bool = False,
    recursion_depth: int = 2,
    rate: int = 0,
    threads: int = 20,
) -> dict[str, Any]:
    """Fuzz web directories, files, and API endpoints using ffuf.

    Discovers hidden resources by brute-forcing URL paths with a wordlist.
    Supports custom HTTP methods, status code filtering, response filtering
    by size/words, custom headers for auth, recursive directory discovery,
    rate limiting, and configurable concurrency.  Returns discovered paths
    with status codes, content lengths, and response metadata.
    """
    require_binary("ffuf", "ffuf_scan")

    target = guard_target(target, "ffuf_scan", TargetType.HOST_OR_URL)

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    # Append /FUZZ if not present.
    if "FUZZ" not in target:
        target = target.rstrip("/") + "/FUZZ"

    wl = _find_wordlist(wordlist)
    if not wl:
        raise ToolException(
            "ffuf_scan: no wordlist found. Provide a custom wordlist path "
            "or install SecLists: apt install seclists"
        )

    # Clamp threads.
    threads = max(1, min(threads, 50))

    # Validate method.
    method = method.upper()
    valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
    if method not in valid_methods:
        raise ToolException(f"ffuf_scan: invalid method '{method}'")

    cmd = [
        "ffuf",
        "-u", target,
        "-w", wl,
        "-X", method,
        "-mc", match_codes,
        "-t", str(threads),
        "-of", "json",
        "-o", "/dev/stdout",
        "-s",  # silent mode
    ]

    if extensions:
        cmd.extend(["-e", extensions])

    if filter_codes:
        cmd.extend(["-fc", filter_codes])

    if filter_size:
        cmd.extend(["-fs", filter_size])

    if filter_words:
        cmd.extend(["-fw", filter_words])

    if headers:
        for h in headers:
            if ":" in h:
                cmd.extend(["-H", h])

    if recursion:
        cmd.append("-recursion")
        depth = max(1, min(recursion_depth, 5))
        cmd.extend(["-recursion-depth", str(depth)])

    if rate > 0:
        cmd.extend(["-rate", str(rate)])

    try:
        code, out, stderr = run_command(
            cmd, timeout=get_tool_timeout("ffuf_scan", _TIMEOUT)
        )
    except Exception as exc:
        raise ToolException(f"ffuf_scan: {exc}") from exc

    findings: list[dict[str, Any]] = []

    # ffuf -of json writes a single JSON object to stdout.
    _parse_ffuf_json(out, findings)

    if not findings:
        msg = (
            "no interesting paths discovered"
            if code == 0
            else (stderr.strip()[:500] or "fuzzing produced no output")
        )
        return format_tool_output(
            "ffuf_scan", target, "ok",
            data={"findings": [], "message": msg},
        )

    return format_tool_output(
        "ffuf_scan", target, "ok",
        data={"total": len(findings), "findings": findings},
    )


def _parse_ffuf_json(output: str, findings: list[dict[str, Any]]) -> None:
    """Parse ffuf JSON output into normalized findings."""
    import json

    output = output.strip()
    if not output:
        return

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        # Try JSONL as fallback.
        for item in parse_jsonl(output):
            _add_ffuf_result(item, findings)
        return

    results = data.get("results", [])
    if isinstance(results, list):
        for result in results:
            _add_ffuf_result(result, findings)


def _add_ffuf_result(result: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    """Normalise a single ffuf result dict into a finding."""
    if not isinstance(result, dict):
        return
    findings.append({
        "url": result.get("url", ""),
        "input": result.get("input", {}).get("FUZZ", ""),
        "status": result.get("status", 0),
        "length": result.get("length", 0),
        "words": result.get("words", 0),
        "lines": result.get("lines", 0),
        "content_type": result.get("content-type", ""),
        "redirect_location": result.get("redirectlocation", ""),
    })


ffuf_scan.handle_tool_error = True  # type: ignore[attr-defined]
