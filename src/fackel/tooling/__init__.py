"""Tool execution infrastructure — shared plumbing for tool wrappers.

Modules
-------
circuit_breaker
    Per-service circuit breaker for external HTTP APIs.
ddgs
    Lazy import for the DuckDuckGo search SDK.
execution
    Subprocess runner, output envelope, binary/env guards, JSONL parsing.
http_client
    Shared HTTP session with connection pooling and automatic retries.
output_sanitizer
    Prompt injection defence and size-limit enforcement.
sanitizers
    Parameter validation for CLI arguments (ports, severity, tags).
validators
    Target input validation and normalisation (domain, IP, URL, host),
    plus pure IP / domain helpers.
"""

from fackel.tooling.ddgs import DDGS  # type: ignore[attr-defined]
from fackel.tooling.execution import (
    format_tool_output,
    get_tool_timeout,
    parse_jsonl,
    require_binary,
    require_env,
    run_command,
)
from fackel.tooling.sanitizers import (
    sanitize_ports,
    sanitize_severity,
    sanitize_tags,
    sanitize_top_ports,
)
from fackel.tooling.validators import (
    TargetType,
    guard_target,
    is_reverse_ptr_subdomain,
    is_valid_domain,
    is_valid_ip,
    sanitize_target,
)

__all__ = [
    "DDGS",
    "TargetType",
    "format_tool_output",
    "get_tool_timeout",
    "guard_target",
    "is_reverse_ptr_subdomain",
    "is_valid_domain",
    "is_valid_ip",
    "parse_jsonl",
    "require_binary",
    "require_env",
    "run_command",
    "sanitize_ports",
    "sanitize_severity",
    "sanitize_tags",
    "sanitize_target",
    "sanitize_top_ports",
]
