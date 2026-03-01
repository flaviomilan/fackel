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

from fackel.tooling.circuit_breaker import circuit_breaker
from fackel.tooling.circuit_breaker import reset_all as reset_circuits
from fackel.tooling.ddgs import DDGS  # type: ignore[attr-defined]
from fackel.tooling.execution import (
    format_tool_output,
    get_tool_timeout,
    parse_jsonl,
    redact_secrets,
    require_binary,
    require_env,
    run_command,
)
from fackel.tooling.http_client import get_session
from fackel.tooling.ip_classifier import IpClass, classify_ip
from fackel.tooling.output_sanitizer import sanitize_tool_output
from fackel.tooling.sanitizers import (
    sanitize_ports,
    sanitize_severity,
    sanitize_tags,
    sanitize_top_ports,
)
from fackel.tooling.validators import (
    TargetType,
    guard_dns_rebinding,
    guard_target,
    is_private_ip,
    is_reverse_ptr_subdomain,
    is_valid_domain,
    is_valid_ip,
    resolve_host,
    sanitize_target,
)

__all__ = [
    "DDGS",
    "IpClass",
    "TargetType",
    "circuit_breaker",
    "classify_ip",
    "format_tool_output",
    "get_session",
    "get_tool_timeout",
    "guard_dns_rebinding",
    "guard_target",
    "is_private_ip",
    "is_reverse_ptr_subdomain",
    "is_valid_domain",
    "is_valid_ip",
    "parse_jsonl",
    "redact_secrets",
    "require_binary",
    "require_env",
    "reset_circuits",
    "resolve_host",
    "run_command",
    "sanitize_ports",
    "sanitize_severity",
    "sanitize_tags",
    "sanitize_target",
    "sanitize_tool_output",
    "sanitize_top_ports",
]
