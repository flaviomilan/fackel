"""Tool execution infrastructure — shared plumbing for tool wrappers.

Modules
-------
ddgs
    Lazy import for the DuckDuckGo search SDK.
execution
    Subprocess runner, output envelope, binary/env guards, JSONL parsing.
sanitizers
    Parameter validation for CLI arguments (ports, severity, tags).
validators
    Target input validation and normalisation (domain, IP, URL, host),
    plus pure IP / domain helpers previously in ``fackel.utils``.
"""

from fackel.tooling.ddgs import DDGS
from fackel.tooling.execution import (
    format_tool_output,
    parse_jsonl,
    require_binary,
    require_env,
    run_command,
)
from fackel.tooling.ip_classifier import IpClass, classify_ip
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
    "IpClass",
    "TargetType",
    "classify_ip",
    "format_tool_output",
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
