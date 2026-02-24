"""Parameter sanitizers for subprocess-based tools.

Validates and normalises LLM-provided values (ports, severity, tags)
that are passed to CLI binaries like nmap, naabu, nuclei, and testssl.sh.

These sit alongside :mod:`fackel.tooling.validators` (which handles *target*
parameters) and are called *before* values reach subprocess arguments.
"""

from __future__ import annotations

import re

# ── Ports ──────────────────────────────────────────────────────────────

# Valid forms: "80", "80,443", "80-443", "80,443,8000-9000"
_PORTS_RE = re.compile(r"^\d+(-\d+)?(,\d+(-\d+)?)*$")


def sanitize_ports(value: str) -> tuple[str, str | None]:
    """Validate a port specification string.

    Accepts comma-separated port numbers or port ranges (e.g. ``"80,443,8000-9000"``).
    Whitespace between tokens is stripped.

    Returns
    -------
    (cleaned_value, None)
        Validation passed.
    ("", error_message)
        Validation failed.
    """
    stripped = value.strip()
    if not stripped:
        return "", None

    # Remove spaces around commas/hyphens
    normalised = re.sub(r"\s*,\s*", ",", stripped)
    normalised = re.sub(r"\s*-\s*", "-", normalised)

    if not _PORTS_RE.match(normalised):
        return "", f"invalid port specification: {value!r} — expected comma-separated ports or ranges (e.g. '80,443,8000-9000')"

    return normalised, None


# Valid top-N thresholds accepted by naabu/nmap.
_VALID_TOP_PORTS = frozenset({100, 1000})


def sanitize_top_ports(value: str) -> tuple[str, str | None]:
    """Validate a *top-ports* integer (e.g. ``"100"`` or ``"1000"``).

    Only accepts a single positive integer from the set ``{100, 1000}``
    which correspond to the standard naabu / nmap ``--top-ports`` presets.

    Returns
    -------
    (cleaned_value, None)
        Validation passed.
    ("", error_message)
        Validation failed.
    """
    stripped = value.strip()
    if not stripped:
        return "", None

    if not stripped.isdigit():
        return "", f"invalid top_ports value: {value!r} — expected a positive integer (100 or 1000)"

    num = int(stripped)
    if num not in _VALID_TOP_PORTS:
        return "", f"unsupported top_ports value: {num} — allowed: {', '.join(str(v) for v in sorted(_VALID_TOP_PORTS))}"

    return stripped, None


# ── Severity ───────────────────────────────────────────────────────────

_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


def sanitize_severity(value: str) -> tuple[str, str | None]:
    """Validate a comma-separated severity filter.

    Accepts: ``"critical"``, ``"critical,high"``, ``"HIGH, MEDIUM"``, etc.

    Returns
    -------
    (cleaned_value, None)
        Validation passed.
    ("", error_message)
        Validation failed.
    """
    stripped = value.strip()
    if not stripped:
        return "", None

    parts = [s.strip().lower() for s in stripped.split(",") if s.strip()]
    invalid = [p for p in parts if p not in _VALID_SEVERITIES]
    if invalid:
        return "", (
            f"invalid severity value(s): {', '.join(invalid)!r} "
            f"— allowed: {', '.join(sorted(_VALID_SEVERITIES))}"
        )

    return ",".join(parts), None


# ── Tags ───────────────────────────────────────────────────────────────

# Tags must be simple alphanumeric + hyphen/underscore tokens.
_TAG_TOKEN_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def sanitize_tags(value: str) -> tuple[str, str | None]:
    """Validate a comma-separated list of nuclei template tags.

    Accepts simple tokens like ``"cve,wordpress"``, ``"CVE, XSS,sqli"``.

    Returns
    -------
    (cleaned_value, None)
        Validation passed.
    ("", error_message)
        Validation failed.
    """
    stripped = value.strip()
    if not stripped:
        return "", None

    parts = [s.strip().lower() for s in stripped.split(",") if s.strip()]
    invalid = [p for p in parts if not _TAG_TOKEN_RE.match(p)]
    if invalid:
        return "", (
            f"invalid tag(s): {', '.join(invalid)!r} "
            f"— tags must be alphanumeric (hyphens and underscores allowed)"
        )

    return ",".join(parts), None
