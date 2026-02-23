"""Standardised input-validation rails for tool wrappers.

Every tool that receives a *target* parameter should call
:func:`guard_target` at the top of its body.  The function validates
and normalises the input, returning either a clean string **or** a
pre-formatted error dict that the tool can return immediately.

Usage inside a tool::

    target, err = guard_target(target, "my_tool", TargetType.DOMAIN)
    if err:
        return err
    # ... proceed with *target* (already stripped / normalised)

Available target types:

* ``DOMAIN``  – valid domain name; rejects IPs, URLs, and shell meta-characters.
* ``IP``      – valid IPv4 / IPv6 address.
* ``HOST``    – domain **or** IP.
* ``URL``     – must include ``http://`` or ``https://`` scheme.
* ``HOST_OR_URL`` – domain, IP, or full URL.
"""

from __future__ import annotations

import re
from enum import Enum
from urllib.parse import urlparse

from fackel.utils.network import is_valid_domain, is_valid_ip

# Characters that must never reach a subprocess argument.
_SHELL_META_RE = re.compile(r"[;&|`$(){}!\[\]<>'\"\\\n\r]")


class TargetType(Enum):
    """Declares what kind of target a tool accepts."""

    DOMAIN = "domain"
    IP = "ip"
    HOST = "host"            # domain or IP
    URL = "url"              # requires scheme
    HOST_OR_URL = "host_or_url"  # domain, IP, or full URL


def _extract_host(value: str) -> str:
    """Return the bare hostname / IP from a value that may include a scheme."""
    parsed = urlparse(value)
    host = parsed.hostname or parsed.netloc or parsed.path.split("/")[0] or value
    return host.strip().rstrip(".")


def guard_target(
    value: str,
    tool_name: str,
    accept: TargetType,
) -> tuple[str, dict | None]:
    """Validate and normalise a tool target.

    Returns
    -------
    (cleaned_value, None)
        Validation passed.  Use *cleaned_value* going forward.
    ("", error_dict)
        Validation failed.  The tool should ``return error_dict``.
    """
    from .utils import format_tool_output   # local to avoid circular import

    def _err(msg: str) -> tuple[str, dict]:
        return "", format_tool_output(tool_name, value, "error", error=msg)

    # ── basic sanity ────────────────────────────────────────────────
    if not value or not value.strip():
        return _err("target is empty")

    raw = value.strip()

    # ── URL type: require scheme, validate netloc ───────────────────
    if accept is TargetType.URL:
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https"):
            return _err(
                f"expected a full URL (http/https), got: {raw}"
            )
        if not parsed.hostname:
            return _err(f"URL has no hostname: {raw}")
        host = parsed.hostname
        if _SHELL_META_RE.search(host):
            return _err(f"target contains forbidden characters: {host!r}")
        return raw, None

    # ── HOST_OR_URL: accept either scheme-based URL or bare host ────
    if accept is TargetType.HOST_OR_URL:
        parsed = urlparse(raw)
        if parsed.scheme in ("http", "https") and parsed.hostname:
            host = parsed.hostname
            if _SHELL_META_RE.search(host):
                return _err(f"target contains forbidden characters: {host!r}")
            return raw, None      # keep full URL
        # fall through → treat as HOST
        return guard_target(raw, tool_name, TargetType.HOST)

    # ── extract host for DOMAIN / IP / HOST checks ─────────────────
    host = _extract_host(raw)

    if _SHELL_META_RE.search(host):
        return _err(f"target contains forbidden characters: {host!r}")

    if accept is TargetType.DOMAIN:
        if is_valid_ip(host):
            return _err(
                f"{tool_name} requires a domain name, not an IP address. "
                f"Use the domain or subdomain instead of {host}."
            )
        if not is_valid_domain(host):
            return _err(f"invalid domain name: {host!r}")
        return host, None

    if accept is TargetType.IP:
        if not is_valid_ip(host):
            return _err(
                f"{tool_name} requires an IP address, got: {host!r}"
            )
        return host, None

    if accept is TargetType.HOST:
        if not is_valid_ip(host) and not is_valid_domain(host):
            return _err(f"invalid host (not a valid IP or domain): {host!r}")
        return host, None

    return _err(f"unknown target type: {accept}")  # pragma: no cover
