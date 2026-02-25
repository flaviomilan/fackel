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

* ``DOMAIN``  - valid domain name; rejects IPs, URLs, and shell meta-characters.
* ``IP``      - valid IPv4 / IPv6 address.
* ``HOST``    - domain **or** IP.
* ``HOST_PORT`` - domain or IP, optionally with ``:port``.
* ``URL``     - must include ``http://`` or ``https://`` scheme.
* ``HOST_OR_URL`` - domain, IP, or full URL.
"""

from __future__ import annotations

import ipaddress
import re
from enum import Enum
from urllib.parse import urlparse

from langchain_core.tools import ToolException

_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$")

_OCTET_QUAD_RE = re.compile(r"^\d{1,3}(?:-\d{1,3}){3}$")


def is_valid_ip(value: str) -> bool:
    """Return ``True`` if *value* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    """Return ``True`` if *value* looks like a syntactically valid domain name."""
    return bool(_DOMAIN_RE.match(value.strip()))


def is_reverse_ptr_subdomain(label: str) -> bool:
    """Return ``True`` if the first label looks like an IP encoded as a hostname.

    Matches patterns like ``200-210-75-128`` (4 octets joined by hyphens),
    which are typically auto-generated reverse-PTR records and not real
    application subdomains.
    """
    first_label = label.split(".")[0]
    return bool(_OCTET_QUAD_RE.match(first_label))


_SHELL_META_RE = re.compile(r"[;&|`$(){}!\[\]<>'\"\\\n\r]")


class TargetType(Enum):
    """Declares what kind of target a tool accepts."""

    DOMAIN = "domain"
    IP = "ip"
    HOST = "host"
    HOST_PORT = "host_port"
    URL = "url"
    HOST_OR_URL = "host_or_url"


def _extract_host(value: str) -> str:
    """Return the bare hostname / IP from a value that may include a scheme."""
    parsed = urlparse(value)
    host = parsed.hostname or parsed.netloc or parsed.path.split("/")[0] or value
    return host.strip().rstrip(".")


def guard_target(
    value: str,
    tool_name: str,
    accept: TargetType,
) -> str:
    """Validate and normalise a tool target.

    Returns the cleaned value on success.  Raises ``ToolException`` on
    validation failure so the agent receives a clear error message.

    Raises
    ------
    ToolException
        When the target is empty, contains forbidden characters, or
        does not match the expected *accept* type.
    """

    def _err(msg: str) -> ToolException:
        return ToolException(f"{tool_name}: {msg}")

    if not value or not value.strip():
        raise _err("target is empty")

    raw = value.strip()

    if accept is TargetType.URL:
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https"):
            raise _err(f"expected a full URL (http/https), got: {raw}")
        if not parsed.hostname:
            raise _err(f"URL has no hostname: {raw}")
        host = parsed.hostname
        if _SHELL_META_RE.search(host):
            raise _err(f"target contains forbidden characters: {host!r}")
        return raw

    if accept is TargetType.HOST_OR_URL:
        parsed = urlparse(raw)
        if parsed.scheme in ("http", "https") and parsed.hostname:
            host = parsed.hostname
            if _SHELL_META_RE.search(host):
                raise _err(f"target contains forbidden characters: {host!r}")
            return raw
        return guard_target(raw, tool_name, TargetType.HOST)

    host = _extract_host(raw)

    if _SHELL_META_RE.search(host):
        raise _err(f"target contains forbidden characters: {host!r}")

    if accept is TargetType.DOMAIN:
        if is_valid_ip(host):
            raise _err(
                f"{tool_name} requires a domain name, not an IP address. "
                f"Use the domain or subdomain instead of {host}."
            )
        if not is_valid_domain(host):
            raise _err(f"invalid domain name: {host!r}")
        return host

    if accept is TargetType.IP:
        if not is_valid_ip(host):
            raise _err(f"{tool_name} requires an IP address, got: {host!r}")
        return host

    if accept is TargetType.HOST:
        if not is_valid_ip(host) and not is_valid_domain(host):
            raise _err(f"invalid host (not a valid IP or domain): {host!r}")
        return host

    if accept is TargetType.HOST_PORT:
        candidate = raw
        port_part = ""
        if ":" in candidate and not candidate.startswith("["):
            last_colon = candidate.rfind(":")
            maybe_port = candidate[last_colon + 1 :]
            if maybe_port.isdigit():
                candidate = candidate[:last_colon]
                port_part = f":{maybe_port}"
        bare = candidate.strip().rstrip(".")
        if _SHELL_META_RE.search(bare):
            raise _err(f"target contains forbidden characters: {bare!r}")
        if not is_valid_ip(bare) and not is_valid_domain(bare):
            raise _err(f"invalid host (not a valid IP or domain): {bare!r}")
        return f"{bare}{port_part}"

    raise _err(f"unknown target type: {accept}")  # pragma: no cover


def sanitize_target(raw: str) -> str:
    """Normalise and validate a user-supplied target string.

    Strips scheme / path from URLs, rejects shell metacharacters,
    and ensures the result is a valid IP or domain.

    This is the **orchestrator-level** entry-point guard (raises on bad
    input).  Tools should prefer :func:`guard_target` instead, which
    returns structured error dicts.

    Raises
    ------
    ValueError
        If the target is empty, contains dangerous characters, or
        is neither a valid IP nor a valid domain.
    """
    if not raw or not raw.strip():
        raise ValueError("Target is empty.")

    raw = raw.strip()

    host = _extract_host(raw)

    if _SHELL_META_RE.search(host):
        raise ValueError(f"Target contains forbidden characters: {host!r}")

    if is_valid_ip(host) or is_valid_domain(host):
        return host

    raise ValueError(f"Target is not a valid IP or domain: {host!r}")
