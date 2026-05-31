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
import logging
import re
import socket
from collections.abc import Callable
from enum import Enum
from urllib.parse import urlparse

from langchain_core.tools import ToolException

_ErrFn = Callable[[str], ToolException]

logger = logging.getLogger(__name__)


def _enforce_scope(host: str, _err: _ErrFn) -> None:
    """Reject *host* when a Rules-of-Engagement scope file excludes it.

    No-op when no scope file is configured (permissive default).  This is the
    code-level enforcement point for the RoE scope — every tool target flows
    through :func:`guard_target` and therefore through here.
    """
    from fackel.scope import check_scope

    decision = check_scope(host)
    if not decision.allowed:
        raise _err(decision.reason or f"target out of scope: {host!r}")


_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$")

_OCTET_QUAD_RE = re.compile(r"^\d{1,3}(?:-\d{1,3}){3}$")


_PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("::/128"),
)


def is_private_ip(value: str) -> bool:
    """Return ``True`` if *value* is an IP in a private or reserved range.

    Covers RFC 1918, loopback (127.x), link-local (169.254.x),
    IPv6 ULA (fc00::/7), and IPv6 link-local (fe80::/10).
    """
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETWORKS)


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


def ensure_scheme(value: str, *, default_scheme: str = "https") -> str:
    """Prefix *value* with ``{default_scheme}://`` if it has no scheme.

    Tools that accept a host-or-URL target and pass it to an HTTP client or
    a URL-oriented binary use this to normalise bare hosts (``example.com``)
    into full URLs (``https://example.com``).  Values that already start with
    ``http://`` or ``https://`` are returned unchanged.
    """
    if value.startswith(("http://", "https://")):
        return value
    return f"{default_scheme}://{value}"


def _extract_host(value: str) -> str:
    """Return the bare hostname / IP from a value that may include a scheme.

    Handles bare IPv6 addresses (e.g. ``fc00::1``) which ``urlparse``
    misinterprets as having a scheme.
    """
    # Detect bare IPv6 first — urlparse misparses these.
    try:
        ipaddress.ip_address(value)
        return value  # Already a valid IP literal.
    except ValueError:
        pass

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
        return _guard_url(raw, _err)
    if accept is TargetType.HOST_OR_URL:
        return _guard_host_or_url(raw, tool_name, _err)
    if accept is TargetType.HOST_PORT:
        return _guard_host_port(raw, _err)

    # DOMAIN / IP / HOST share host extraction + shell-meta rejection.
    host = _extract_host(raw)
    if _SHELL_META_RE.search(host):
        raise _err(f"target contains forbidden characters: {host!r}")
    if accept is TargetType.DOMAIN:
        return _guard_domain(host, tool_name, _err)
    if accept is TargetType.IP:
        return _guard_ip(host, tool_name, _err)
    if accept is TargetType.HOST:
        return _guard_host(host, _err)

    raise _err(f"unknown target type: {accept}")  # pragma: no cover


_PRIVATE_IP_MSG = (
    "target is a private/reserved IP address ({host}). "
    "Scanning internal networks is not permitted. "
    "Use a public IP or domain name instead."
)


def _guard_url(raw: str, _err: _ErrFn) -> str:
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise _err(f"expected a full URL (http/https), got: {raw}")
    if not parsed.hostname:
        raise _err(f"URL has no hostname: {raw}")
    if _SHELL_META_RE.search(parsed.hostname):
        raise _err(f"target contains forbidden characters: {parsed.hostname!r}")
    _enforce_scope(parsed.hostname, _err)
    return raw


def _guard_host_or_url(raw: str, tool_name: str, _err: _ErrFn) -> str:
    parsed = urlparse(raw)
    if parsed.scheme in ("http", "https") and parsed.hostname:
        if _SHELL_META_RE.search(parsed.hostname):
            raise _err(f"target contains forbidden characters: {parsed.hostname!r}")
        _enforce_scope(parsed.hostname, _err)
        return raw
    return guard_target(raw, tool_name, TargetType.HOST)


def _guard_domain(host: str, tool_name: str, _err: _ErrFn) -> str:
    if is_valid_ip(host):
        raise _err(
            f"{tool_name} requires a domain name, not an IP address. "
            f"Use the domain or subdomain instead of {host}."
        )
    if not is_valid_domain(host):
        raise _err(f"invalid domain name: {host!r}")
    _enforce_scope(host, _err)
    return host


def _guard_ip(host: str, tool_name: str, _err: _ErrFn) -> str:
    if not is_valid_ip(host):
        raise _err(f"{tool_name} requires an IP address, got: {host!r}")
    if is_private_ip(host):
        raise _err(_PRIVATE_IP_MSG.format(host=host))
    _enforce_scope(host, _err)
    return host


def _guard_host(host: str, _err: _ErrFn) -> str:
    if not is_valid_ip(host) and not is_valid_domain(host):
        raise _err(f"invalid host (not a valid IP or domain): {host!r}")
    if is_valid_ip(host) and is_private_ip(host):
        raise _err(_PRIVATE_IP_MSG.format(host=host))
    _enforce_scope(host, _err)
    return host


def _guard_host_port(raw: str, _err: _ErrFn) -> str:
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
    _enforce_scope(bare, _err)
    return f"{bare}{port_part}"


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

    if is_valid_ip(host):
        if is_private_ip(host):
            raise ValueError(
                f"Target is a private/reserved IP address ({host}). "
                "Scanning internal networks is not permitted."
            )
        return host

    if is_valid_domain(host):
        return host

    raise ValueError(f"Target is not a valid IP or domain: {host!r}")


def resolve_host(hostname: str) -> list[str]:
    """Resolve *hostname* to a list of IP address strings.

    Returns an empty list if DNS resolution fails.  Never raises.
    """
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return list({str(info[4][0]) for info in infos})
    except (socket.gaierror, OSError):
        return []


def guard_dns_rebinding(hostname: str, tool_name: str) -> None:
    """Resolve *hostname* and reject it if any address is private/reserved.

    DNS rebinding attacks work by making a domain resolve to a private IP
    **after** the domain-level validation has passed.  This function
    performs an actual DNS lookup and checks every resolved address against
    :data:`_PRIVATE_NETWORKS`.

    Should be called **immediately before** the tool makes its outbound
    network request, to minimise the window between resolution and use.

    Raises
    ------
    ToolException
        When the hostname resolves to one or more private/reserved IPs.
    """
    if is_valid_ip(hostname):
        # Already checked by guard_target — skip resolution.
        return

    resolved = resolve_host(hostname)
    if not resolved:
        logger.debug(
            "guard_dns_rebinding(%s): DNS resolution returned no results",
            hostname,
        )
        return  # Tool will fail on its own when it can't connect.

    private_addrs = [ip for ip in resolved if is_private_ip(ip)]
    if private_addrs:
        raise ToolException(
            f"{tool_name}: hostname {hostname!r} resolves to private/reserved "
            f"address(es) {private_addrs}. This may be a DNS rebinding attack. "
            "Scanning internal networks is not permitted."
        )


def guard_request_target(value: str, tool_name: str) -> None:
    """Guard the host a tool is about to connect to against SSRF.

    Accepts a bare host or a full URL and extracts the hostname.  When the
    host is an IP literal it is rejected outright if private/reserved (e.g.
    ``http://169.254.169.254/`` cloud-metadata, ``127.0.0.1``, RFC-1918);
    otherwise it is checked for DNS rebinding via :func:`guard_dns_rebinding`.

    Call this **immediately before** issuing the outbound request in tools
    that connect to a *user-supplied* target (e.g. fetching a URL).  Tools
    that query a fixed third-party API about the target do **not** need this —
    they never connect to the target itself.

    Note that :func:`guard_target` validates input *syntax* but does not
    reject private IPs for ``URL`` / ``HOST_OR_URL`` types, so this guard is
    the actual SSRF rail for connect-to-target tools.

    Raises
    ------
    ToolException
        When the target host is, or resolves to, a private/reserved address.
    """
    host = _extract_host(value)
    if is_valid_ip(host):
        if is_private_ip(host):
            raise ToolException(
                f"{tool_name}: target host {host!r} is a private/reserved "
                "address. Connecting to internal networks is not permitted."
            )
        return
    guard_dns_rebinding(host, tool_name)
