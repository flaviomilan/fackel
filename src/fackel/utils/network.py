"""IP and domain validation helpers."""

from __future__ import annotations

import ipaddress
import re

_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)

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
