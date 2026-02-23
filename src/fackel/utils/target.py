"""Target string normalisation and validation."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from fackel.utils.network import is_valid_domain, is_valid_ip


def extract_host(target: str) -> str | None:
    """Extract the bare hostname or IP from a target that may include a URL scheme.

    Returns ``None`` when *target* is empty.
    """
    if not target:
        return None
    parsed = urlparse(target)
    return parsed.hostname or parsed.netloc or parsed.path.split("/")[0] or target or None


def sanitize_target(raw: str) -> str:
    """Normalise and validate a user-supplied target string.

    Strips scheme / path from URLs, rejects shell metacharacters,
    and ensures the result is a valid IP or domain.

    Raises
    ------
    ValueError
        If the target is empty, contains dangerous characters, or
        is neither a valid IP nor a valid domain.
    """
    if not raw or not raw.strip():
        raise ValueError("Target is empty.")

    raw = raw.strip()

    # Strip URL scheme / path if present.
    parsed = urlparse(raw)
    host = parsed.hostname or parsed.netloc or parsed.path.split("/")[0] or raw
    host = host.strip().rstrip(".")

    # Block shell metacharacters (prevent injection via subprocess tools).
    if re.search(r"[;&|`$(){}!\[\]<>'\"\\\n\r]", host):
        raise ValueError(f"Target contains forbidden characters: {host!r}")

    if is_valid_ip(host) or is_valid_domain(host):
        return host

    raise ValueError(f"Target is not a valid IP or domain: {host!r}")
