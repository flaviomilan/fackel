"""Rules-of-Engagement (RoE) scope enforcement.

A penetration test must stay within an agreed scope.  Fackel reads an optional
TOML scope file (``.fackel/scope.toml`` by default, override with
``FACKEL_SCOPE_FILE``) and enforces it as **code-level** policy inside
:func:`fackel.tooling.validators.guard_target` — every tool that accepts a
target therefore refuses out-of-scope work, not just because a prompt said so.

The file is optional and the default is **permissive**: if no scope file exists,
every otherwise-valid target is allowed (no behaviour change).  When a file is
present:

- ``out_of_scope`` is a denylist and always wins.
- ``in_scope`` is an allowlist; if it is non-empty, a target must match it.
- An empty/absent ``in_scope`` means "everything not denied is allowed".

Example ``.fackel/scope.toml``::

    in_scope = ["example.com", "*.corp.example.com", "203.0.113.0/24"]
    out_of_scope = ["admin.example.com", "10.0.0.0/8"]

Entries may be exact domains (apex also covers its subdomains), ``*.`` wildcard
domains, or IP addresses / CIDR ranges.
"""

from __future__ import annotations

import ipaddress
import logging
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Scope:
    """A parsed Rules-of-Engagement scope."""

    in_scope: tuple[str, ...]
    out_of_scope: tuple[str, ...]


@dataclass(frozen=True)
class ScopeDecision:
    """Outcome of a scope check for one target."""

    allowed: bool
    reason: str | None = None


def _matches(target: str, pattern: str) -> bool:
    """Return whether *target* matches a single scope *pattern*.

    Supports CIDR / IP entries (membership), ``*.`` wildcard domains, and exact
    domains where the apex also covers its subdomains.
    """
    pattern = pattern.strip().lower()
    if not pattern:
        return False

    # IP / CIDR entry: only an IP target can match.
    try:
        network = ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        network = None
    if network is not None:
        try:
            return ipaddress.ip_address(target) in network
        except ValueError:
            return False

    # Wildcard domain: "*.example.com" matches any subdomain of example.com.
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return target == pattern[2:] or target.endswith(suffix)

    # Exact domain — the apex also covers its subdomains.
    return target == pattern or target.endswith("." + pattern)


def check_scope(target: str) -> ScopeDecision:
    """Decide whether *target* is permitted by the configured scope.

    Permissive when no scope file is present.  ``out_of_scope`` always wins; a
    non-empty ``in_scope`` acts as a required allowlist.
    """
    scope = _load_scope()
    if scope is None:
        return ScopeDecision(allowed=True)

    t = target.strip().lower()

    for pattern in scope.out_of_scope:
        if _matches(t, pattern):
            return ScopeDecision(
                allowed=False,
                reason=(
                    f"Target {target!r} is explicitly out of scope "
                    f"(matched {pattern!r}). Refusing per Rules-of-Engagement."
                ),
            )

    if not scope.in_scope:
        return ScopeDecision(allowed=True)

    for pattern in scope.in_scope:
        if _matches(t, pattern):
            return ScopeDecision(allowed=True)

    return ScopeDecision(
        allowed=False,
        reason=(
            f"Target {target!r} is not within the configured in-scope allowlist. "
            f"Refusing per Rules-of-Engagement."
        ),
    )


def _load_scope() -> Scope | None:
    """Load and cache the scope file (keyed on path + mtime), or ``None``."""
    from fackel.settings import get_settings

    path = Path(get_settings().scope_file)
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    return _load_scope_cached(str(path), mtime)


@lru_cache(maxsize=4)
def _load_scope_cached(path_str: str, _mtime: float) -> Scope | None:
    path = Path(path_str)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        logger.warning("scope: failed to read %s (%s) — treating as no scope", path, exc)
        return None

    in_scope = tuple(str(x).strip() for x in data.get("in_scope", []) if str(x).strip())
    out_of_scope = tuple(str(x).strip() for x in data.get("out_of_scope", []) if str(x).strip())
    logger.info("scope: loaded %s (in=%d, out=%d)", path, len(in_scope), len(out_of_scope))
    return Scope(in_scope=in_scope, out_of_scope=out_of_scope)


def clear_scope_cache() -> None:
    """Drop the cached scope (used by tests after changing the scope file/env)."""
    _load_scope_cached.cache_clear()
