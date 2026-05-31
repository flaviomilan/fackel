"""Username → social-account discovery via Maigret.

Maigret checks a username against hundreds of websites and returns the profiles
that exist.  Unlike the rest of Fackel's OSINT surface — which queries a single
fixed third-party endpoint about the target — Maigret fans out to many
third-party sites, so it is **semi-passive**.  It is therefore gated behind an
explicit opt-in (``FACKEL_ENABLE_MAIGRET``) and is disabled by default.

It produces the ``USERNAME`` and ``SOCIAL_ACCOUNT`` information types, which
nothing else in the toolset emits.

Requires the ``maigret`` binary and ``FACKEL_ENABLE_MAIGRET`` set to a truthy
value (``1``/``true``/``yes``).
"""

from __future__ import annotations

import os
import re
from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import format_tool_output, get_tool_timeout, require_binary, run_command

_TIMEOUT = 180
_MAX_ACCOUNTS = 200
# Conservative username charset: letters, digits, dot, underscore, hyphen.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
# Maigret prints found accounts as: "[+] SiteName: https://site/user"
_FOUND_RE = re.compile(r"^\[\+\]\s*(?P<site>[^:]+):\s*(?P<url>https?://\S+)\s*$")


class MaigretInput(BaseModel):
    """Input for Maigret username enumeration."""

    username: str = Field(
        description=(
            "Username / handle to search across social and web platforms "
            "(e.g. 'janedoe'). Returns the profiles that exist. Semi-passive: "
            "queries many third-party sites. Disabled unless "
            "FACKEL_ENABLE_MAIGRET is set."
        ),
    )


def _enabled() -> bool:
    return os.getenv("FACKEL_ENABLE_MAIGRET", "").strip().lower() in ("1", "true", "yes", "on")


@tool(args_schema=MaigretInput)
def maigret_scan(username: str) -> dict[str, Any]:
    """Discover a username's social/web accounts via Maigret.

    Returns the platforms where the username has an existing profile, each with
    the site name and URL.  **Semi-passive** — queries hundreds of third-party
    sites, so it is gated behind ``FACKEL_ENABLE_MAIGRET`` and disabled by
    default.  Produces the USERNAME and SOCIAL_ACCOUNT information types.
    """
    if not _enabled():
        raise ToolException(
            "maigret_scan: disabled. This tool is semi-passive (queries many "
            "third-party sites). Set FACKEL_ENABLE_MAIGRET=1 to opt in."
        )
    require_binary("maigret", "maigret_scan")

    username = username.strip()
    if not _USERNAME_RE.match(username):
        raise ToolException(f"maigret_scan: invalid username: {username!r}")

    cmd = ["maigret", username, "--no-color", "--no-progressbar"]
    try:
        code, out, stderr = run_command(cmd, timeout=get_tool_timeout("maigret_scan", _TIMEOUT))
    except Exception as exc:
        raise ToolException(f"maigret_scan: {exc}") from exc

    accounts: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in out.splitlines():
        match = _FOUND_RE.match(line.strip())
        if not match:
            continue
        url = match.group("url").strip()
        if url in seen:
            continue
        seen.add(url)
        accounts.append({"site": match.group("site").strip(), "url": url})
        if len(accounts) >= _MAX_ACCOUNTS:
            break

    if not accounts and code and not out.strip():
        raise ToolException(f"maigret_scan: {stderr.strip() or 'scan failed'}")

    return format_tool_output(
        "maigret_scan",
        username,
        "ok",
        data={"username": username, "accounts": accounts, "count": len(accounts)},
    )


maigret_scan.handle_tool_error = True
