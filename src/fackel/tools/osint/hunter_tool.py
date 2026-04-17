"""Email discovery via Hunter.io domain search.

Discovers email addresses (and the people/positions behind them) associated
with a domain — the input that ``analyze_email`` needs but that nothing else
produces.  Queries Hunter.io's API only (a fixed third-party endpoint), never
the target, so it stays passive.

Requires ``HUNTER_API_KEY`` (free tier available).
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    format_tool_output,
    get_tool_timeout,
    guard_target,
    require_env,
)
from fackel.tooling.circuit_breaker import circuit_breaker
from fackel.tooling.http_client import get_session

_API_URL = "https://api.hunter.io/v2/domain-search"
_TIMEOUT = 20
_MAX_EMAILS = 50


class HunterInput(BaseModel):
    """Input for Hunter.io email discovery."""

    domain: str = Field(
        description=(
            "Domain to discover email addresses for (e.g. 'example.com'). "
            "Returns emails with the associated person name, position, and "
            "confidence, plus the organisation name. Feed the discovered "
            "addresses to analyze_email for breach/reputation checks."
        ),
    )


@tool(args_schema=HunterInput)
def hunter_email_search(domain: str) -> dict[str, Any]:
    """Discover a domain's email addresses and contacts via Hunter.io.

    Returns the organisation name and a list of emails, each with the
    person's name, position, and a confidence score.  This is the discovery
    step that feeds ``analyze_email`` (which only checks a known address).
    """
    domain = guard_target(domain, "hunter_email_search", TargetType.DOMAIN)
    api_key = require_env("HUNTER_API_KEY", "hunter_email_search")

    import requests

    with circuit_breaker("hunter"):
        try:
            resp = get_session().get(
                _API_URL,
                params={"domain": domain, "api_key": api_key, "limit": str(_MAX_EMAILS)},
                timeout=get_tool_timeout("hunter_email_search", _TIMEOUT),
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise ToolException(f"hunter_email_search: request failed: {exc}") from exc

    try:
        payload = resp.json()
    except ValueError:
        raise ToolException("hunter_email_search: returned non-JSON response") from None

    data = payload.get("data") or {}
    emails = []
    for entry in data.get("emails", []) or []:
        if not isinstance(entry, dict) or not entry.get("value"):
            continue
        emails.append(
            {
                "email": str(entry["value"]).strip().lower(),
                "first_name": entry.get("first_name") or "",
                "last_name": entry.get("last_name") or "",
                "position": entry.get("position") or "",
                "confidence": entry.get("confidence", 0),
                "type": entry.get("type", ""),
            }
        )

    return format_tool_output(
        "hunter_email_search",
        domain,
        "ok",
        data={
            "domain": data.get("domain", domain),
            "organization": data.get("organization") or "",
            "emails": emails,
            "count": len(emails),
        },
    )


hunter_email_search.handle_tool_error = True
