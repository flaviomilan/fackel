"""Credential-leak lookup via the LeakCheck breach database.

Checks an email address against LeakCheck's aggregated breach database and
returns the breaches it appears in (source name and date).  Complements
``analyze_email`` (HIBP) with a second breach corpus and feeds the
``CREDENTIAL_LEAK`` information type.  Queries the LeakCheck API only — never
the target — so it stays passive.

Requires ``LEAKCHECK_API_KEY`` (free tier available).
"""

from __future__ import annotations

import re
from typing import Any

import requests
from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import format_tool_output, get_tool_timeout, require_env
from fackel.tooling.circuit_breaker import circuit_breaker
from fackel.tooling.http_client import get_session

_API_URL = "https://leakcheck.io/api/v2/query/{query}"
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_TIMEOUT = 20
_MAX_BREACHES = 100


class BreachLookupInput(BaseModel):
    """Input for LeakCheck breach lookup."""

    email: str = Field(
        description=(
            "Email address to check against the LeakCheck breach database "
            "(e.g. 'jane@example.com'). Returns the breaches the address "
            "appears in. Passive — only the LeakCheck dataset is queried."
        ),
    )


@tool(args_schema=BreachLookupInput)
def breach_lookup(email: str) -> dict[str, Any]:
    """Check an email against the LeakCheck breach database.

    Returns the list of breaches the address appears in, each with a source
    name and date.  Complements ``analyze_email`` (HIBP) with a second corpus.
    Pure passive OSINT — the LeakCheck dataset is queried, never the target.
    Requires LEAKCHECK_API_KEY (free tier available).
    """
    email = email.strip().lower()
    if not _EMAIL_RE.match(email):
        raise ToolException("breach_lookup: invalid email format")
    api_key = require_env("LEAKCHECK_API_KEY", "breach_lookup")

    with circuit_breaker("leakcheck"):
        try:
            resp = get_session().get(
                _API_URL.format(query=email),
                params={"type": "email"},
                headers={"X-API-Key": api_key, "Accept": "application/json"},
                timeout=get_tool_timeout("breach_lookup", _TIMEOUT),
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise ToolException(f"breach_lookup: request failed: {exc}") from exc

    try:
        payload = resp.json()
    except ValueError:
        raise ToolException("breach_lookup: returned non-JSON response") from None

    breaches: list[dict[str, str]] = []
    seen: set[str] = set()
    for entry in payload.get("result", []) or []:
        if not isinstance(entry, dict):
            continue
        source = entry.get("source") or {}
        if isinstance(source, dict):
            name = str(source.get("name", "")).strip()
            date = str(source.get("breach_date", "") or source.get("date", "")).strip()
        else:
            name = str(source).strip()
            date = ""
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        breaches.append({"name": name, "date": date})
        if len(breaches) >= _MAX_BREACHES:
            break

    return format_tool_output(
        "breach_lookup",
        email,
        "ok",
        data={"email": email, "found": len(breaches), "breaches": breaches},
    )


breach_lookup.handle_tool_error = True
