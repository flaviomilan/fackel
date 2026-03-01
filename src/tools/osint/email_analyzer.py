"""Email analysis — breach exposure, reputation, and service registration checks."""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import format_tool_output
from fackel.tooling.http_client import get_session

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_TIMEOUT = 10


class EmailAnalyzerInput(BaseModel):
    """Input schema for email analysis."""

    email: str = Field(
        description="Email address to analyse for breach exposure, reputation, and service registrations.",
    )


def _check_breaches(email: str) -> list[dict[str, Any]]:
    """Query HIBP for data breaches. Degrades gracefully without API key."""
    api_key = os.getenv("HIBP_API_KEY", "").strip()
    if not api_key:
        return []
    try:
        resp = get_session().get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={"hibp-api-key": api_key, "user-agent": "OSINT-Tool"},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            result: list[dict[str, Any]] = resp.json()
            return result
    except Exception:
        logger.debug("HIBP lookup failed for %s", email, exc_info=True)
    return []


def _check_reputation(email: str) -> dict[str, Any] | None:
    """Query EmailRep for reputation scoring. Degrades gracefully without API key."""
    api_key = os.getenv("EMAILREP_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        resp = get_session().get(
            f"https://emailrep.io/{email}",
            headers={"Key": api_key},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            result: dict[str, Any] = resp.json()
            return result
    except Exception:
        logger.debug("EmailRep lookup failed for %s", email, exc_info=True)
    return None


@tool(args_schema=EmailAnalyzerInput)
def analyze_email(email: str) -> dict[str, Any]:
    """Analyse an email address across multiple sources: data breach exposure
    (HIBP) and reputation scoring (EmailRep).

    HIBP and EmailRep checks degrade gracefully when API keys are missing.
    """
    email = email.strip()
    if not _EMAIL_RE.match(email):
        raise ToolException("analyze_email: invalid email format")

    breaches = _check_breaches(email)
    reputation = _check_reputation(email)

    return format_tool_output(
        "analyze_email",
        email,
        "ok",
        data={
            "breaches": breaches,
            "reputation": reputation,
        },
    )


analyze_email.handle_tool_error = True
