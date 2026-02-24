"""Email analysis — breach exposure, reputation, and service registration checks."""

from __future__ import annotations

import logging
import os
import re

import requests
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from fackel.tooling import format_tool_output

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class EmailAnalyzerInput(BaseModel):
    """Input schema for email analysis."""

    email: str = Field(
        description="Email address to analyse for breach exposure, reputation, and service registrations.",
    )


def _check_breaches(email: str) -> list[dict]:
    """Query HIBP for data breaches. Degrades gracefully without API key."""
    api_key = os.getenv("HIBP_API_KEY", "").strip()
    if not api_key:
        return []
    try:
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={"hibp-api-key": api_key, "user-agent": "OSINT-Tool"},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        logger.debug("HIBP lookup failed for %s", email, exc_info=True)
    return []


def _check_reputation(email: str) -> dict | None:
    """Query EmailRep for reputation scoring. Degrades gracefully without API key."""
    api_key = os.getenv("EMAILREP_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        resp = requests.get(
            f"https://emailrep.io/{email}",
            headers={"Key": api_key},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        logger.debug("EmailRep lookup failed for %s", email, exc_info=True)
    return None


@tool(args_schema=EmailAnalyzerInput)
def analyze_email(email: str) -> dict:
    """Analyse an email address across multiple sources: data breach exposure
    (HIBP) and reputation scoring (EmailRep).

    HIBP and EmailRep checks degrade gracefully when API keys are missing.
    """
    email = email.strip()
    if not _EMAIL_RE.match(email):
        return format_tool_output(
            "analyze_email", email, "error",
            error="invalid email format",
        )

    breaches = _check_breaches(email)
    reputation = _check_reputation(email)

    return format_tool_output(
        "analyze_email", email, "ok",
        data={
            "breaches": breaches,
            "reputation": reputation,
        },
    )
