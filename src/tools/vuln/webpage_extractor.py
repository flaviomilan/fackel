"""Webpage content extraction — strips HTML boilerplate and returns text."""

from __future__ import annotations

from typing import Any

import requests
from bs4 import BeautifulSoup
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target

_MAX_CONTENT_LENGTH = 2000
_TIMEOUT = 10  # seconds

_SESSION_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    ),
}


def _extract_text(html: str) -> str:
    """Extract meaningful text from HTML, stripping boilerplate tags."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()

    return "\n".join(
        text
        for tag in soup.find_all(["p", "h1", "h2", "h3", "h4", "h5", "h6"])
        if (text := tag.get_text(strip=True)) and len(text) > 20
    )


class WebpageExtractorInput(BaseModel):
    """Input schema for webpage content extraction."""

    url: str = Field(
        description="Full URL to extract content from (must include http:// or https://).",
    )


@tool(args_schema=WebpageExtractorInput)
def extract_webpage_content(url: str) -> dict[str, Any]:
    """Extract relevant text content from a web page, stripping HTML boilerplate.

    Useful for reading page content to identify technologies, organisation info,
    or intel from discovered web endpoints.
    """
    url, err = guard_target(url, "extract_webpage_content", TargetType.URL)
    if err:
        return err

    try:
        resp = requests.get(url, headers=_SESSION_HEADERS, timeout=_TIMEOUT)
        resp.raise_for_status()

        content_type = resp.headers.get("content-type", "").lower()
        if "text/html" not in content_type:
            return format_tool_output(
                "extract_webpage_content",
                url,
                "error",
                error=f"content is not HTML: {content_type}",
            )

        content = _extract_text(resp.text)
        if len(content) > _MAX_CONTENT_LENGTH:
            content = content[:_MAX_CONTENT_LENGTH] + "... (truncated)"

        return format_tool_output("extract_webpage_content", url, "ok", data={"content": content})

    except requests.exceptions.RequestException as exc:
        return format_tool_output("extract_webpage_content", url, "error", error=str(exc))
    except Exception as exc:
        return format_tool_output("extract_webpage_content", url, "error", error=str(exc))
