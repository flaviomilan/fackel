"""GitHub public-repository discovery.

Lists the public repositories of a GitHub organisation or user so they can be
fed to ``trufflehog_scan`` for leaked-secret scanning.  Without this, the
operator has to find the org's repos by hand — ``trufflehog_scan`` needs a
repo URL that nothing else produces.

Works **unauthenticated** (subject to GitHub's low anonymous rate limit); set
``GITHUB_TOKEN`` to raise the limit.  Queries GitHub's API only — never the
target — so it stays passive.
"""

from __future__ import annotations

import os
from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import format_tool_output, get_tool_timeout
from fackel.tooling.circuit_breaker import circuit_breaker
from fackel.tooling.http_client import get_session

_API_URL = "https://api.github.com"
_TIMEOUT = 20
_MAX_REPOS = 100


class GithubReposInput(BaseModel):
    """Input for GitHub repository discovery."""

    org: str = Field(
        description=(
            "GitHub organisation or user login to enumerate public repositories "
            "for (e.g. 'acme-corp'). Use the company's GitHub handle. Returned "
            "repository URLs can be fed to trufflehog_scan for secret scanning."
        ),
    )


def _slug(value: str) -> str:
    """Return the bare GitHub login from a handle or a github.com URL."""
    v = value.strip().rstrip("/")
    for prefix in ("https://github.com/", "http://github.com/", "github.com/", "@"):
        if v.lower().startswith(prefix):
            v = v[len(prefix) :]
            break
    return v.split("/")[0]


@tool(args_schema=GithubReposInput)
def github_repo_discovery(org: str) -> dict[str, Any]:
    """Discover the public GitHub repositories of an organisation or user.

    Lists public repos (most-recently-pushed first) for the given GitHub
    login.  Use the discovered ``html_url`` values as input to
    ``trufflehog_scan`` to hunt for leaked credentials in the target's code.
    Works without a key; ``GITHUB_TOKEN`` raises the rate limit.
    """
    login = _slug(org)
    if not login or "/" in login or any(c in login for c in " \t\n"):
        raise ToolException(f"github_repo_discovery: invalid GitHub login {org!r}")

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    import requests

    with circuit_breaker("github"):
        try:
            resp = get_session().get(
                f"{_API_URL}/users/{login}/repos",
                params={"per_page": str(_MAX_REPOS), "sort": "pushed", "type": "public"},
                timeout=get_tool_timeout("github_repo_discovery", _TIMEOUT),
                headers=headers,
            )
        except requests.RequestException as exc:
            raise ToolException(f"github_repo_discovery: request failed: {exc}") from exc

    if resp.status_code == 404:
        return format_tool_output(
            "github_repo_discovery",
            login,
            "ok",
            data={"repositories": [], "count": 0, "message": f"no public GitHub account '{login}'"},
        )
    if resp.status_code == 403:
        raise ToolException(
            "github_repo_discovery: rate limited by GitHub — set GITHUB_TOKEN to raise the limit"
        )

    try:
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise ToolException(f"github_repo_discovery: request failed: {exc}") from exc

    try:
        payload = resp.json()
    except ValueError:
        raise ToolException("github_repo_discovery: returned non-JSON response") from None

    if not isinstance(payload, list):
        raise ToolException("github_repo_discovery: unexpected response shape")

    repositories = [
        {
            "full_name": repo.get("full_name", ""),
            "html_url": repo.get("html_url", ""),
            "language": repo.get("language") or "",
            "pushed_at": repo.get("pushed_at", ""),
            "fork": bool(repo.get("fork", False)),
        }
        for repo in payload
        if isinstance(repo, dict)
    ]

    return format_tool_output(
        "github_repo_discovery",
        login,
        "ok",
        data={"repositories": repositories, "count": len(repositories)},
    )


github_repo_discovery.handle_tool_error = True
