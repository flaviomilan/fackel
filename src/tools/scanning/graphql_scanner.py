"""GraphQL security scanner tool.

Tests GraphQL endpoints for common security misconfigurations:
introspection exposure, query batching, field suggestions, and
schema enumeration.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import requests
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target
from tools.http_client import get_session

logger = logging.getLogger(__name__)

_INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields { name }
    }
  }
}"""

_TIMEOUT = 30


class GraphqlInput(BaseModel):
    """Input for GraphQL security scanner."""

    url: str = Field(
        description=(
            "Full URL of the GraphQL endpoint "
            "(e.g. 'https://example.com/api/graphql'). "
            "Use when Nuclei or httpx detected a GraphQL endpoint — common "
            "paths: /graphql, /api/graphql, /v1/graphql, /gql."
        ),
    )


@tool(args_schema=GraphqlInput)
def graphql_scan(url: str) -> dict[str, Any]:
    """Scan a GraphQL endpoint for security misconfigurations.

    Tests for introspection exposure, alias/array query batching, field
    suggestion leaks, GET-method queries (CSRF risk), and schema enumeration.
    """
    url = guard_target(url, "graphql_scan", TargetType.URL)

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "fackel-scanner/0.1",
    }
    issues: list[dict[str, str]] = []
    schema_summary: dict[str, Any] = {}

    introspection_enabled, intro_issues, intro_schema = _probe_introspection(url, headers)
    issues.extend(intro_issues)
    schema_summary = intro_schema

    issues.extend(_probe_alias_batching(url, headers))
    issues.extend(_probe_array_batching(url, headers))
    issues.extend(_probe_get_method(url, headers))
    issues.extend(_probe_field_suggestions(url, headers))

    if not issues:
        return format_tool_output(
            "graphql_scan",
            url,
            "ok",
            data={
                "issues": [],
                "introspection_enabled": False,
                "message": "No GraphQL security issues detected",
            },
        )

    return format_tool_output(
        "graphql_scan",
        url,
        "ok",
        data={
            "introspection_enabled": introspection_enabled,
            "schema_summary": schema_summary,
            "issues": issues,
            "total_issues": len(issues),
        },
    )


graphql_scan.handle_tool_error = True


def _probe_introspection(
    url: str,
    headers: dict[str, str],
) -> tuple[bool, list[dict[str, str]], dict[str, Any]]:
    """Test for introspection exposure. Returns (enabled, issues, schema_summary)."""
    try:
        resp = get_session().post(
            url,
            json={"query": _INTROSPECTION_QUERY},
            headers=headers,
            timeout=_TIMEOUT,
            verify=True,
        )
        if resp.status_code == 200:
            data = resp.json()
            schema = (data.get("data") or {}).get("__schema")
            if schema:
                types = schema.get("types", [])
                user_types = [t for t in types if not t["name"].startswith("__")]
                query_type = schema.get("queryType") or {}
                mutation_type = schema.get("mutationType")

                queries: list[str] = []
                mutations: list[str] = []
                for t in types:
                    if query_type and t["name"] == query_type.get("name"):
                        queries = [f["name"] for f in (t.get("fields") or [])]
                    if mutation_type and t["name"] == mutation_type.get("name"):
                        mutations = [f["name"] for f in (t.get("fields") or [])]

                summary = {
                    "total_types": len(user_types),
                    "type_names": [t["name"] for t in user_types[:50]],
                    "queries": queries[:30],
                    "mutations": mutations[:30],
                    "has_mutations": bool(mutations),
                }
                issue = {
                    "issue": "Introspection enabled",
                    "severity": "medium",
                    "detail": (
                        f"Full schema exposed: {len(user_types)} types, "
                        f"{len(queries)} queries, {len(mutations)} mutations"
                    ),
                }
                return True, [issue], summary
    except (requests.RequestException, json.JSONDecodeError, KeyError, TypeError):
        logger.debug("introspection probe failed for %s", url, exc_info=True)
    return False, [], {}


def _probe_alias_batching(
    url: str,
    headers: dict[str, str],
) -> list[dict[str, str]]:
    """Test for alias-based query batching."""
    try:
        resp = get_session().post(
            url,
            json={"query": "{ a: __typename b: __typename c: __typename }"},
            headers=headers,
            timeout=_TIMEOUT,
            verify=True,
        )
        if resp.status_code == 200:
            data = resp.json()
            d = data.get("data") or {}
            if d.get("a") and d.get("b"):
                return [
                    {
                        "issue": "Alias-based batching allowed",
                        "severity": "low",
                        "detail": (
                            "Multiple operations via aliases in a single request — "
                            "enables brute-force or DoS attacks"
                        ),
                    }
                ]
    except (requests.RequestException, json.JSONDecodeError):
        logger.debug("alias batching probe failed for %s", url, exc_info=True)
    return []


def _probe_array_batching(
    url: str,
    headers: dict[str, str],
) -> list[dict[str, str]]:
    """Test for array-based query batching."""
    try:
        resp = get_session().post(
            url,
            json=[{"query": "{ __typename }"}, {"query": "{ __typename }"}],
            headers=headers,
            timeout=_TIMEOUT,
            verify=True,
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) >= 2:
                return [
                    {
                        "issue": "Array-based query batching allowed",
                        "severity": "low",
                        "detail": (
                            "Multiple queries accepted in array format — "
                            "enables batch brute-force attacks"
                        ),
                    }
                ]
    except (requests.RequestException, json.JSONDecodeError):
        logger.debug("array batching probe failed for %s", url, exc_info=True)
    return []


def _probe_get_method(
    url: str,
    headers: dict[str, str],
) -> list[dict[str, str]]:
    """Test for GET method query support (CSRF risk)."""
    try:
        resp = get_session().get(
            url,
            params={"query": "{__typename}"},
            headers={"User-Agent": headers["User-Agent"]},
            timeout=_TIMEOUT,
            verify=True,
        )
        if resp.status_code == 200:
            data = resp.json()
            if (data.get("data") or {}).get("__typename"):
                return [
                    {
                        "issue": "GET method queries allowed",
                        "severity": "info",
                        "detail": (
                            "GraphQL queries via GET may be cached or "
                            "logged in access logs, leaking query content"
                        ),
                    }
                ]
    except (requests.RequestException, json.JSONDecodeError):
        logger.debug("GET method probe failed for %s", url, exc_info=True)
    return []


def _probe_field_suggestions(
    url: str,
    headers: dict[str, str],
) -> list[dict[str, str]]:
    """Test for field suggestion leaks."""
    try:
        resp = get_session().post(
            url,
            json={"query": "{ __typo_name }"},
            headers=headers,
            timeout=_TIMEOUT,
            verify=True,
        )
        if resp.status_code in (200, 400):
            body = resp.text.lower()
            if "did you mean" in body or "suggestion" in body:
                return [
                    {
                        "issue": "Field suggestions enabled",
                        "severity": "info",
                        "detail": (
                            "Server suggests valid field names on typos — "
                            "aids schema enumeration without introspection"
                        ),
                    }
                ]
    except requests.RequestException:
        logger.debug("field suggestion probe failed for %s", url, exc_info=True)
    return []
