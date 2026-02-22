"""GraphQL security scanner tool.

Tests GraphQL endpoints for common security misconfigurations:
introspection exposure, query batching, field suggestions, and
schema enumeration.
"""

from __future__ import annotations

import json
from typing import Any

import requests
from langchain_core.tools import tool

from .utils import format_tool_output

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


@tool
def graphql_scan(url: str) -> dict[str, Any]:
    """Scan a GraphQL endpoint for security misconfigurations.

    Tests for introspection exposure, query batching, field suggestion
    leaks, and schema enumeration. Use when Nuclei or httpx detected
    a GraphQL endpoint (paths like /graphql, /api/graphql, /v1/graphql).

    Args:
        url: Full URL of the GraphQL endpoint
             (e.g. "https://example.com/api/graphql").

    Returns:
        Dict with introspection status, schema summary (types, queries,
        mutations), batching support, and security observations.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "fackel-scanner/0.1",
    }
    issues: list[dict[str, str]] = []
    schema_summary: dict[str, Any] = {}

    # ── 1. Introspection ───────────────────────────────────────────────
    introspection_enabled = False
    try:
        resp = requests.post(
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
                introspection_enabled = True
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

                schema_summary = {
                    "total_types": len(user_types),
                    "type_names": [t["name"] for t in user_types[:50]],
                    "queries": queries[:30],
                    "mutations": mutations[:30],
                    "has_mutations": bool(mutations),
                }
                issues.append({
                    "issue": "Introspection enabled",
                    "severity": "medium",
                    "detail": (
                        f"Full schema exposed: {len(user_types)} types, "
                        f"{len(queries)} queries, {len(mutations)} mutations"
                    ),
                })
    except (requests.RequestException, json.JSONDecodeError, KeyError, TypeError):
        pass

    # ── 2. Alias-based batching ────────────────────────────────────────
    try:
        resp = requests.post(
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
                issues.append({
                    "issue": "Alias-based batching allowed",
                    "severity": "low",
                    "detail": (
                        "Multiple operations via aliases in a single request — "
                        "enables brute-force or DoS attacks"
                    ),
                })
    except (requests.RequestException, json.JSONDecodeError):
        pass

    # ── 3. Array-based batching ────────────────────────────────────────
    try:
        resp = requests.post(
            url,
            json=[{"query": "{ __typename }"}, {"query": "{ __typename }"}],
            headers=headers,
            timeout=_TIMEOUT,
            verify=True,
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) >= 2:
                issues.append({
                    "issue": "Array-based query batching allowed",
                    "severity": "low",
                    "detail": (
                        "Multiple queries accepted in array format — "
                        "enables batch brute-force attacks"
                    ),
                })
    except (requests.RequestException, json.JSONDecodeError):
        pass

    # ── 4. GET method queries ──────────────────────────────────────────
    try:
        resp = requests.get(
            url,
            params={"query": "{__typename}"},
            headers={"User-Agent": headers["User-Agent"]},
            timeout=_TIMEOUT,
            verify=True,
        )
        if resp.status_code == 200:
            data = resp.json()
            if (data.get("data") or {}).get("__typename"):
                issues.append({
                    "issue": "GET method queries allowed",
                    "severity": "info",
                    "detail": (
                        "GraphQL queries via GET may be cached or "
                        "logged in access logs, leaking query content"
                    ),
                })
    except (requests.RequestException, json.JSONDecodeError):
        pass

    # ── 5. Field suggestions ───────────────────────────────────────────
    try:
        resp = requests.post(
            url,
            json={"query": "{ __typo_name }"},
            headers=headers,
            timeout=_TIMEOUT,
            verify=True,
        )
        if resp.status_code in (200, 400):
            body = resp.text.lower()
            if "did you mean" in body or "suggestion" in body:
                issues.append({
                    "issue": "Field suggestions enabled",
                    "severity": "info",
                    "detail": (
                        "Server suggests valid field names on typos — "
                        "aids schema enumeration without introspection"
                    ),
                })
    except requests.RequestException:
        pass

    if not issues:
        return format_tool_output(
            "graphql_scan", url, "ok",
            data={
                "issues": [],
                "introspection_enabled": False,
                "message": "No GraphQL security issues detected",
            },
        )

    return format_tool_output(
        "graphql_scan", url, "ok",
        data={
            "introspection_enabled": introspection_enabled,
            "schema_summary": schema_summary,
            "issues": issues,
            "total_issues": len(issues),
        },
    )
