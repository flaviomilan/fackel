"""FOFA asset search engine — passive host/service discovery.

Queries the FOFA REST API for hosts, services, and technologies matching
a domain or IP.  Requires ``FOFA_EMAIL`` and ``FOFA_KEY`` environment
variables.
"""

from __future__ import annotations

import contextlib
from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import format_tool_output, require_env
from fackel.tooling.circuit_breaker import circuit_breaker
from fackel.tooling.http_client import get_session

_API_BASE = "https://en.fofa.info/api/v1/search/all"
_MAX_RESULTS = 100


_ACCOUNT_ERROR_CODES = frozenset({820031, -700})


class FofaInput(BaseModel):
    """Input for FOFA asset search."""

    query: str = Field(
        description=(
            "FOFA query string. Use 'domain=' prefix for domain searches "
            "(e.g. 'domain=example.com'), 'ip=' for IP lookups "
            "(e.g. 'ip=1.2.3.4'), or raw FOFA dork syntax "
            '(e.g. \'header="Apache" && country="BR"\'). '
            "See https://en.fofa.info/api for full query syntax."
        ),
    )


@tool(args_schema=FofaInput)
def fofa_search(query: str) -> dict[str, Any]:
    """Search FOFA for internet-connected assets — no packets sent to the target.

    Discovers hosts, open ports, services, technologies, and certificates
    indexed by FOFA's global scan engine.  Useful for passive reconnaissance
    alongside Shodan and Censys.
    Requires FOFA_EMAIL and FOFA_KEY environment variables.
    """
    email = require_env("FOFA_EMAIL", "fofa_search")
    api_key = require_env("FOFA_KEY", "fofa_search")

    import base64

    encoded_query = base64.b64encode(query.encode()).decode()

    params = {
        "email": email,
        "key": api_key,
        "qbase64": encoded_query,
        "size": _MAX_RESULTS,
        "fields": "host,ip,port,protocol,server,title,domain,as_organization,banner",
    }

    try:
        with circuit_breaker("fofa"):
            resp = get_session().get(_API_BASE, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
    except ToolException:
        raise
    except Exception as exc:
        raise ToolException(f"fofa_search: FOFA API request failed: {exc}") from exc

    if data.get("error") and data.get("errmsg"):
        errmsg = data["errmsg"]
        # Extract numeric error code from "[820031] ..." format.
        code = None
        if errmsg.startswith("["):
            with contextlib.suppress(ValueError, IndexError):
                code = int(errmsg.split("]")[0].lstrip("["))
        if code in _ACCOUNT_ERROR_CODES:
            raise ToolException(
                f"fofa_search: FOFA account error — {errmsg}. "
                "Check your FOFA subscription and F-point balance at https://en.fofa.info."
            )
        raise ToolException(f"fofa_search: FOFA API error: {errmsg}")

    results_raw = data.get("results", [])
    field_names = [
        "host",
        "ip",
        "port",
        "protocol",
        "server",
        "title",
        "domain",
        "as_organization",
        "banner",
    ]

    results: list[dict[str, Any]] = []
    for row in results_raw:
        if isinstance(row, list) and len(row) == len(field_names):
            entry: dict[str, Any] = {}
            for i, name in enumerate(field_names):
                val = row[i]
                if name == "banner" and isinstance(val, str):
                    val = val[:300]
                entry[name] = val
            results.append(entry)

    return format_tool_output(
        "fofa_search",
        query,
        "ok",
        data={
            "total": data.get("size", len(results)),
            "results": results,
        },
    )


fofa_search.handle_tool_error = True  # type: ignore[attr-defined]
