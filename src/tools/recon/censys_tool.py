"""Censys host/service search via the Censys REST API.

Requires ``CENSYS_API_ID`` and ``CENSYS_API_SECRET`` environment variables.
"""

from __future__ import annotations

from typing import Any

from censys.search import CensysHosts
from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target, require_env


class CensysInput(BaseModel):
    """Input schema for Censys host lookup."""

    domain: str = Field(
        description="Domain or IP to search in Censys host database.",
    )


@tool(args_schema=CensysInput)
def censys_lookup(domain: str) -> dict[str, Any]:
    """Search host and service data via the Censys REST API."""
    domain = guard_target(domain, "censys_lookup", TargetType.HOST)

    api_id = require_env("CENSYS_API_ID", "censys_lookup")
    api_secret = require_env("CENSYS_API_SECRET", "censys_lookup")

    try:
        client = CensysHosts(api_id=api_id, api_secret=api_secret)
        query = f"services.tls.certificates.leaf_data.subject.common_name: {domain} OR services.tls.certificates.leaf_data.subject.organization: {domain}"
        results = client.search(query, per_page=5)

        hosts: list[dict[str, Any]] = []
        for host in results:
            host_data: dict[str, Any] = dict(host)  # type: ignore[arg-type]
            services = []
            for service in host_data.get("services", []):
                svc = {
                    "port": service.get("port"),
                    "protocol": service.get("transport_protocol"),
                    "name": service.get("service_name"),
                }
                services.append(svc)

            hosts.append(
                {
                    "ip": host_data.get("ip"),
                    "services": services,
                }
            )

        return format_tool_output(
            "censys_lookup",
            domain,
            "ok",
            data={"hosts": hosts},
        )

    except Exception as e:
        raise ToolException(f"censys_lookup: Censys query failed: {e}") from e


censys_lookup.handle_tool_error = True
