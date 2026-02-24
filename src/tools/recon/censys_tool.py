"""Censys host/service search via the Censys REST API.

Requires ``CENSYS_API_ID`` and ``CENSYS_API_SECRET`` environment variables.
"""

from __future__ import annotations

from censys.search import CensysHosts
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target, require_env


class CensysInput(BaseModel):
    """Input schema for Censys host lookup."""

    domain: str = Field(
        description="Domain or IP to search in Censys host database.",
    )


@tool(args_schema=CensysInput)
def censys_lookup(domain: str) -> dict:
    """Search host and service data via the Censys REST API."""
    domain, err = guard_target(domain, "censys_lookup", TargetType.HOST)
    if err:
        return err

    api_id, id_err = require_env("CENSYS_API_ID", "censys_lookup", domain)
    if id_err:
        return id_err
    api_secret, sec_err = require_env("CENSYS_API_SECRET", "censys_lookup", domain)
    if sec_err:
        return sec_err

    try:
        client = CensysHosts(api_id=api_id, api_secret=api_secret)
        query = f"services.tls.certificates.leaf_data.subject.common_name: {domain} OR services.tls.certificates.leaf_data.subject.organization: {domain}"
        results = client.search(query, per_page=5)

        hosts: list[dict] = []
        for host in results:
            services = []
            for service in host.get("services", []):
                svc = {
                    "port": service.get("port"),
                    "protocol": service.get("transport_protocol"),
                    "name": service.get("service_name"),
                }
                services.append(svc)

            hosts.append(
                {
                    "ip": host.get("ip"),
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
        return format_tool_output(
            "censys_lookup",
            domain,
            "error",
            error=f"Censys query failed: {e}",
        )
