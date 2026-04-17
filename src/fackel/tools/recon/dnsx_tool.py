"""dnsx — fast bulk DNS resolution and wildcard filtering.

Wraps ProjectDiscovery's ``dnsx`` to resolve a whole set of discovered
subdomains in a single pass, returning only the ones that actually resolve
(with their A records) and filtering wildcard-DNS noise.  This turns the raw,
multi-source subdomain list into a validated, resolvable host set so later
phases don't waste budget on dead names — and surfaces names that *don't*
resolve as subdomain-takeover candidates.

Resolution only (no traffic to the target's services) — stays passive.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    format_tool_output,
    get_tool_timeout,
    guard_target,
    is_valid_domain,
    parse_jsonl,
    require_binary,
    run_command,
)

_TIMEOUT = 120
_MAX_HOSTS = 5000


class DnsxInput(BaseModel):
    """Input for dnsx bulk resolution."""

    hosts: list[str] = Field(
        description=(
            "List of hostnames/subdomains to resolve in one batch (e.g. the "
            "subdomains discovered by subfinder/amass/crt.sh). dnsx resolves "
            "all of them at once, returns the ones with A records, and filters "
            "wildcard DNS. Names that do not resolve are reported separately as "
            "subdomain-takeover candidates."
        ),
    )
    wildcard_domain: str = Field(
        default="",
        description=(
            "Optional base domain (e.g. 'example.com') to enable wildcard-DNS "
            "detection and filtering. Set it when resolving subdomains of a "
            "single apex domain so wildcard responses are removed."
        ),
    )


@tool(args_schema=DnsxInput)
def dnsx_resolve(hosts: list[str], wildcard_domain: str = "") -> dict[str, Any]:
    """Bulk-resolve hostnames and filter wildcard DNS with dnsx.

    Resolves every supplied hostname in a single pass, returning each
    resolvable host with its A records and listing the unresolved ones as
    takeover candidates.  When ``wildcard_domain`` is given, wildcard-DNS
    responses are detected and filtered out.  Use after subdomain enumeration
    to validate the discovered set before downstream scanning.
    """
    require_binary("dnsx", "dnsx_resolve")

    clean = sorted(
        {h.strip().lower().rstrip(".") for h in hosts if h and is_valid_domain(h.strip())}
    )
    if not clean:
        return format_tool_output(
            "dnsx_resolve",
            wildcard_domain or "dnsx",
            "ok",
            data={
                "hosts": [],
                "resolved": 0,
                "unresolved": [],
                "message": "no valid hostnames given",
            },
        )
    clean = clean[:_MAX_HOSTS]

    wildcard = ""
    if wildcard_domain:
        wildcard = guard_target(wildcard_domain, "dnsx_resolve", TargetType.DOMAIN)

    fd, tmp_path = tempfile.mkstemp(suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(clean))

        cmd = ["dnsx", "-l", tmp_path, "-json", "-a", "-resp", "-silent"]
        if wildcard:
            cmd += ["-wd", wildcard]

        try:
            code, out, stderr = run_command(cmd, timeout=get_tool_timeout("dnsx_resolve", _TIMEOUT))
        except Exception as exc:
            raise ToolException(f"dnsx_resolve: {exc}") from exc
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)

    resolved_hosts: list[dict[str, str]] = []
    resolved_names: set[str] = set()
    for entry in parse_jsonl(out):
        host = str(entry.get("host", "")).strip().lower().rstrip(".")
        if not host:
            continue
        resolved_names.add(host)
        a_records = entry.get("a") or []
        if isinstance(a_records, list) and a_records:
            for ip in a_records:
                # `hostname`/`ip` keys are the shape the orchestrator's
                # extractors and translators already parse → automatic parity.
                resolved_hosts.append({"hostname": host, "ip": str(ip)})
        else:
            resolved_hosts.append({"hostname": host, "ip": ""})

    if not resolved_hosts and code:
        raise ToolException(f"dnsx_resolve: {stderr.strip() or 'resolution failed'}")

    unresolved = [h for h in clean if h not in resolved_names]

    return format_tool_output(
        "dnsx_resolve",
        wildcard or "dnsx",
        "ok",
        data={
            "hosts": resolved_hosts,
            "resolved": len(resolved_names),
            "input_count": len(clean),
            "unresolved": unresolved,
            "unresolved_count": len(unresolved),
            "wildcard_filtered": bool(wildcard),
        },
    )


dnsx_resolve.handle_tool_error = True
