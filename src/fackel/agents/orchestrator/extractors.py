"""Message payload extractors for orchestrator graph nodes.

Each function extracts structured data from ``ToolMessage`` payloads
produced by specialist ReAct agents.  The shared ``iter_tool_payloads``
generator eliminates repeated JSON-parsing boilerplate across extractors.

**Pipeline role:** these extractors feed the LangGraph ``ScanState`` — the
*routing* data that decides what the next phase scans (discovered IPs,
subdomains, classifications, fingerprints).  A second pipeline,
``orchestrator.translators``, turns the *same* tool payloads into
provenance-rich ``InformationCandidate`` records for the ``InformationStore``
(persistence, the judge, and the report).

The two serve different needs (no-store state projection vs per-message,
provenance-tracked store candidates), so they remain separate thin adapters —
**but the actual payload-parsing primitives live here once** (``raw_ips_from_payload``,
``normalize_subdomain``, ``parse_httpx_entry``, ``merge_ip_classification_fields``,
``build_classification_attrs``) and are imported by ``translators`` so the logic
is not duplicated.  ``tests/agents/test_node_extractors.py::TestExtractionParity``
guards that both pipelines still agree on IPs and subdomains.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterator
from typing import Any

from langchain_core.messages import ToolMessage

from fackel.tooling import is_reverse_ptr_subdomain, is_valid_domain, is_valid_ip
from fackel.tooling.ip_classifier import classify_ip

logger = logging.getLogger(__name__)


def iter_tool_payloads(
    messages: list[Any],
    *,
    tool_name: str | None = None,
    require_ok: bool = False,
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(tool_name, data_dict)`` for each valid ToolMessage payload.

    Handles JSON parsing, non-dict filtering, and the standard
    ``format_tool_output`` envelope (``{"tool": …, "status": …, "data": {…}}``).
    The inner ``data`` dict is yielded directly.

    Parameters
    ----------
    tool_name:
        When set, only payloads from this tool are yielded.
    require_ok:
        When True, only payloads with ``status == "ok"`` are yielded.
    """
    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        try:
            payload = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
            if not isinstance(payload, dict):
                continue
            name = payload.get("tool", getattr(msg, "name", "") or "")
            if tool_name and name != tool_name:
                continue
            if require_ok and payload.get("status") != "ok":
                continue
            inner = payload.get("data", payload)
            if not isinstance(inner, dict):
                continue
            yield name, inner
        except (json.JSONDecodeError, TypeError, AttributeError):
            logger.debug(
                "skipping unparseable ToolMessage: %s",
                msg.content[:120] if hasattr(msg, "content") else "",
            )
            continue


def _add_unique_ip(ips: list[str], value: object) -> None:
    """Append a validated, unique IP to *ips*."""
    ip_str = str(value).strip()
    if ip_str and ip_str not in ips and is_valid_ip(ip_str):
        ips.append(ip_str)


# --- shared payload-parsing primitives (also used by ``translators``) ---


def raw_ips_from_payload(data: dict[str, Any]) -> list[str]:
    """Collect candidate IP strings from one tool payload — unvalidated, ordered.

    Covers ``ips``, ``hosts[*].ip``, a top-level ``ip``, and ``matches[*].ip``.
    Callers validate (``is_valid_ip``) and de-duplicate.  Shared so both the
    state extractor and the store translator pull IPs identically.
    """
    raw: list[str] = []
    for ip in data.get("ips", []) or []:
        raw.append(str(ip).strip())
    for host in data.get("hosts", []) or []:
        if isinstance(host, dict) and "ip" in host:
            raw.append(str(host["ip"]).strip())
    if isinstance(data.get("ip"), str):
        raw.append(data["ip"].strip())
    for match in data.get("matches", []) or []:
        if isinstance(match, dict) and "ip" in match:
            raw.append(str(match["ip"]).strip())
    return raw


def normalize_subdomain(value: object, base_lower: str) -> str | None:
    """Normalise + scope-filter a subdomain candidate, or ``None`` if rejected.

    Lower-cased, trailing dot and ``*.`` stripped; must be in-scope
    (``*.base_lower``), a valid domain, and not a reverse-PTR host.  Shared so
    both pipelines accept/reject subdomains identically.
    """
    host = str(value).strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if (
        host
        and host != base_lower
        and host.endswith(f".{base_lower}")
        and is_valid_domain(host)
        and not is_reverse_ptr_subdomain(host)
    ):
        return host
    return None


def _subdomain_collector(base_domain: str) -> tuple[list[str], Callable[[object], None]]:
    """Return ``(collection, add_fn)`` for deduplicated subdomain accumulation."""
    subs: list[str] = []
    base_lower = base_domain.lower()

    def _add(value: object) -> None:
        host = normalize_subdomain(value, base_lower)
        if host and host not in subs:
            subs.append(host)

    return subs, _add


def extract_ips(messages: list[Any]) -> list[str]:
    """Pull IP addresses from ToolMessage payloads across all OSINT tools.

    Handles:
    - ``dns_resolve`` — ``data.ips``
    - ``dnsdumpster_lookup`` — ``data.hosts[*].ip``
    - ``shodan_lookup`` (host) — ``data.ip``
    - ``shodan_lookup`` (search) — ``data.matches[*].ip``
    - ``censys_lookup`` — ``data.hosts[*].ip``
    """
    ips: list[str] = []
    for _tool, data in iter_tool_payloads(messages):
        for ip in raw_ips_from_payload(data):
            _add_unique_ip(ips, ip)
    return ips


def extract_subdomains(messages: list[Any], base_domain: str) -> list[str]:
    """Pull subdomain hostnames from ToolMessage payloads.

    Extracts from ``crtsh``, ``virustotal``, ``subfinder``, and
    ``dnsdumpster`` outputs.  Reverse-PTR-style subdomains are filtered.
    """
    subs, add = _subdomain_collector(base_domain)
    for _tool, data in iter_tool_payloads(messages):
        for sub in data.get("subdomains", []):
            add(sub)
        for host in data.get("hosts", []):
            if isinstance(host, dict) and "hostname" in host:
                add(host["hostname"])
        for detail in data.get("details", []):
            if isinstance(detail, dict) and "subdomain" in detail:
                add(detail["subdomain"])
    return sorted(subs)


def merge_ip_classification_fields(
    entry: dict[str, Any],
    tool: str,
    data: dict[str, Any],
) -> None:
    """Merge ipinfo / BGP fields from one payload into a per-IP aggregate (in place).

    Shared so both pipelines build the same per-IP classification record; the
    *policy* of which tools register an IP stays with each caller.
    """
    if tool == "ipinfo_lookup":
        entry.update(
            {
                "org": data.get("org", ""),
                "asn": data.get("asn", ""),
                "hostname": data.get("hostname", ""),
                "anycast": data.get("anycast", False),
                "city": data.get("city", ""),
                "country": data.get("country", ""),
            }
        )
    elif tool == "bgp_lookup":
        entry.setdefault("org", "")
        entry.update(
            {
                "asn_name": data.get("asn_name", ""),
                "asn_description": data.get("asn_description", ""),
                "prefix": data.get("prefix", ""),
                "rir": data.get("rir", ""),
            }
        )
        entry.setdefault("asn", data.get("asn", ""))


def build_classification_attrs(
    ip: str,
    data: dict[str, Any],
    target_domain: str,
) -> dict[str, Any]:
    """Classify *ip* from its aggregated fields and return the attribute dict.

    Shared by the state extractor and the store translator.
    """
    ip_class = classify_ip(
        org=data.get("org", ""),
        asn=data.get("asn"),
        asn_name=data.get("asn_name", ""),
        hostname=data.get("hostname", ""),
        anycast=bool(data.get("anycast", False)),
        target_domain=target_domain,
    )
    return {
        "ip": ip,
        "ip_class": ip_class,
        "org": data.get("org", ""),
        "asn": str(data.get("asn", "")),
        "asn_name": data.get("asn_name", ""),
        "country": data.get("country", ""),
        "anycast": bool(data.get("anycast", False)),
    }


def _collect_ip_data(messages: list[Any]) -> dict[str, dict[str, Any]]:
    """Aggregate per-IP fields from ipinfo and BGP tool outputs."""
    ip_data: dict[str, dict[str, Any]] = {}
    for tool, data in iter_tool_payloads(messages):
        ip_key = data.get("ip", "")
        if not ip_key:
            continue
        entry = ip_data.setdefault(ip_key, {})
        merge_ip_classification_fields(entry, tool, data)
    return ip_data


def extract_ip_classifications(
    messages: list[Any],
    target_domain: str,
) -> list[dict[str, Any]]:
    """Build IP classification entries from ipinfo/BGP ToolMessage payloads.

    For each IP with an ipinfo result, ``classify_ip`` determines the
    infrastructure class (cdn / cloud / direct_host / isp).
    """
    ip_data = _collect_ip_data(messages)
    return [build_classification_attrs(ip, data, target_domain) for ip, data in ip_data.items()]


def parse_httpx_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Normalise a single httpx result entry into a fingerprint dict."""
    url = entry.get("url", entry.get("input", ""))
    if not url:
        return None
    techs = entry.get("tech", [])
    if isinstance(techs, str):
        techs = [techs]
    tls_raw = entry.get("tls", {})
    tls_info = (
        {"version": tls_raw.get("version", ""), "cipher": tls_raw.get("cipher", "")}
        if isinstance(tls_raw, dict)
        else {"version": "", "cipher": ""}
    )
    return {
        "target": url,
        "host": entry.get("host", entry.get("input", "")),
        "status_code": entry.get("status_code", entry.get("status-code")),
        "server": entry.get("webserver", entry.get("server", "")),
        "title": entry.get("title", ""),
        "technologies": techs or [],
        "content_type": entry.get("content_type", entry.get("content-type", "")),
        "redirect_chain": entry.get("chain", []),
        "tls": tls_info,
        "cdn": entry.get("cdn", False),
        "waf": entry.get("waf", ""),
    }


def extract_tech_fingerprints(messages: list[Any]) -> list[dict[str, Any]]:
    """Build tech fingerprint entries from httpx_scan ToolMessage payloads."""
    fingerprints: list[dict[str, Any]] = []
    seen: set[str] = set()
    for _tool, data in iter_tool_payloads(messages, tool_name="httpx_scan", require_ok=True):
        results = data.get("results", [])
        if not isinstance(results, list):
            continue
        for entry in results:
            if not isinstance(entry, dict):
                continue
            fp = parse_httpx_entry(entry)
            if fp and fp["target"] not in seen:
                seen.add(fp["target"])
                fingerprints.append(fp)
    return fingerprints


def extract_historical_ips(
    messages: list[Any],
    current_ips: list[str],
) -> list[str]:
    """Pull historical A-record IPs not in *current_ips* from securitytrails.

    These are potential direct-origin candidates that may bypass CDN protection.
    """
    historical: list[str] = []
    for _tool, data in iter_tool_payloads(
        messages,
        tool_name="securitytrails_history",
        require_ok=True,
    ):
        for record in data.get("a_records", []):
            if not isinstance(record, dict):
                continue
            ip_str = str(record.get("value", "")).strip()
            if (
                ip_str
                and ip_str not in historical
                and ip_str not in current_ips
                and is_valid_ip(ip_str)
            ):
                historical.append(ip_str)
    return historical


def extract_san_domains(messages: list[Any], base_domain: str) -> list[str]:
    """Pull SAN domains from tlscert_lookup ToolMessage payloads.

    Wildcard prefixes (``*.``) are stripped before validation.
    """
    subs, add = _subdomain_collector(base_domain)
    for _tool, data in iter_tool_payloads(
        messages,
        tool_name="tlscert_lookup",
        require_ok=True,
    ):
        for san in data.get("san_domains", []):
            add(san)
    return sorted(subs)
