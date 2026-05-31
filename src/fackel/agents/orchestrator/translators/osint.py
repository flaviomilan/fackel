"""OSINT-phase translators: tool payloads → information & edge candidates.

This module owns everything OSINT-specific — the per-record candidate builders,
the people/document/social emitters, and the knowledge-graph edge inference.
Shared low-level primitives live in :mod:`._common`; the generic payload
parsers (``raw_ips_from_payload`` etc.) live in :mod:`..extractors` and are
shared with the ``ScanState`` extraction pipeline (parity is guarded by
``tests/agents/test_node_extractors.py::TestExtractionParity``).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from langchain_core.messages import ToolMessage

from fackel.domain import (
    EdgeCandidate,
    InformationCandidate,
    InformationType,
    RelationshipType,
    fingerprint,
)
from fackel.tooling import is_valid_domain, is_valid_ip

from ..extractors import (
    build_classification_attrs,
    merge_ip_classification_fields,
    normalize_subdomain,
    parse_httpx_entry,
    raw_ips_from_payload,
)
from ._common import _iter_tool_messages, _make

# ----------------------------------------------------------------------
# Per-record candidate builders


def _osint_ip_candidates(
    msg: ToolMessage,
    tool_name: str,
    data: dict[str, Any],
    seen: set[str],
) -> list[InformationCandidate]:
    out: list[InformationCandidate] = []
    for ip in raw_ips_from_payload(data):
        if not ip or not is_valid_ip(ip):
            continue
        key = f"ip:{ip}"
        if key in seen:
            continue
        seen.add(key)
        out.append(
            _make(
                InformationType.IP_ADDRESS,
                normalized_value=ip,
                original_value=ip,
                attributes={},
                msg=msg,
                tool_name=tool_name,
                phase="osint",
            )
        )
    return out


def _osint_subdomain_candidates(
    msg: ToolMessage,
    tool_name: str,
    data: dict[str, Any],
    base_domain: str,
    seen: set[str],
) -> list[InformationCandidate]:
    base_lower = base_domain.lower()
    raw_subs: list[str] = []
    for sub in data.get("subdomains", []) or []:
        raw_subs.append(str(sub))
    for host in data.get("hosts", []) or []:
        if isinstance(host, dict) and "hostname" in host:
            raw_subs.append(str(host["hostname"]))
    for detail in data.get("details", []) or []:
        if isinstance(detail, dict) and "subdomain" in detail:
            raw_subs.append(str(detail["subdomain"]))

    out: list[InformationCandidate] = []
    for raw in raw_subs:
        host = normalize_subdomain(raw, base_lower)
        if not host:
            continue
        key = f"sub:{host}"
        if key in seen:
            continue
        seen.add(key)
        out.append(
            _make(
                InformationType.SUBDOMAIN,
                normalized_value=host,
                original_value=raw,
                attributes={},
                msg=msg,
                tool_name=tool_name,
                phase="osint",
            )
        )
    return out


def _osint_san_candidates(
    msg: ToolMessage,
    tool_name: str,
    data: dict[str, Any],
    base_domain: str,
    seen: set[str],
) -> list[InformationCandidate]:
    if tool_name != "tlscert_lookup":
        return []
    base_lower = base_domain.lower()
    out: list[InformationCandidate] = []
    for raw in data.get("san_domains", []) or []:
        host = normalize_subdomain(raw, base_lower)
        if not host:
            continue
        key = f"san:{host}"
        if key in seen:
            continue
        seen.add(key)
        out.append(
            _make(
                InformationType.TLS_SAN_DOMAIN,
                normalized_value=host,
                original_value=str(raw),
                attributes={},
                msg=msg,
                tool_name=tool_name,
                phase="osint",
            )
        )
    return out


def _osint_historical_ip_candidates(
    msg: ToolMessage,
    tool_name: str,
    data: dict[str, Any],
    seen: set[str],
) -> list[InformationCandidate]:
    if tool_name != "securitytrails_history":
        return []
    out: list[InformationCandidate] = []
    for record in data.get("a_records", []) or []:
        if not isinstance(record, dict):
            continue
        ip = str(record.get("value", "")).strip()
        if not ip or not is_valid_ip(ip):
            continue
        key = f"hist:{ip}"
        if key in seen:
            continue
        seen.add(key)
        out.append(
            _make(
                InformationType.HISTORICAL_IP_ADDRESS,
                normalized_value=ip,
                original_value=ip,
                attributes={"first_seen": record.get("first_seen", "")},
                msg=msg,
                tool_name=tool_name,
                phase="osint",
            )
        )
    return out


def _osint_classification_candidates(
    messages: list[Any],
    target: str,
) -> list[InformationCandidate]:
    """Aggregate ipinfo + bgp results into one IP_CLASSIFICATION per IP.

    Field-merge and attribute-building reuse the shared primitives in
    ``extractors``; the translator adds per-IP source provenance (ipinfo
    execution id wins when present).  ipinfo / bgp contribute infra fields and
    greynoise / abuseipdb contribute reputation fields; every registering tool
    sets a source message so each entry has provenance.
    """
    per_ip: dict[str, dict[str, Any]] = {}
    source_msg: dict[str, ToolMessage] = {}
    source_tool: dict[str, str] = {}
    classifying_tools = (
        "ipinfo_lookup",
        "bgp_lookup",
        "greynoise_lookup",
        "abuseipdb_lookup",
    )
    for msg, tool, data in _iter_tool_messages(messages):
        if tool not in classifying_tools:
            continue
        ip = str(data.get("ip", "")).strip()
        if not ip or not is_valid_ip(ip):
            continue
        entry = per_ip.setdefault(ip, {})
        merge_ip_classification_fields(entry, tool, data)
        # ipinfo wins provenance (richest infra fields); the others only fill in.
        if tool == "ipinfo_lookup":
            source_msg[ip] = msg
            source_tool[ip] = tool
        else:
            source_msg.setdefault(ip, msg)
            source_tool.setdefault(ip, tool)

    return [
        _make(
            InformationType.IP_CLASSIFICATION,
            normalized_value=ip,
            original_value=ip,
            attributes=build_classification_attrs(ip, data, target),
            msg=source_msg[ip],
            tool_name=source_tool[ip],
            phase="osint",
        )
        for ip, data in per_ip.items()
    ]


def _osint_tech_fingerprint_candidates(
    messages: list[Any],
) -> list[InformationCandidate]:
    out: list[InformationCandidate] = []
    seen: set[str] = set()
    for msg, tool, data in _iter_tool_messages(messages):
        if tool != "httpx_scan":
            continue
        results = data.get("results", [])
        if not isinstance(results, list):
            continue
        for entry in results:
            if not isinstance(entry, dict):
                continue
            fp = parse_httpx_entry(entry)
            if fp is None:
                continue
            url = fp["target"]
            if url in seen:
                continue
            seen.add(url)
            out.append(
                _make(
                    InformationType.TECH_FINGERPRINT,
                    normalized_value=url,
                    original_value=url,
                    attributes=fp,
                    msg=msg,
                    tool_name=tool,
                    phase="osint",
                )
            )
    return out


# ----------------------------------------------------------------------
# People / document / social emitters


def _emit_breach_lookup_leaks(
    data: dict[str, Any],
    msg: ToolMessage,
    tool: str,
    emit: Callable[..., None],
) -> None:
    """Emit EMAIL + CREDENTIAL_LEAK candidates from breach_lookup output."""
    addr = str(data.get("email", "")).strip().lower()
    if not addr or "@" not in addr:
        return
    emit(InformationType.EMAIL, f"email:{addr}", addr, addr, {}, msg, tool)
    for breach in data.get("breaches", []) or []:
        if not isinstance(breach, dict):
            continue
        name = str(breach.get("name", "")).strip()
        if not name:
            continue
        emit(
            InformationType.CREDENTIAL_LEAK,
            f"leak:{addr}:{name.lower()}",
            f"{addr}:{name}",
            f"{addr}:{name}",
            {"breach": name, "email": addr, "date": breach.get("date", "")},
            msg,
            tool,
        )


def _emit_analyze_email_leaks(
    data: dict[str, Any],
    msg: ToolMessage,
    tool: str,
    emit: Callable[..., None],
) -> None:
    """Emit EMAIL + CREDENTIAL_LEAK candidates from analyze_email (HIBP) output."""
    addr = str(data.get("email", "")).strip().lower()
    if not addr or "@" not in addr:
        return
    emit(InformationType.EMAIL, f"email:{addr}", addr, addr, {}, msg, tool)
    for breach in data.get("breaches", []) or []:
        if isinstance(breach, dict):
            breach_name = str(breach.get("Name") or breach.get("name") or breach.get("Title") or "")
        else:
            breach_name = str(breach)
        if breach_name:
            emit(
                InformationType.CREDENTIAL_LEAK,
                f"leak:{addr}:{breach_name.lower()}",
                f"{addr}:{breach_name}",
                f"{addr}:{breach_name}",
                {"breach": breach_name, "email": addr},
                msg,
                tool,
            )


def _osint_people_candidates(
    messages: list[Any],
    seen: set[str],
) -> list[InformationCandidate]:
    """Extract people/organisation entities from hunter + analyze_email output."""
    out: list[InformationCandidate] = []

    def _emit(
        info_type: InformationType,
        key: str,
        normalized: str,
        original: str,
        attrs: dict[str, Any],
        msg: ToolMessage,
        tool: str,
    ) -> None:
        if not normalized or key in seen:
            return
        seen.add(key)
        out.append(
            _make(
                info_type,
                normalized_value=normalized,
                original_value=original,
                attributes=attrs,
                msg=msg,
                tool_name=tool,
                phase="osint",
            )
        )

    for msg, tool, data in _iter_tool_messages(messages):
        if tool == "hunter_email_search":
            org = str(data.get("organization") or "").strip()
            if org:
                _emit(
                    InformationType.ORGANIZATION,
                    f"org:{org.lower()}",
                    org.lower(),
                    org,
                    {},
                    msg,
                    tool,
                )
            for entry in data.get("emails", []) or []:
                if not isinstance(entry, dict):
                    continue
                addr = str(entry.get("email", "")).strip().lower()
                if addr and "@" in addr:
                    _emit(
                        InformationType.EMAIL,
                        f"email:{addr}",
                        addr,
                        addr,
                        {
                            "position": entry.get("position", ""),
                            "confidence": entry.get("confidence", 0),
                        },
                        msg,
                        tool,
                    )
                name = f"{entry.get('first_name', '')} {entry.get('last_name', '')}".strip()
                if name:
                    _emit(
                        InformationType.PERSON,
                        f"person:{name.lower()}",
                        name.lower(),
                        name,
                        {"position": entry.get("position", "")},
                        msg,
                        tool,
                    )
        elif tool == "breach_lookup":
            _emit_breach_lookup_leaks(data, msg, tool, _emit)
        elif tool == "analyze_email":
            _emit_analyze_email_leaks(data, msg, tool, _emit)
    return out


def _osint_document_candidates(
    messages: list[Any],
    seen: set[str],
) -> list[InformationCandidate]:
    """Extract DOCUMENT entities from document_search output."""
    out: list[InformationCandidate] = []
    for msg, tool, data in _iter_tool_messages(messages):
        if tool != "document_search":
            continue
        for entry in data.get("documents", []) or []:
            if not isinstance(entry, dict):
                continue
            url = str(entry.get("url", "")).strip()
            if not url:
                continue
            key = f"doc:{url.lower()}"
            if key in seen:
                continue
            seen.add(key)
            out.append(
                _make(
                    InformationType.DOCUMENT,
                    normalized_value=url,
                    original_value=url,
                    attributes={
                        "title": entry.get("title", ""),
                        "filetype": entry.get("filetype", ""),
                    },
                    msg=msg,
                    tool_name=tool,
                    phase="osint",
                )
            )
    return out


def _osint_social_candidates(
    messages: list[Any],
    seen: set[str],
) -> list[InformationCandidate]:
    """Extract USERNAME + SOCIAL_ACCOUNT entities from maigret_scan output."""
    out: list[InformationCandidate] = []
    for msg, tool, data in _iter_tool_messages(messages):
        if tool != "maigret_scan":
            continue
        username = str(data.get("username", "")).strip()
        if username:
            key = f"username:{username.lower()}"
            if key not in seen:
                seen.add(key)
                out.append(
                    _make(
                        InformationType.USERNAME,
                        normalized_value=username.lower(),
                        original_value=username,
                        attributes={"account_count": data.get("count", 0)},
                        msg=msg,
                        tool_name=tool,
                        phase="osint",
                    )
                )
        for entry in data.get("accounts", []) or []:
            if not isinstance(entry, dict):
                continue
            url = str(entry.get("url", "")).strip()
            if not url:
                continue
            key = f"social:{url.lower()}"
            if key in seen:
                continue
            seen.add(key)
            out.append(
                _make(
                    InformationType.SOCIAL_ACCOUNT,
                    normalized_value=url,
                    original_value=url,
                    attributes={"site": entry.get("site", ""), "username": username},
                    msg=msg,
                    tool_name=tool,
                    phase="osint",
                )
            )
    return out


# ----------------------------------------------------------------------
# Public OSINT entry points


def translate_osint(
    messages: list[Any],
    *,
    target: str,
) -> list[InformationCandidate]:
    """Build OSINT-phase information candidates from the message log."""
    candidates: list[InformationCandidate] = []
    seen: set[str] = set()

    # Materialise the apex domain as a graph node so subdomain_of / resolves_to /
    # has_email edges are rooted at a real record.
    base = target.strip().lower().rstrip(".")
    if is_valid_domain(base):
        seen.add(f"dom:{base}")
        candidates.append(
            InformationCandidate(
                type=InformationType.DOMAIN,
                normalized_value=base,
                original_value=target,
                attributes={},
                source_execution_id="target",
                source_tool="target",
                phase="osint",
            )
        )

    for msg, tool, data in _iter_tool_messages(messages):
        candidates.extend(_osint_ip_candidates(msg, tool, data, seen))
        if is_valid_domain(target):
            candidates.extend(_osint_subdomain_candidates(msg, tool, data, target, seen))
            candidates.extend(_osint_san_candidates(msg, tool, data, target, seen))
        candidates.extend(_osint_historical_ip_candidates(msg, tool, data, seen))
    candidates.extend(_osint_classification_candidates(messages, target))
    candidates.extend(_osint_tech_fingerprint_candidates(messages))
    candidates.extend(_osint_people_candidates(messages, seen))
    candidates.extend(_osint_document_candidates(messages, seen))
    candidates.extend(_osint_social_candidates(messages, seen))
    return candidates


def _osint_edges(  # noqa: C901 - relationship inference across record types; targeted by R10
    messages: list[Any],
    candidates: list[InformationCandidate],
    target: str,
) -> list[EdgeCandidate]:
    """Derive knowledge-graph edges from OSINT output.

    Emits the relationships that are unambiguous from current tool payloads:
    ``subdomain_of`` (subdomain → apex) and ``resolves_to`` (host → IP).
    Endpoints are referenced by the same record fingerprints the record
    translators produce, so edges line up with their nodes.
    """
    base = target.strip().lower().rstrip(".")
    base_is_domain = is_valid_domain(base)
    domain_fp = fingerprint(InformationType.DOMAIN, base) if base_is_domain else ""

    edges: list[EdgeCandidate] = []
    seen: set[tuple[str, str, str]] = set()

    def _host_fp(host: str) -> str:
        host = host.strip().lower().rstrip(".")
        if not host:
            return ""
        if host == base:
            return fingerprint(InformationType.DOMAIN, host)
        if base_is_domain and host.endswith(f".{base}") and is_valid_domain(host):
            return fingerprint(InformationType.SUBDOMAIN, host)
        return ""

    def _add(src_fp: str, rel: RelationshipType, tgt_fp: str, tool: str) -> None:
        if not src_fp or not tgt_fp or src_fp == tgt_fp:
            return
        key = (src_fp, rel.value, tgt_fp)
        if key in seen:
            return
        seen.add(key)
        edges.append(
            EdgeCandidate(
                source_fingerprint=src_fp,
                target_fingerprint=tgt_fp,
                type=rel,
                source_tool=tool,
                phase="osint",
            )
        )

    # subdomain_of: every discovered subdomain belongs to the apex domain.
    if domain_fp:
        for cand in candidates:
            if cand.type == InformationType.SUBDOMAIN:
                _add(cand.fingerprint, RelationshipType.SUBDOMAIN_OF, domain_fp, cand.source_tool)

    # resolves_to: host → IP, from dns_resolve and any hosts[{hostname, ip}] payload.
    for _msg, tool, data in _iter_tool_messages(messages):
        if data.get("type") == "domain" and data.get("ips"):
            src = _host_fp(str(data.get("target", "")))
            for ip in data.get("ips", []) or []:
                if is_valid_ip(str(ip)):
                    _add(
                        src,
                        RelationshipType.RESOLVES_TO,
                        fingerprint(InformationType.IP_ADDRESS, str(ip).strip()),
                        tool,
                    )
        for host in data.get("hosts", []) or []:
            if isinstance(host, dict) and host.get("hostname") and host.get("ip"):
                ip = str(host["ip"]).strip()
                if is_valid_ip(ip):
                    _add(
                        _host_fp(str(host["hostname"])),
                        RelationshipType.RESOLVES_TO,
                        fingerprint(InformationType.IP_ADDRESS, ip),
                        tool,
                    )

    # people / organisation edges: apex domain → email/org, org → person.
    org_cands = [c for c in candidates if c.type == InformationType.ORGANIZATION]
    if domain_fp:
        for cand in candidates:
            if cand.type == InformationType.EMAIL:
                _add(domain_fp, RelationshipType.HAS_EMAIL, cand.fingerprint, cand.source_tool)
            elif cand.type == InformationType.ORGANIZATION:
                _add(domain_fp, RelationshipType.OWNED_BY, cand.fingerprint, cand.source_tool)
    if org_cands:
        org_fp = org_cands[0].fingerprint
        for cand in candidates:
            if cand.type == InformationType.PERSON:
                _add(org_fp, RelationshipType.EMPLOYS, cand.fingerprint, cand.source_tool)

    return edges
