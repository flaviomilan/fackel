"""Per-phase translators turning ToolMessages into domain candidates.

Each ``translate_*`` function is best-effort:

- Unknown tools are silently ignored.
- Malformed payloads are skipped (errors logged at debug level).
- The output is a flat list of :class:`InformationCandidate`; dedup is
  the persistence layer's job.

**Pipeline role:** these translators feed the ``InformationStore`` (persistence,
the judge, the report).  A second, parallel pipeline, ``orchestrator.extractors``,
parses the *same* tool payloads into the LangGraph ``ScanState`` that drives
routing.  The two must stay in **parity** on the data they both extract (IPs,
subdomains); ``tests/agents/test_node_extractors.py::TestExtractionParity``
guards that contract.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from langchain_core.messages import AIMessage, ToolMessage

from fackel.domain import (
    EdgeCandidate,
    InformationCandidate,
    InformationType,
    RelationshipType,
    ToolExecution,
    ToolExecutionStatus,
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

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# ToolExecution extraction


def _tool_call_params(messages: list[Any]) -> dict[str, dict[str, Any]]:
    """Index tool-call arguments by ``tool_call_id`` from preceding AIMessages."""
    params: dict[str, dict[str, Any]] = {}
    for msg in messages:
        if not isinstance(msg, AIMessage):
            continue
        for call in getattr(msg, "tool_calls", []) or []:
            call_id = call.get("id") if isinstance(call, dict) else getattr(call, "id", None)
            args = call.get("args") if isinstance(call, dict) else getattr(call, "args", None)
            if call_id and isinstance(args, dict):
                params[call_id] = args
    return params


def _execution_status(payload: dict[str, Any] | None) -> ToolExecutionStatus:
    """Map the ``status`` field of the tool payload to an enum value."""
    if not isinstance(payload, dict):
        return ToolExecutionStatus.OK
    raw = str(payload.get("status", "ok")).lower()
    try:
        return ToolExecutionStatus(raw)
    except ValueError:
        return ToolExecutionStatus.ERROR if raw not in {"ok", "success"} else ToolExecutionStatus.OK


def extract_tool_executions(
    messages: list[Any],
    *,
    scan_id: str,
    phase: str,
) -> list[ToolExecution]:
    """Build :class:`ToolExecution` records from the message log.

    One execution per :class:`ToolMessage`.  Parameters are pulled from
    the matching :class:`AIMessage.tool_calls` entry by
    ``tool_call_id``; ``raw_output`` is the raw ``ToolMessage.content``
    string truncated by the caller's sanitizer (we keep it as-is here).
    """
    params_index = _tool_call_params(messages)
    executions: list[ToolExecution] = []
    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        raw_content = msg.content if isinstance(msg.content, str) else str(msg.content)
        payload: dict[str, Any] | None = None
        try:
            parsed = json.loads(raw_content) if raw_content else None
            if isinstance(parsed, dict):
                payload = parsed
        except (TypeError, json.JSONDecodeError):
            payload = None

        tool_name = (
            (payload.get("tool") if isinstance(payload, dict) else None)
            or getattr(msg, "name", "")
            or "unknown"
        )
        call_id = getattr(msg, "tool_call_id", "") or ""
        executions.append(
            ToolExecution(
                execution_id=call_id or uuid.uuid4().hex,
                scan_id=scan_id,
                phase=phase,
                tool_name=str(tool_name),
                params=params_index.get(call_id, {}),
                raw_output=raw_content,
                status=_execution_status(payload),
                started_at=datetime.now(UTC),
            )
        )
    return executions


# ----------------------------------------------------------------------
# Helpers shared across phase translators


def _execution_id_for(msg: ToolMessage) -> str:
    """Best-effort deterministic execution id mirroring ``extract_tool_executions``."""
    return getattr(msg, "tool_call_id", "") or uuid.uuid4().hex


def _iter_tool_messages(
    messages: list[Any],
) -> Iterable[tuple[ToolMessage, str, dict[str, Any]]]:
    """Yield ``(ToolMessage, tool_name, inner_data)`` for valid payloads."""
    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        try:
            payload = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        if payload.get("status") not in {None, "ok"}:
            continue
        tool_name = str(payload.get("tool", getattr(msg, "name", "") or ""))
        inner = payload.get("data", payload)
        if not isinstance(inner, dict):
            continue
        yield msg, tool_name, inner


def _make(
    info_type: InformationType,
    *,
    normalized_value: str,
    original_value: str,
    attributes: dict[str, Any],
    msg: ToolMessage,
    tool_name: str,
    phase: str,
) -> InformationCandidate:
    return InformationCandidate(
        type=info_type,
        normalized_value=normalized_value,
        original_value=original_value,
        attributes=attributes,
        source_execution_id=_execution_id_for(msg),
        source_tool=tool_name,
        phase=phase,
    )


# ----------------------------------------------------------------------
# OSINT translator


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
    execution id wins when both ipinfo and bgp are present).  Only ipinfo/bgp
    register an IP here, so every entry has a source message.
    """
    per_ip: dict[str, dict[str, Any]] = {}
    source_msg: dict[str, ToolMessage] = {}
    source_tool: dict[str, str] = {}
    for msg, tool, data in _iter_tool_messages(messages):
        if tool not in ("ipinfo_lookup", "bgp_lookup"):
            continue
        ip = str(data.get("ip", "")).strip()
        if not ip or not is_valid_ip(ip):
            continue
        entry = per_ip.setdefault(ip, {})
        merge_ip_classification_fields(entry, tool, data)
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
        elif tool == "analyze_email":
            addr = str(data.get("email", "")).strip().lower()
            if addr and "@" in addr:
                _emit(InformationType.EMAIL, f"email:{addr}", addr, addr, {}, msg, tool)
                for breach in data.get("breaches", []) or []:
                    if isinstance(breach, dict):
                        breach_name = str(
                            breach.get("Name") or breach.get("name") or breach.get("Title") or ""
                        )
                    else:
                        breach_name = str(breach)
                    if breach_name:
                        _emit(
                            InformationType.CREDENTIAL_LEAK,
                            f"leak:{addr}:{breach_name.lower()}",
                            f"{addr}:{breach_name}",
                            f"{addr}:{breach_name}",
                            {"breach": breach_name, "email": addr},
                            msg,
                            tool,
                        )
    return out


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
    return candidates


# ----------------------------------------------------------------------
# Port-scan translator


_PORT_SCAN_TOOLS = {"naabu_scan", "nmap_scan"}


def translate_port_scan(messages: list[Any]) -> list[InformationCandidate]:
    """Best-effort extraction of OPEN_PORT / SERVICE_VERSION candidates."""
    candidates: list[InformationCandidate] = []
    seen: set[str] = set()
    for msg, tool, data in _iter_tool_messages(messages):
        if tool not in _PORT_SCAN_TOOLS:
            continue
        host_default = str(data.get("host", data.get("target", "")) or "").strip().lower()
        for entry in data.get("ports", []) or []:
            if not isinstance(entry, dict):
                continue
            host = str(entry.get("host", host_default) or "").strip().lower()
            port = entry.get("port")
            if port is None:
                continue
            try:
                port_int = int(port)
            except (TypeError, ValueError):
                continue
            if not host:
                continue
            proto = str(entry.get("protocol", "tcp") or "tcp").lower()
            normalized = f"{host}:{port_int}/{proto}"
            key = f"port:{normalized}"
            if key not in seen:
                seen.add(key)
                attrs = {
                    "host": host,
                    "port": port_int,
                    "protocol": proto,
                    "state": entry.get("state", ""),
                    "service": entry.get("service", ""),
                }
                candidates.append(
                    _make(
                        InformationType.OPEN_PORT,
                        normalized_value=normalized,
                        original_value=normalized,
                        attributes=attrs,
                        msg=msg,
                        tool_name=tool,
                        phase="port_scan",
                    )
                )
            service = entry.get("service") or ""
            version = entry.get("version") or entry.get("product") or ""
            if service and version:
                svc_norm = f"{host}:{port_int}/{service}/{version}".lower()
                svc_key = f"svc:{svc_norm}"
                if svc_key not in seen:
                    seen.add(svc_key)
                    candidates.append(
                        _make(
                            InformationType.SERVICE_VERSION,
                            normalized_value=svc_norm,
                            original_value=f"{service} {version}",
                            attributes={
                                "host": host,
                                "port": port_int,
                                "service": service,
                                "version": version,
                            },
                            msg=msg,
                            tool_name=tool,
                            phase="port_scan",
                        )
                    )
    return candidates


# ----------------------------------------------------------------------
# Vuln-scan translator


_VULN_SCAN_TOOLS = {"nuclei_scan"}


def translate_vuln_scan(messages: list[Any]) -> list[InformationCandidate]:
    """Best-effort extraction of SECURITY_VULNERABILITY candidates."""
    candidates: list[InformationCandidate] = []
    seen: set[str] = set()
    for msg, tool, data in _iter_tool_messages(messages):
        if tool not in _VULN_SCAN_TOOLS:
            continue
        for finding in data.get("findings", data.get("results", [])) or []:
            if not isinstance(finding, dict):
                continue
            template = str(finding.get("template-id", finding.get("template_id", "")) or "").strip()
            host = str(finding.get("host", finding.get("matched-at", "")) or "").strip().lower()
            if not template or not host:
                continue
            normalized = f"{template}@{host}"
            key = f"vuln:{normalized}"
            if key in seen:
                continue
            seen.add(key)
            attrs = {
                "template_id": template,
                "host": host,
                "severity": finding.get("info", {}).get("severity")
                if isinstance(finding.get("info"), dict)
                else finding.get("severity", ""),
                "name": finding.get("info", {}).get("name")
                if isinstance(finding.get("info"), dict)
                else finding.get("name", ""),
                "matched_at": finding.get("matched-at", finding.get("matched_at", "")),
            }
            candidates.append(
                _make(
                    InformationType.SECURITY_VULNERABILITY,
                    normalized_value=normalized,
                    original_value=normalized,
                    attributes=attrs,
                    msg=msg,
                    tool_name=tool,
                    phase="vuln_scan",
                )
            )
    return candidates


# ----------------------------------------------------------------------
# Public entry point


def translate_phase_messages(
    messages: list[Any],
    *,
    phase: str,
    scan_id: str,
    target: str = "",
) -> tuple[list[ToolExecution], list[InformationCandidate]]:
    """Return ``(executions, candidates)`` for a given phase's message log.

    Parameters
    ----------
    messages:
        The full message log produced by :func:`run_and_stream_agent`.
    phase:
        Phase name (``"osint"``, ``"port_scan"``, ``"vuln_scan"``).
    scan_id:
        Owning scan id, used to stamp every :class:`ToolExecution`.
    target:
        Original scan target — required for OSINT subdomain validation.
    """
    started = time.monotonic()
    executions = extract_tool_executions(messages, scan_id=scan_id, phase=phase)
    if phase == "osint":
        candidates = translate_osint(messages, target=target)
    elif phase == "port_scan":
        candidates = translate_port_scan(messages)
    elif phase == "vuln_scan":
        candidates = translate_vuln_scan(messages)
    else:
        candidates = []
    elapsed_ms = int((time.monotonic() - started) * 1000)
    logger.debug(
        "translators: phase=%s executions=%d candidates=%d elapsed_ms=%d",
        phase,
        len(executions),
        len(candidates),
        elapsed_ms,
    )
    return executions, candidates


# ----------------------------------------------------------------------
# Relationship (knowledge-graph edge) extraction


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


def translate_phase_edges(
    messages: list[Any],
    candidates: list[InformationCandidate],
    *,
    phase: str,
    target: str = "",
) -> list[EdgeCandidate]:
    """Return knowledge-graph edge candidates for a phase's message log."""
    if phase == "osint":
        return _osint_edges(messages, candidates, target)
    return []


# ----------------------------------------------------------------------
# Convenience: persist into the scan-bound store


def persist_phase(
    messages: list[Any],
    *,
    phase: str,
    target: str = "",
) -> None:
    """Translate *and* persist a phase's outputs into the bound store.

    No-op when no :class:`InformationStore` is bound to the current
    context (e.g. unit tests that bypass ``orchestrator.run``).
    """
    from fackel.persistence import get_current_store

    store = get_current_store()
    if store is None:
        return
    executions, candidates = translate_phase_messages(
        messages,
        phase=phase,
        scan_id=store.scan_id,
        target=target,
    )
    for execution in executions:
        store.record_execution(execution)
    if candidates:
        store.ingest(candidates, phase=phase)
    edges = translate_phase_edges(messages, candidates, phase=phase, target=target)
    if edges:
        store.ingest_edges(edges, phase=phase)
