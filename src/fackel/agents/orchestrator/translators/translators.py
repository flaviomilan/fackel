"""Translate ReAct ToolMessages into domain candidates and executions.

This is the bridge between the message-passing world used by the
LangGraph ReAct agents and the persistent domain model defined in
:mod:`fackel.domain`.

For each phase, ``translate_phase_messages`` returns:

- A list of :class:`~fackel.domain.ToolExecution` (one per tool call).
- A list of :class:`~fackel.domain.InformationCandidate` (semantic
  facts extracted from the tool outputs).

Translators are best-effort and side-effect-free.  Persistence happens
in the orchestrator nodes via the bound :class:`InformationStore`.

The OSINT record + edge builders live in :mod:`.osint`; the low-level
primitives shared by every phase live in :mod:`._common`.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from langchain_core.messages import AIMessage, ToolMessage

from fackel.domain import (
    EdgeCandidate,
    InformationCandidate,
    InformationType,
    ToolExecution,
    ToolExecutionStatus,
)

from ._common import _iter_tool_messages, _make
from .osint import _osint_edges, translate_osint

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
