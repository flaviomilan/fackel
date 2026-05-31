"""Low-level primitives shared across the phase translators.

Kept in their own module so the per-phase translator code can import them
without a circular dependency: ``translators`` (executions, port/vuln, phase
dispatch) and ``osint`` (the OSINT record + edge builders) both depend on these
but not on each other's bodies.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable
from typing import Any

from langchain_core.messages import ToolMessage

from fackel.domain import InformationCandidate, InformationType


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
