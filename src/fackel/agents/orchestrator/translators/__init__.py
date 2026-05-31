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
"""

from __future__ import annotations

from .translators import persist_phase, translate_phase_edges, translate_phase_messages

__all__ = ["persist_phase", "translate_phase_edges", "translate_phase_messages"]
