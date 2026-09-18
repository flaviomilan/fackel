"""Shared specialist sub-agent definition.

Both OSINT and vuln-scan run as focused specialist sub-agents: a name, a task
focus, and a narrow slice of the phase's tool list.  This module holds the one
dataclass they share; each phase supplies its own tool registry and task-prompt
wording (see ``osint/specialists.py`` and ``vuln_scan/specialists.py``).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Specialist:
    """A focused sub-agent: a domain name, a task focus, and its tools.

    ``registry`` (a ``name -> tool`` map for the owning phase) is excluded from
    equality/hash so instances stay hashable and usable as ``lru_cache`` keys.
    """

    name: str
    focus: str
    tool_names: tuple[str, ...]
    registry: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)

    @property
    def tools(self) -> list[Any]:
        return [self.registry[n] for n in self.tool_names if n in self.registry]


def specialist_task(
    name: str,
    focus: str,
    role: str,
    *,
    target: str = "",
    base_prompt: str = "",
) -> str:
    """Build a specialist's task message.

    *role* is the domain label (``"OSINT"`` / ``"vulnerability-scan"``).
    *target* adds a ``for the target: …`` clause (OSINT); *base_prompt* prepends
    the shared per-run context (vuln-scan).
    """
    prefix = f"{base_prompt}\n\n" if base_prompt else ""
    subject = f" for the target: {target}" if target else ""
    return (
        f"{prefix}You are the **{name}** {role} specialist{subject}.\n"
        f"Focus exclusively on: {focus}.\n"
        "Use only your available tools (do not attempt anything outside your "
        "domain), be thorough, then produce a concise structured summary of your "
        "findings."
    )
