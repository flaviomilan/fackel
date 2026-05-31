"""Live context/token tracking for the interactive harness.

Aggregates a running token estimate from streamed agent events (thinking tokens,
tool results, summaries) per phase and overall, reusing the orchestrator's token
estimator so the figures line up with the trimming guard-rail.  Exposes a compact
meter for the live footer / bottom toolbar and a per-phase breakdown for
``/context``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fackel.agents.orchestrator.streaming import text_tokens
from fackel.settings import get_settings

# Event types whose ``content`` represents tokens flowing through agent context.
_COUNTED_EVENTS = frozenset({"token", "reasoning", "reasoning_trace", "tool_result", "summary"})

_BAR_CELLS = 10


def _human(n: int) -> str:
    """Format a token count compactly (e.g. ``12.3k``)."""
    if n < 1000:
        return str(n)
    return f"{n / 1000:.1f}k"


@dataclass
class ContextTracker:
    """Running token totals fed from streamed events."""

    total: int = 0
    per_phase: dict[str, int] = field(default_factory=dict)
    per_lane: dict[str, int] = field(default_factory=dict)

    def add_event(self, phase: str, event_type: str, data: dict[str, object]) -> None:
        """Account for an event's content tokens, if it carries any."""
        if event_type not in _COUNTED_EVENTS:
            return
        content = data.get("content", "")
        if not isinstance(content, str) or not content:
            return
        tokens = text_tokens(content)
        if tokens == 0:
            return
        self.total += tokens
        self.per_phase[phase] = self.per_phase.get(phase, 0) + tokens
        lane = data.get("lane")
        if isinstance(lane, str):
            self.per_lane[lane] = self.per_lane.get(lane, 0) + tokens

    def reset(self) -> None:
        self.total = 0
        self.per_phase.clear()
        self.per_lane.clear()

    @property
    def window(self) -> int:
        return get_settings().agent_context_window

    def _bar(self) -> tuple[str, str]:
        """Return (bar string, rich color) for the fill ratio."""
        window = self.window or 1
        ratio = min(self.total / window, 1.0)
        filled = round(ratio * _BAR_CELLS)
        bar = "▓" * filled + "░" * (_BAR_CELLS - filled)
        color = "green" if ratio < 0.6 else "yellow" if ratio < 0.85 else "red"
        return bar, color

    def render_meter(self) -> str:
        """Compact one-line meter (Rich markup) for the live footer."""
        bar, color = self._bar()
        return f"[dim]ctx[/dim] {_human(self.total)}/{_human(self.window)} [{color}]{bar}[/{color}]"
