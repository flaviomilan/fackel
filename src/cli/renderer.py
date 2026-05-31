"""Real-time TUI renderer for agent ReAct events.

Uses a single Rich ``Live`` area per phase to show concurrent agents.  Parallel
specialists each emit events tagged with a ``lane`` (see
``fackel.agents.orchestrator.streaming.lane``); the renderer keeps **per-lane
state** so their thinking and tool activity are shown in separate lanes instead
of one interleaved stream.  Sequential phases (no lane) use the single ``main``
lane, which keeps the richer thinking-panel + tool-table view.

Finalized content (per-lane summaries, completed tool tables, thinking panels) is
persisted via ``console.print`` *above* the live region; the transient live area
(active lanes + spinner) vanishes when the phase ends.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar

from rich.console import Console, Group, RenderableType
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from cli import theme

_MAIN = "main"
"""Lane id for sequential (non-parallel) phases."""

_THINKING_MAX_CHARS = 500
"""Max characters of LLM reasoning to show in the main thinking panel."""

_LANE_THINKING_TAIL = 60
"""Chars of thinking shown on a compact parallel-lane line."""


@dataclass
class _LaneState:
    """Mutable per-agent state within the current phase."""

    name: str
    status: str = "running"  # running | done | error
    tool_batch: list[dict[str, Any]] = field(default_factory=list)
    thinking: str = ""
    tool_count: int = 0
    start: float = field(default_factory=time.perf_counter)


class EventRenderer:
    """Renders agent ReAct events, one Rich ``Live`` area per phase.

    Each event optionally carries ``data["lane"]`` identifying which parallel
    agent emitted it (``None`` → the ``main`` lane).  Lane state is keyed so
    concurrent agents never share buffers.
    """

    def __init__(
        self,
        console: Console,
        *,
        verbose: bool,
        meter_provider: Callable[[], str] | None = None,
    ) -> None:
        self._console = console
        self._verbose = verbose
        self._meter_provider = meter_provider
        self._lanes: dict[str, _LaneState] = {}
        self._phase: str | None = None
        self._phase_label = ""
        self._phase_icon = "▶"
        self._phase_start: float = 0.0
        self._seen_errors: set[str] = set()
        self._suppressed_errors = 0
        self._spinner_msg = ""
        self._live: Any = None  # rich.live.Live, imported lazily

    # -- lane helpers ------------------------------------------------------

    def _lane(self, data: dict[str, Any]) -> _LaneState:
        """Return (creating if needed) the lane state for an event."""
        lane_id = data.get("lane") or _MAIN
        lane = self._lanes.get(lane_id)
        if lane is None:
            lane = _LaneState(name=lane_id)
            self._lanes[lane_id] = lane
        return lane

    def _named_lanes(self) -> list[_LaneState]:
        return [lane for lane in self._lanes.values() if lane.name != _MAIN]

    # -- live area ---------------------------------------------------------

    def _build_display(self) -> Group:
        spinner = Spinner("dots", text=f"  {self._spinner_msg}", style="dim")
        footer: list[RenderableType] = []
        meter = self._meter_provider() if self._meter_provider else ""
        if meter:
            footer.append(Text.from_markup(meter))
        footer.append(spinner)

        named = self._named_lanes()
        body: RenderableType
        if named:
            body = self._build_lane_table(named)
        else:
            main = self._lanes.get(_MAIN)
            if main and main.tool_batch:
                body = self._build_tool_table(main)
            elif main and main.thinking.strip():
                body = self._build_thinking_panel(main)
            else:
                body = Text("")
        return Group(body, "", *footer)

    def _refresh(self) -> None:
        from rich.live import Live

        display = self._build_display()
        if self._live is None:
            self._live = Live(
                display,
                console=self._console,
                refresh_per_second=12,
                transient=True,
            )
            self._live.start()
        else:
            self._live.update(display)

    def _stop_live(self) -> None:
        """Stop the live area (content vanishes due to ``transient=True``)."""
        if self._live is not None:
            self._live.stop()
            self._live = None

    def shutdown(self) -> None:
        self._stop_live()

    # -- phase framing -----------------------------------------------------

    def _ensure_phase(self, phase: str) -> None:
        """Open a new phase (print header, reset lanes) when the phase changes.

        Idempotent: a no-op while *phase* is unchanged.  This frames phases
        robustly whether the first event seen is a sequential ``start`` or a
        parallel specialist's ``lane_start`` (each parallel agent also emits its
        own lane-scoped ``start``)."""
        if phase == self._phase:
            return
        self._stop_live()
        self._phase = phase
        self._phase_label = theme.phase_label(phase)
        self._phase_icon = theme.phase_glyph(phase)
        self._phase_start = time.perf_counter()
        self._lanes.clear()
        self._seen_errors.clear()
        self._suppressed_errors = 0
        self._spinner_msg = f"{self._phase_label}: analyzing…"
        self._console.print()
        if phase in theme.STEP_ORDER:
            self._console.print(theme.render_stepper(phase), justify="center")
        self._console.print(
            Rule(f"{self._phase_icon} {self._phase_label}", style=theme.color("phase"))
        )
        self._refresh()

    def handle(self, phase: str, event_type: str, data: dict[str, Any]) -> None:
        """Route an agent event to the appropriate renderer."""
        if event_type != "done":
            self._ensure_phase(phase)
        handler = self._EVENT_HANDLERS.get(event_type)
        if handler is not None:
            handler(self, data=data)

    # -- main-lane content (single sequential agent) -----------------------

    def _build_tool_table(self, lane: _LaneState) -> Table:
        table = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False, expand=True)
        table.add_column("icon", width=4, no_wrap=True)
        table.add_column("name", min_width=20, no_wrap=True)
        table.add_column("detail", ratio=1)
        table.add_column("time", justify="right", no_wrap=True, style="dim")
        for t in lane.tool_batch:
            status = t["status"]
            name = t["name"]
            if status == "done":
                row_icon = (
                    f"  [{theme.color('success')}]{theme.glyph('done')}[/{theme.color('success')}]"
                )
                name_mk = f"[dim]{name}[/dim]"
                detail = f"[dim]{t.get('args_str', '')}[/dim]" if self._verbose else ""
            elif status == "error":
                row_icon = (
                    f"  [{theme.color('danger')}]{theme.glyph('error')}[/{theme.color('danger')}]"
                )
                name_mk = f"[{theme.color('danger')}]{name}[/{theme.color('danger')}]"
                detail = f"[dim]{t.get('error_msg', '')}[/dim]"
            else:
                row_icon = (
                    f"  [{theme.color('accent')}]{theme.glyph('running')}[/{theme.color('accent')}]"
                )
                name_mk = f"[bold]{name}[/bold]"
                detail = f"[dim]{t.get('args_str', '')}[/dim]"
            table.add_row(row_icon, name_mk, detail, t.get("elapsed", ""))
        return table

    def _build_thinking_panel(self, lane: _LaneState) -> Panel:
        text = lane.thinking.strip()
        limit = _THINKING_MAX_CHARS if not self._verbose else len(text) + 1
        if len(text) > limit:
            text = "… " + text[len(text) - limit :].lstrip()
        return Panel(
            Text(text, style="italic color(245)"),
            title="[color(245)]thinking[/color(245)]",
            border_style="color(245)",
            padding=(0, 1),
            expand=True,
        )

    # -- parallel-lane content ---------------------------------------------

    def _lane_activity(self, lane: _LaneState) -> str:
        running = [t for t in lane.tool_batch if t["status"] == "running"]
        if running:
            extra = f" [dim]+{len(running) - 1}[/dim]" if len(running) > 1 else ""
            args = running[0].get("args_str", "")
            arg_str = f"[dim]({args})[/dim]" if args and self._verbose else ""
            run_icon = (
                f"[{theme.color('accent')}]{theme.glyph('running')}[/{theme.color('accent')}]"
            )
            return f"{run_icon} {running[0]['name']}{arg_str}{extra}"
        if lane.thinking.strip():
            tail = lane.thinking.strip().replace("\n", " ")[-_LANE_THINKING_TAIL:]
            return f"[dim]thinking… {tail}[/dim]"
        return "[dim]analyzing…[/dim]"

    def _build_lane_table(self, lanes: list[_LaneState]) -> Table:
        table = Table(box=None, show_header=False, padding=(0, 1), pad_edge=False)
        table.add_column("icon", width=3, no_wrap=True)
        table.add_column("name", min_width=14, no_wrap=True)
        table.add_column("activity")
        for lane in lanes:
            icon: RenderableType = Spinner("dots", style="cyan")
            table.add_row(icon, f"[bold]{lane.name}[/bold]", self._lane_activity(lane))
        return table

    # -- event handlers ----------------------------------------------------

    def _on_start(self, *, data: dict[str, Any]) -> None:
        # Lane-scoped start (a parallel specialist) is handled by lane_start;
        # a bare start just (re)affirms the phase already opened by _ensure_phase.
        if data.get("lane"):
            self._lane(data)
            self._refresh()

    def _on_lane_start(self, *, data: dict[str, Any]) -> None:
        self._lane(data)
        self._spinner_msg = f"{self._phase_label}: {len(self._named_lanes())} agents…"
        self._refresh()

    def _on_lane_end(self, *, data: dict[str, Any]) -> None:
        lane = self._lane(data)
        elapsed = time.perf_counter() - lane.start
        icon = (
            f"[{theme.color('danger')}]{theme.glyph('error')}[/{theme.color('danger')}]"
            if lane.status == "error"
            else f"[{theme.color('success')}]{theme.glyph('done')}[/{theme.color('success')}]"
        )
        meta = f"{lane.tool_count} tools, {elapsed:.1f}s" if lane.tool_count else f"{elapsed:.1f}s"
        self._console.print(f"  {icon} [bold]{lane.name}[/bold] [dim]— {meta}[/dim]")
        self._lanes.pop(lane.name, None)
        remaining = len(self._named_lanes())
        self._spinner_msg = (
            f"{self._phase_label}: {remaining} agents…"
            if remaining
            else f"{self._phase_label}: collecting…"
        )
        self._refresh()

    def _on_tool_call(self, *, data: dict[str, Any]) -> None:
        lane = self._lane(data)
        lane.tool_count += 1
        args = data.get("args", {})
        args_str = ", ".join(f"{k}={v}" for k, v in args.items() if v not in ("", None))
        lane.tool_batch.append(
            {
                "name": data.get("tool", "?"),
                "args_str": args_str,
                "status": "running",
                "error_msg": "",
                "started": time.perf_counter(),
                "elapsed": "",
            }
        )
        self._refresh()

    def _find_pending(self, lane: _LaneState, name: str) -> dict[str, Any] | None:
        for t in lane.tool_batch:
            if t["name"] == name and t["status"] == "running":
                return t
        return None

    @staticmethod
    def _mark_elapsed(entry: dict[str, Any]) -> None:
        """Stamp an entry with its wall-clock duration once it settles."""
        started = entry.get("started")
        if isinstance(started, float):
            entry["elapsed"] = f"{time.perf_counter() - started:.1f}s"

    def _maybe_persist_main_batch(self, lane: _LaneState) -> None:
        """For the sequential main lane: when all tools finish, persist the table."""
        if lane.name != _MAIN:
            return
        if lane.tool_batch and all(t["status"] in ("done", "error") for t in lane.tool_batch):
            self._console.print(self._build_tool_table(lane))
            lane.tool_batch.clear()
            self._spinner_msg = f"{self._phase_label}: analyzing…"
            self._refresh()

    def _on_tool_result(self, *, data: dict[str, Any]) -> None:
        lane = self._lane(data)
        entry = self._find_pending(lane, data.get("tool", "?"))
        if entry is not None:
            entry["status"] = "done"
            self._mark_elapsed(entry)
            if self._verbose:
                content = data.get("content", "")
                entry["args_str"] = content[:120] + "…" if len(content) > 120 else content
        self._refresh()
        self._maybe_persist_main_batch(lane)

    def _on_tool_error(self, *, data: dict[str, Any]) -> None:
        lane = self._lane(data)
        tool = data.get("tool", "?")
        error = data.get("error", "unknown error")
        first_line = error.strip().splitlines()[-1].strip() if error.strip() else "unknown error"
        error_key = f"{tool}:{first_line}"
        if error_key in self._seen_errors:
            self._suppressed_errors += 1
        else:
            self._seen_errors.add(error_key)
        entry = self._find_pending(lane, tool)
        if entry is not None:
            entry["status"] = "error"
            entry["error_msg"] = first_line
            self._mark_elapsed(entry)
        if lane.name != _MAIN:
            lane.status = "error"
        self._refresh()
        self._maybe_persist_main_batch(lane)

    def _append_thinking(self, lane: _LaneState, content: str) -> None:
        if not content:
            return
        # Main lane: persist any completed tool table before switching to thinking.
        if lane.name == _MAIN and lane.tool_batch:
            self._console.print(self._build_tool_table(lane))
            lane.tool_batch.clear()
        lane.thinking += content
        if lane.name == _MAIN:
            self._spinner_msg = f"{self._phase_label}: thinking…"
        self._refresh()

    def _on_token(self, *, data: dict[str, Any]) -> None:
        self._append_thinking(self._lane(data), data.get("content", ""))

    def _on_summary(self, *, data: dict[str, Any]) -> None:
        content = data.get("content", "")
        if content:
            self._console.print()
            self._console.print(
                Panel(
                    Markdown(content),
                    title=f"{theme.glyph('summary')} {self._phase_label} Summary",
                    border_style=theme.color("accent"),
                    padding=(1, 2),
                )
            )

    def _on_evaluation(self, *, data: dict[str, Any]) -> None:
        score = data.get("score", 0)
        completeness = data.get("completeness", "?")
        recommendation = data.get("recommendation", "proceed")
        style = (
            "green"
            if completeness == "complete"
            else "yellow"
            if completeness == "partial"
            else "red"
        )
        self._console.print(
            f"  [{style}]{theme.glyph('quality')} Quality: {completeness} "
            f"(score: {score:.1f}) → {recommendation}[/{style}]",
        )

    def _on_tool_approval(self, *, data: dict[str, Any]) -> None:
        self._stop_live()

    def _on_done(self, *, data: dict[str, Any]) -> None:
        # Persist any lingering main-lane content, then close the phase.
        main = self._lanes.get(_MAIN)
        if main and main.tool_batch:
            self._console.print(self._build_tool_table(main))
        self._stop_live()
        if self._phase_label.lower() == "approval":
            self._phase = None
            return
        elapsed = time.perf_counter() - self._phase_start
        meta = [f"{elapsed:.1f}s"]
        if self._suppressed_errors > 0:
            meta.append(f"{self._suppressed_errors} duplicate errors hidden")
        meta_str = f" [dim]({', '.join(meta)})[/dim]" if meta else ""
        self._console.print(
            f"  [{theme.color('success')}]{theme.glyph('done')} {self._phase_label} complete"
            f"[/{theme.color('success')}]{meta_str}"
        )
        self._phase = None

    # -- compatibility shim (used by the CLI approval prompt) --------------

    def _persist_content(self) -> None:
        """Persist pending main-lane content and stop the live area.

        Retained for the approval-prompt flow in ``cli.main`` which pauses the
        display before asking the operator a question."""
        main = self._lanes.get(_MAIN)
        if main and main.tool_batch:
            self._console.print(self._build_tool_table(main))
            main.tool_batch.clear()
        elif main and main.thinking.strip():
            self._console.print(self._build_thinking_panel(main))
            main.thinking = ""
        self._stop_live()

    _EVENT_HANDLERS: ClassVar[dict[str, Any]] = {
        "start": _on_start,
        "lane_start": _on_lane_start,
        "lane_end": _on_lane_end,
        "tool_call": _on_tool_call,
        "tool_error": _on_tool_error,
        "tool_result": _on_tool_result,
        "token": _on_token,
        "reasoning_trace": _on_token,
        "reasoning": _on_token,
        "summary": _on_summary,
        "evaluation": _on_evaluation,
        "tool_approval": _on_tool_approval,
        "done": _on_done,
    }
