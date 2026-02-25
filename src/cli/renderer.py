"""Real-time TUI renderer for agent ReAct events.

Uses a single Rich ``Live`` area to show tool batches and LLM thinking
panels with an animated spinner.  Content is persisted via
``console.print`` when finalized, and the transient live area is cleared.
"""

from __future__ import annotations

import time
from typing import Any, ClassVar

from rich.console import Console, Group
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from fackel.formatting import PHASE_ICONS, PHASE_LABELS

_THINKING_MAX_CHARS = 500
"""Max characters of LLM reasoning to show in the thinking panel."""

_THINKING_EVENTS = frozenset({"token", "reasoning_trace", "reasoning"})
"""Event types that contribute to the live thinking panel."""


class EventRenderer:
    """Renders agent ReAct events using a single Rich ``Live`` area.

    The live area always contains an animated spinner at the bottom.
    Above the spinner, the current content (tool batch table or thinking
    panel) is rendered.  When content is finalized, it is persisted via
    ``console.print`` and the live area restarts with the spinner alone.

    Because ``Live(transient=True)`` is used, the live area vanishes when
    stopped — leaving only the explicitly persisted output on screen.
    """

    def __init__(self, console: Console, *, verbose: bool) -> None:
        self._console = console
        self._verbose = verbose
        self._streaming_tokens = False
        self._thinking_text = ""
        self._phase_start: float = 0.0
        self._seen_errors: set[str] = set()
        self._suppressed_errors: int = 0
        self._tool_count: int = 0
        self._tool_batch: list[dict[str, str]] = []
        self._current_label = ""
        self._spinner_msg = ""
        self._live: Live | None = None
        self._live_kind: str | None = None


    def _build_display(self) -> Group:
        """Build the renderable shown inside the Live area."""
        spinner = Spinner("dots", text=f"  {self._spinner_msg}", style="dim")
        if self._live_kind == "tools" and self._tool_batch:
            return Group(self._build_tool_table(), "", spinner)
        if self._live_kind == "thinking" and self._thinking_text.strip():
            return Group(self._build_thinking_panel(), "", spinner)
        return Group("", spinner)


    def _refresh_live(self) -> None:
        """Start or update the single Live area."""
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
        """Stop the Live area (content vanishes due to ``transient=True``)."""
        if self._live is not None:
            self._live.stop()
            self._live = None
        self._live_kind = None

    def _persist_content(self) -> None:
        """Print the current content permanently, then stop the Live area."""
        if self._live_kind == "tools" and self._tool_batch:
            content = self._build_tool_table()
        elif self._live_kind == "thinking" and self._thinking_text.strip():
            content = self._build_thinking_panel()
        else:
            content = None
        self._stop_live()
        if content is not None:
            self._console.print(content)

    def _end_token_stream(self) -> None:
        """Finalize the thinking panel when a non-thinking event arrives."""
        if self._streaming_tokens:
            self._streaming_tokens = False
            self._persist_content()
            self._thinking_text = ""

    def shutdown(self) -> None:
        """Clean up all live displays."""
        self._stop_live()


    def handle(self, phase: str, event_type: str, data: dict[str, Any]) -> None:
        """Route an agent event to the appropriate renderer."""
        label = PHASE_LABELS.get(phase, phase)
        icon = PHASE_ICONS.get(phase, "▶")

        if event_type not in _THINKING_EVENTS and self._streaming_tokens:
            self._end_token_stream()

        handler = self._EVENT_HANDLERS.get(event_type)
        if handler is not None:
            handler(self, label=label, icon=icon, data=data)


    def _on_start(self, *, label: str, icon: str, data: dict[str, Any]) -> None:
        self._persist_content()
        self._phase_start = time.perf_counter()
        self._seen_errors.clear()
        self._suppressed_errors = 0
        self._tool_count = 0
        self._tool_batch.clear()
        self._thinking_text = ""
        self._current_label = label
        self._console.print()
        self._console.print(Rule(f"{icon} {label}", style="bold blue"))
        self._spinner_msg = f"{label}: analyzing\u2026"
        self._live_kind = None
        self._refresh_live()


    def _build_tool_table(self) -> Table:
        """Build a table showing the current tool batch with live status."""
        table = Table(
            box=None,
            show_header=False,
            padding=(0, 1),
            pad_edge=False,
        )
        table.add_column("icon", width=4, no_wrap=True)
        table.add_column("name", min_width=20, no_wrap=True)
        table.add_column("detail")
        for t in self._tool_batch:
            status = t["status"]
            name = t["name"]
            if status == "done":
                row_icon = "  [green]✓[/green]"
                name_mk = f"[dim]{name}[/dim]"
                detail = f"[dim]{t.get('args_str', '')}[/dim]" if self._verbose else ""
            elif status == "error":
                row_icon = "  [red]✗[/red]"
                name_mk = f"[red]{name}[/red]"
                detail = f"[dim]{t.get('error_msg', '')}[/dim]"
            else:
                row_icon = "  [cyan]→[/cyan]"
                name_mk = f"[bold]{name}[/bold]"
                detail = f"[dim]{t.get('args_str', '')}[/dim]"
            table.add_row(row_icon, name_mk, detail)
        return table

    def _update_spinner_for_tools(self) -> None:
        """Set the spinner message to reflect running tool count."""
        running = sum(1 for t in self._tool_batch if t["status"] == "running")
        if running > 0:
            noun = "tool" if running == 1 else "tools"
            self._spinner_msg = f"{self._current_label}: running {running} {noun}\u2026"
        else:
            self._spinner_msg = f"{self._current_label}: analyzing\u2026"

    def _find_pending_tool(self, name: str) -> dict[str, str] | None:
        """Find the first tool entry with *name* that is still running."""
        for t in self._tool_batch:
            if t["name"] == name and t["status"] == "running":
                return t
        return None

    def _batch_all_finished(self) -> bool:
        """Return True when every tool in the current batch has completed."""
        return bool(self._tool_batch) and all(
            t["status"] in ("done", "error") for t in self._tool_batch
        )

    def _check_batch_complete(self) -> None:
        """If all tools finished, persist the table and show spinner only."""
        if self._batch_all_finished():
            self._persist_content()
            self._tool_batch.clear()
            self._spinner_msg = f"{self._current_label}: analyzing\u2026"
            self._live_kind = None
            self._refresh_live()

    def _on_tool_call(self, *, label: str, icon: str, data: dict[str, Any]) -> None:
        self._tool_count += 1
        tool = data.get("tool", "?")
        args = data.get("args", {})
        args_str = ", ".join(f"{k}={v}" for k, v in args.items() if v not in ("", None))
        self._tool_batch.append(
            {"name": tool, "args_str": args_str, "status": "running", "error_msg": ""}
        )
        self._live_kind = "tools"
        self._update_spinner_for_tools()
        self._refresh_live()

    def _on_tool_error(self, *, label: str, icon: str, data: dict[str, Any]) -> None:
        tool = data.get("tool", "?")
        error = data.get("error", "unknown error")
        first_line = error.strip().splitlines()[-1].strip() if error.strip() else "unknown error"
        error_key = f"{tool}:{first_line}"
        if error_key in self._seen_errors:
            self._suppressed_errors += 1
        else:
            self._seen_errors.add(error_key)
        entry = self._find_pending_tool(tool)
        if entry is not None:
            entry["status"] = "error"
            entry["error_msg"] = first_line
            self._update_spinner_for_tools()
            self._refresh_live()
        self._check_batch_complete()

    def _on_tool_result(self, *, label: str, icon: str, data: dict[str, Any]) -> None:
        tool = data.get("tool", "?")
        entry = self._find_pending_tool(tool)
        if entry is not None:
            entry["status"] = "done"
            if self._verbose:
                content = data.get("content", "")
                preview = content[:120] + "\u2026" if len(content) > 120 else content
                entry["args_str"] = preview
            self._update_spinner_for_tools()
            self._refresh_live()
        self._check_batch_complete()


    def _build_thinking_panel(self) -> Panel:
        """Build a Panel renderable from the current thinking text."""
        text = self._thinking_text.strip()
        limit = _THINKING_MAX_CHARS if not self._verbose else len(text) + 1
        if len(text) > limit:
            text = "\u2026 " + text[len(text) - limit :].lstrip()
        return Panel(
            Text(text, style="italic color(245)"),
            title="[color(245)]thinking[/color(245)]",
            border_style="color(245)",
            padding=(0, 1),
            expand=True,
        )

    def _append_thinking(self, content: str) -> None:
        """Append content to the thinking buffer and refresh the display."""
        if not content:
            return
        if self._live_kind == "tools" and self._tool_batch:
            self._persist_content()
            self._tool_batch.clear()
        self._thinking_text += content
        self._live_kind = "thinking"
        self._spinner_msg = f"{self._current_label}: thinking\u2026"
        self._streaming_tokens = True
        self._refresh_live()

    def _on_token(self, *, label: str, icon: str, data: dict[str, Any]) -> None:
        self._append_thinking(data.get("content", ""))

    def _on_reasoning_trace(self, *, label: str, icon: str, data: dict[str, Any]) -> None:
        self._append_thinking(data.get("content", ""))

    def _on_reasoning(self, *, label: str, icon: str, data: dict[str, Any]) -> None:
        self._append_thinking(data.get("content", ""))

    def _on_summary(self, *, label: str, icon: str, data: dict[str, Any]) -> None:
        self._persist_content()
        content = data.get("content", "")
        if content:
            self._console.print()
            self._console.print(
                Panel(
                    Markdown(content),
                    title=f"📋 {label} Summary",
                    border_style="cyan",
                    padding=(1, 2),
                )
            )

    def _on_evaluation(self, *, label: str, icon: str, data: dict[str, Any]) -> None:
        self._persist_content()
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
            f"  [{style}]📊 Quality: {completeness} "
            f"(score: {score:.1f}) → {recommendation}[/{style}]",
        )

    def _on_tool_approval(self, *, label: str, icon: str, data: dict[str, Any]) -> None:
        self._persist_content()
        self._stop_live()

    def _on_done(self, *, label: str, icon: str, data: dict[str, Any]) -> None:
        self._persist_content()
        self._tool_batch.clear()
        self._thinking_text = ""
        self._stop_live()
        if self._current_label and self._current_label.lower() == "approval":
            return
        elapsed = time.perf_counter() - self._phase_start
        meta: list[str] = []
        if self._tool_count > 0:
            meta.append(f"{self._tool_count} tool calls")
        meta.append(f"{elapsed:.1f}s")
        if self._suppressed_errors > 0:
            meta.append(f"{self._suppressed_errors} duplicate errors hidden")
        meta_str = f" [dim]({', '.join(meta)})[/dim]" if meta else ""
        self._console.print(f"  [green]✓ {label} complete[/green]{meta_str}")


    _EVENT_HANDLERS: ClassVar[dict[str, Any]] = {
        "start": _on_start,
        "tool_call": _on_tool_call,
        "tool_error": _on_tool_error,
        "tool_result": _on_tool_result,
        "token": _on_token,
        "reasoning_trace": _on_reasoning_trace,
        "reasoning": _on_reasoning,
        "summary": _on_summary,
        "evaluation": _on_evaluation,
        "tool_approval": _on_tool_approval,
        "done": _on_done,
    }
