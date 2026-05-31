"""Interactive Fackel harness — a REPL around the parallel agent pipeline.

Launches scans whose parallel specialists render in separate live lanes, lets the
operator approve gates inline, query the knowledge graph (``/ask``), inspect and
compact context, and chain scans within one session.  A scan runs in a worker
thread; events flow over a queue to the main thread, which owns the Rich ``Live``
display and the prompt — keeping the REPL responsive and the output clean.

Press **Ctrl-C during a scan** to cooperatively cancel it; at the prompt, Ctrl-C
clears the line and Ctrl-D (or ``/quit``) exits.
"""

from __future__ import annotations

import contextvars
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from cli import presenter, theme
from cli.context_tracker import ContextTracker
from cli.renderer import EventRenderer
from cli.session import HarnessSession

_HELP = """[bold]Commands[/bold]
  [cyan]/scan[/cyan] <target> [--no-active] [--approve-tools]   run a scan
  [cyan]/ask[/cyan] <question>        ask about the last scan's knowledge graph
  [cyan]/scans[/cyan]                 list persisted scans
  [cyan]/diff[/cyan] <old> <new>      diff two scans
  [cyan]/graph[/cyan] [scan_id]       export the knowledge graph (mermaid)
  [cyan]/context[/cyan]               show context meter + session memory
  [cyan]/compact[/cyan]               summarise prior findings into session memory
  [cyan]/agents[/cyan]                list the specialist agents
  [cyan]/help[/cyan]                  show this help
  [cyan]/quit[/cyan]                  exit (or Ctrl-D)
[dim]Bare text is treated as /ask. Press Ctrl-C during a scan to stop it.[/dim]"""


@dataclass
class _PendingApproval:
    """An approval request raised by the worker, answered on the main thread."""

    data: dict[str, Any]
    kind: str  # "gate" | "tool"
    event: threading.Event = field(default_factory=threading.Event)
    result: Any = None


class Harness:
    """Stateful interactive session."""

    def __init__(self, console: Console, *, verbose: bool = False) -> None:
        self._console = console
        self._verbose = verbose
        self._session = HarnessSession()
        self._tracker = ContextTracker()
        self._renderer = EventRenderer(
            console, verbose=verbose, meter_provider=self._tracker.render_meter
        )
        self._prompt: PromptSession[str] = PromptSession(history=InMemoryHistory())

    # -- main loop ---------------------------------------------------------

    def run(self) -> None:
        presenter.print_banner(self._console)
        self._console.print(
            "[dim]Type [cyan]/help[/cyan] for commands, [cyan]/quit[/cyan] to exit.[/dim]"
        )
        while True:
            try:
                line = self._prompt.prompt("fackel> ", bottom_toolbar=self._toolbar).strip()
            except KeyboardInterrupt:
                continue  # clear the line
            except EOFError:
                break  # Ctrl-D
            if not line:
                continue
            if not self._dispatch(line):
                break
        self._console.print("[dim]bye 👋[/dim]")

    def _toolbar(self) -> str:
        n = len(self._session.scans)
        return f" tokens ~{self._tracker.total} · {n} scan(s) · /help "

    def _dispatch(self, line: str) -> bool:
        """Run one command. Returns False to exit the loop."""
        if line.startswith("/"):
            cmd, _, rest = line[1:].partition(" ")
            cmd, rest = cmd.lower(), rest.strip()
        else:
            cmd, rest = "ask", line

        handlers = {
            "scan": self._cmd_scan,
            "ask": self._cmd_ask,
            "scans": self._cmd_scans,
            "diff": self._cmd_diff,
            "graph": self._cmd_graph,
            "context": self._cmd_context,
            "compact": self._cmd_compact,
            "agents": self._cmd_agents,
            "help": self._cmd_help,
        }
        if cmd in ("quit", "exit", "q"):
            return False
        handler = handlers.get(cmd)
        if handler is None:
            self._console.print(f"[yellow]unknown command:[/yellow] /{cmd} — try /help")
            return True
        try:
            handler(rest)
        except Exception as exc:  # never crash the REPL on a command error
            self._console.print(f"[red]error:[/red] {exc}")
        return True

    # -- commands ----------------------------------------------------------

    def _cmd_help(self, _rest: str) -> None:
        self._console.print(_HELP)

    def _cmd_scan(self, rest: str) -> None:
        if not rest:
            self._console.print(
                "[yellow]usage:[/yellow] /scan <target> [--no-active] [--approve-tools]"
            )
            return
        parts = rest.split()
        flags = {p for p in parts if p.startswith("--")}
        targets = [p for p in parts if not p.startswith("--")]
        if not targets:
            self._console.print("[yellow]no target given[/yellow]")
            return
        self._run_scan(
            targets[0],
            active_scan="--no-active" not in flags and "--no-active-scan" not in flags,
            approve_tools="--approve-tools" in flags,
        )

    def _cmd_ask(self, rest: str) -> None:
        if not rest:
            self._console.print("[yellow]usage:[/yellow] /ask <question>")
            return
        store = self._session.store_for()
        if store is None:
            self._console.print("[yellow]no scan yet — run /scan <target> first[/yellow]")
            return
        from fackel.agents.query import answer_query

        with self._console.status("thinking…"):
            answer = answer_query(store, rest)
        self._console.print(Panel(Markdown(answer), border_style="cyan", padding=(1, 2)))

    def _cmd_scans(self, _rest: str) -> None:
        from fackel.persistence import list_scans

        ids = list_scans(self._session.data_dir)
        if not ids:
            self._console.print(f"[yellow]no persisted scans in {self._session.data_dir}[/yellow]")
            return
        table = Table(title=f"Persisted scans ({self._session.data_dir})")
        table.add_column("scan_id", style="cyan")
        for sid in ids:
            table.add_row(sid)
        self._console.print(table)

    def _cmd_diff(self, rest: str) -> None:
        from fackel.persistence import diff_scans, format_diff, load_scan

        parts = rest.split()
        if len(parts) != 2:
            self._console.print("[yellow]usage:[/yellow] /diff <old_scan_id> <new_scan_id>")
            return
        old, new = parts
        d = diff_scans(
            load_scan(old, self._session.data_dir), load_scan(new, self._session.data_dir)
        )
        self._console.print(format_diff(d))

    def _cmd_graph(self, rest: str) -> None:
        from fackel.persistence.graph_export import to_mermaid

        scan_id = rest.strip() or (self._session.last.scan_id if self._session.last else "")
        store = self._session.store_for(scan_id or None)
        if store is None:
            self._console.print(
                "[yellow]no scan to export — run /scan first or pass a scan_id[/yellow]"
            )
            return
        self._console.print(to_mermaid(store))

    def _cmd_context(self, _rest: str) -> None:
        t = self._tracker
        self._console.print(Panel.fit(t.render_meter(), border_style="dim"))
        if t.per_phase:
            table = Table(title="Tokens by phase", show_header=True, border_style="dim")
            table.add_column("phase", style="bold")
            table.add_column("tokens", justify="right")
            for phase, tok in sorted(t.per_phase.items(), key=lambda kv: -kv[1]):
                table.add_row(phase, f"{tok:,}")
            self._console.print(table)
        self._console.print(self._session.render_summary())

    def _cmd_compact(self, _rest: str) -> None:
        store = self._session.store_for()
        if store is None:
            self._console.print("[yellow]nothing to compact — no scan yet[/yellow]")
            return
        from fackel.agents.report.report_data import build_report_context
        from fackel.agents.report.verification import build_verification_md, verify_findings

        note = build_report_context(store)
        verification = build_verification_md(verify_findings(store))
        self._session.memory_note = f"{note}\n\n{verification}".strip()
        self._tracker.reset()
        tok = len(self._session.memory_note) // 3
        self._console.print(
            f"[green]✓ compacted[/green] [dim]— session memory ≈ {tok} tokens; live meter reset[/dim]"
        )

    def _cmd_agents(self, _rest: str) -> None:
        from fackel.agents.osint.specialists import SPECIALISTS
        from fackel.agents.vuln_scan.specialists import VULN_SPECIALISTS

        table = Table(title="Specialist agents", show_header=True, border_style="dim")
        table.add_column("phase", style="dim")
        table.add_column("agent", style="bold cyan")
        table.add_column("focus")
        for s in SPECIALISTS:
            table.add_row("osint", s.name, s.focus)
        for v in VULN_SPECIALISTS:
            table.add_row("vuln_scan", v.name, v.focus)
        self._console.print(table)

    # -- scan execution (producer/consumer) --------------------------------

    def _run_scan(self, target: str, *, active_scan: bool, approve_tools: bool) -> None:
        from fackel.agents.orchestrator import run
        from fackel.agents.orchestrator import streaming as st

        self._tracker.reset()
        events: queue.Queue[tuple[Any, ...]] = queue.Queue()
        cancel = threading.Event()
        tool_cb = (
            (lambda data: self._enqueue_approval(events, data, "tool")) if approve_tools else None
        )

        def _worker() -> None:
            try:
                result = run(
                    target,
                    active_scan=active_scan,
                    approval_callback=lambda data: self._enqueue_approval(events, data, "gate"),
                    install_signal_handlers=False,
                )
                events.put(("__done__", result))
            except st.StreamCancelledError:
                events.put(("__cancelled__", None))
            except Exception as exc:  # surfaced to the operator, REPL survives
                events.put(("__error__", exc))

        self._console.print()
        self._console.print(Rule(f"{theme.glyph('scan')} scan {target}", style=theme.color("scan")))
        presenter.print_scan_header(
            self._console, target, active_scan=active_scan, approve_tools=approve_tools
        )
        started = time.perf_counter()

        # One cohesive binding of the run's streaming wiring; restored on exit.
        with st.run_session(
            event_callback=lambda p, e, d: events.put((p, e, d)),
            tool_approval=tool_cb,
            approve_tools=approve_tools,
            cancel=cancel,
        ):
            # A raw thread does NOT inherit the parent's ContextVars; copy the
            # current context (now holding the run_session bindings, incl. cancel)
            # so the worker — and the specialist threads LangGraph spawns from it —
            # see the callback and cancel flag.
            ctx = contextvars.copy_context()
            worker = threading.Thread(
                target=lambda: ctx.run(_worker), name="fackel-scan", daemon=True
            )
            worker.start()
            try:
                outcome = self._drive(events, cancel)
            finally:
                self._renderer.shutdown()
                worker.join(timeout=2.0)

        kind, payload = outcome
        if kind == "done":
            self._session.remember(payload.get("scan_id", "?"), target)
            duration = time.perf_counter() - started
            presenter.present_report(self._console, payload, target, duration)
        elif kind == "cancelled":
            self._console.print(f"[yellow]{theme.glyph('stop')} scan cancelled[/yellow]")
        else:  # error
            self._console.print(
                Panel(
                    f"[red]{payload}[/red]",
                    title=f"[red]{theme.glyph('error')} scan failed[/red]",
                    border_style="red",
                )
            )

    def _drive(
        self, events: queue.Queue[tuple[Any, ...]], cancel: threading.Event
    ) -> tuple[str, Any]:
        """Main-thread loop: drain events into the renderer until the worker ends.

        Ctrl-C sets the cooperative cancel flag and keeps draining until the
        worker reports back."""
        while True:
            try:
                item = events.get(timeout=0.2)
            except queue.Empty:
                continue
            except KeyboardInterrupt:
                cancel.set()
                self._console.print(f"[yellow]{theme.glyph('stop')} stopping…[/yellow]")
                continue
            head = item[0]
            if head == "__done__":
                return "done", item[1]
            if head == "__cancelled__":
                return "cancelled", None
            if head == "__error__":
                return "error", item[1]
            if head == "__approval__":
                self._handle_approval(item[1])
                continue
            phase, etype, data = item
            try:
                self._tracker.add_event(phase, etype, data)
                self._renderer.handle(phase, etype, data)
            except KeyboardInterrupt:
                cancel.set()
                self._console.print(f"[yellow]{theme.glyph('stop')} stopping…[/yellow]")

    def _enqueue_approval(
        self, events: queue.Queue[tuple[Any, ...]], data: dict[str, Any], kind: str
    ) -> Any:
        """Worker-side: enqueue an approval request and block for the answer."""
        box = _PendingApproval(data=data, kind=kind)
        events.put(("__approval__", box))
        box.event.wait()
        return box.result

    def _handle_approval(self, box: _PendingApproval) -> None:
        from prompt_toolkit.shortcuts import confirm

        self._renderer.shutdown()
        if box.kind == "gate":
            question = box.data.get("question", "Proceed with active scanning?")
            presenter.render_gate_approval(self._console, question)
            try:
                approved = confirm("Approve active scanning?")
            except (KeyboardInterrupt, EOFError):
                approved = False
            box.result = approved
        else:
            tool = box.data.get("tool", "?")
            args = box.data.get("args", {})
            presenter.render_tool_approval(self._console, tool, args)
            try:
                ok = confirm(f"Approve {tool}?")
            except (KeyboardInterrupt, EOFError):
                ok = False
            box.result = "approve" if ok else "reject"
        box.event.set()


def launch(*, verbose: bool = False) -> None:
    """Entry point for the interactive harness."""
    from dotenv import load_dotenv

    load_dotenv()
    from fackel.logging_config import configure_logging

    configure_logging(verbose=verbose)
    Harness(Console(), verbose=verbose).run()
