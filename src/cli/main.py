"""Fackel CLI — pentest scan runner."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from fackel.agents.orchestrator.streaming import set_event_callback, set_tool_approval

from . import presenter
from .renderer import EventRenderer

app = typer.Typer(help="Fackel CLI")
console = Console()

_VERSION = presenter.resolve_version()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"fackel {_VERSION}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def _main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the Fackel version and exit.",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show LLM reasoning and tool details (interactive mode)"
    ),
) -> None:
    """Fackel — autonomous OSINT & security intelligence.

    Run with no subcommand to launch the interactive harness (parallel agent
    lanes, inline approvals, /ask, context management)."""
    if ctx.invoked_subcommand is None:
        from .harness import launch

        launch(verbose=verbose)
        raise typer.Exit()


@app.command()
def repl(
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show LLM reasoning and tool output details"
    ),
) -> None:
    """Launch the interactive harness (same as running ``fackel`` with no command)."""
    from .harness import launch

    launch(verbose=verbose)


def _print_provider_status(
    status_list: list[tuple[Any, bool]],
) -> None:
    """Print provider key configuration as a Rich table."""
    table = Table(title="Provider Status", show_header=True, border_style="dim")
    table.add_column("Provider", style="bold")
    table.add_column("Variables", style="dim")
    table.add_column("Status")
    for spec, configured in status_list:
        vars_str = ", ".join(spec.env_vars)
        status = "[green]✓ configured[/green]" if configured else "[red]✗ missing[/red]"
        table.add_row(spec.provider, vars_str, status)
    console.print(table)
    console.print()


def _make_approval_prompt(
    renderer: EventRenderer,
) -> tuple[Any, Any]:
    """Create approval prompt closures that pause the Live area."""

    def approval_prompt(interrupt_data: dict[str, Any]) -> bool:
        renderer._persist_content()
        renderer._stop_live()
        question = interrupt_data.get("question", "Proceed with active scanning?")
        presenter.render_gate_approval(console, question)
        approved = typer.confirm("  Approve?", default=True)
        if approved:
            console.print(
                "  [bold green]✓ Approved[/bold green]  "
                "[dim]— proceeding with active scanning[/dim]",
            )
        else:
            console.print(
                "  [bold red]✗ Rejected[/bold red]  [dim]— skipping active scanning[/dim]",
            )
        console.print()
        return approved

    def tool_approval_prompt(interrupt_data: dict[str, Any]) -> str:
        renderer._persist_content()
        renderer._stop_live()
        description = interrupt_data.get("description", "")
        if description == str(interrupt_data):
            description = ""
        tool_name = interrupt_data.get("tool", "")
        args = interrupt_data.get("args", {})
        presenter.render_tool_approval(console, tool_name, args, description=description)
        approved = typer.confirm("  Approve tool execution?", default=True)
        verdict = (
            "[bold green]✓ Approved[/bold green]" if approved else "[bold red]✗ Rejected[/bold red]"
        )
        tool_label = f"[cyan]{tool_name}[/cyan] " if tool_name else ""
        console.print(f"  {verdict}  {tool_label}")
        console.print()
        return "approve" if approved else "reject"

    return approval_prompt, tool_approval_prompt


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain or IP"),
    active_scan: bool = typer.Option(
        True,
        "--active-scan/--no-active-scan",
        help="Enable active scanning phases",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write full report to this file (default: auto-named in ./reports/)",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show LLM reasoning and tool output details"
    ),
    check_providers: bool = typer.Option(
        False, "--check-providers", help="Print provider key status before scan"
    ),
    approve_tools: bool = typer.Option(
        False,
        "--approve-tools",
        help="Require per-tool-call approval for active scanning tools",
    ),
    timeout: int | None = typer.Option(
        None,
        "--timeout",
        help=(
            "Global scan timeout in seconds; 0 (or negative) disables it. "
            "Overrides FACKEL_SCAN_TIMEOUT (default 3600)."
        ),
    ),
) -> None:
    """Run an autonomous scan against a target.

    Fackel runs the full OSINT → active scan → vulnerability → triage →
    report pipeline start-to-finish with real-time Rich output showing
    tool execution, LLM reasoning, and phase progress.
    """
    from dotenv import load_dotenv

    load_dotenv()
    from fackel.logging_config import configure_logging
    from fackel.provider_keys import get_provider_key_status

    configure_logging(verbose=verbose)

    presenter.print_banner(console)

    if check_providers:
        _print_provider_status(get_provider_key_status())

    presenter.print_scan_header(
        console, target, active_scan=active_scan, approve_tools=approve_tools
    )

    from fackel.provider_keys import get_unavailable_tool_names

    unavailable = get_unavailable_tool_names()
    if unavailable:
        console.print("[yellow]⚠ Tools disabled (missing API keys):[/yellow]")
        for tool_name, (provider, missing_vars) in unavailable.items():
            vars_str = ", ".join(missing_vars)
            console.print(f"  [dim]• {tool_name} — {provider} ({vars_str})[/dim]")
        console.print()

    from fackel.agents.orchestrator import run

    renderer = EventRenderer(console, verbose=verbose)
    set_event_callback(renderer.handle)
    approval_prompt, tool_approval_prompt = _make_approval_prompt(renderer)

    if approve_tools:
        set_tool_approval(enabled=True, callback=tool_approval_prompt)
        console.print("[yellow]⚠ Tool-level approval enabled for active scanning tools[/yellow]")
        console.print()

    started_at = time.perf_counter()

    result = _execute_scan(
        renderer,
        run,
        target,
        active_scan,
        approval_prompt,
        started_at,
        timeout,
    )
    _render_report(result, output, target, started_at)


def _execute_scan(
    renderer: EventRenderer,
    run_fn: Any,
    target: str,
    active_scan: bool,
    approval_prompt: Any,
    started_at: float,
    timeout: int | None = None,
) -> dict[str, Any]:
    """Run the orchestrator and handle interrupts / errors."""
    try:
        result: dict[str, Any] = run_fn(
            target,
            active_scan=active_scan,
            approval_callback=approval_prompt,
            timeout=timeout,
        )
        return result
    except KeyboardInterrupt:
        renderer.shutdown()
        elapsed = time.perf_counter() - started_at
        console.print()
        console.print(
            Panel(
                "[bold yellow]Scan interrupted by user[/bold yellow]\n"
                f"[dim]Elapsed: {elapsed:.1f}s[/dim]",
                title="[bold yellow]⚠ Interrupted[/bold yellow]",
                border_style="yellow",
                padding=(1, 2),
                expand=True,
            )
        )
        raise typer.Exit(code=130) from None
    except Exception as exc:
        renderer.shutdown()
        elapsed = time.perf_counter() - started_at
        console.print()
        console.print(
            Panel(
                f"[bold red]{exc}[/bold red]\n[dim]Elapsed: {elapsed:.1f}s[/dim]",
                title="[bold red]✗ Scan Failed[/bold red]",
                border_style="red",
                padding=(1, 2),
                expand=True,
            )
        )
        raise typer.Exit(code=1) from exc
    finally:
        renderer.shutdown()
        set_event_callback(None)
        set_tool_approval(enabled=False)


def _render_report(
    result: dict[str, Any],
    output: Path | None,
    target: str,
    started_at: float,
) -> None:
    """Display the LLM report on console and save the full report to disk.

    Thin CLI wrapper around :func:`cli.presenter.present_report` that enforces the
    one-shot exit semantics (non-zero exit when no report was produced)."""
    duration = time.perf_counter() - started_at
    if not presenter.present_report(console, result, target, duration, output=output):
        typer.echo("\nError: no report generated.", err=True)
        raise typer.Exit(code=1)


@app.command()
def scans() -> None:
    """List persisted scans available for diffing/monitoring."""
    from fackel.persistence import list_scans
    from fackel.settings import get_settings

    data_dir = Path(get_settings().data_dir).expanduser()
    ids = list_scans(data_dir)
    if not ids:
        console.print(f"[yellow]No persisted scans found in {data_dir}[/yellow]")
        return
    table = Table(title=f"Persisted scans ({data_dir})")
    table.add_column("scan_id", style="cyan")
    for sid in ids:
        table.add_row(sid)
    console.print(table)


@app.command()
def diff(
    baseline: str = typer.Argument(..., help="Baseline scan id (earlier)"),
    current: str = typer.Argument(..., help="Current scan id (later)"),
) -> None:
    """Show what changed between two scans (new / resolved / changed entities)."""
    from fackel.persistence import diff_scans, format_diff, list_scans, load_scan
    from fackel.settings import get_settings

    data_dir = Path(get_settings().data_dir).expanduser()
    available = set(list_scans(data_dir))
    for scan_id in (baseline, current):
        if scan_id not in available:
            console.print(f"[red]Scan '{scan_id}' not found in {data_dir}[/red]")
            console.print("[dim]Run 'fackel scans' to list available scans.[/dim]")
            raise typer.Exit(code=1)

    result = diff_scans(load_scan(baseline, data_dir), load_scan(current, data_dir))
    console.print(format_diff(result))


def _require_scan(scan_id: str) -> tuple[Any, Path]:
    """Resolve a scan id to its loaded store, exiting cleanly if missing."""
    from fackel.persistence import list_scans, load_scan
    from fackel.settings import get_settings

    data_dir = Path(get_settings().data_dir).expanduser()
    if scan_id not in set(list_scans(data_dir)):
        console.print(f"[red]Scan '{scan_id}' not found in {data_dir}[/red]")
        console.print("[dim]Run 'fackel scans' to list available scans.[/dim]")
        raise typer.Exit(code=1)
    return load_scan(scan_id, data_dir), data_dir


@app.command()
def graph(
    scan_id: str = typer.Argument(..., help="Scan id to export"),
    fmt: str = typer.Option("mermaid", "--format", "-f", help="Output format: mermaid | json"),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write to file instead of stdout"
    ),
) -> None:
    """Export a scan's knowledge graph as a Mermaid diagram or JSON."""
    import json as _json

    from fackel.persistence.graph_export import to_json, to_mermaid

    store, _ = _require_scan(scan_id)
    rendered = _json.dumps(to_json(store), indent=2) if fmt == "json" else to_mermaid(store)

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]📈 Graph ({fmt}) written to {output}[/green]")
    else:
        console.print(rendered)


@app.command()
def ask(
    scan_id: str = typer.Argument(..., help="Scan id to query"),
    question: str = typer.Argument(..., help="Natural-language question about the attack surface"),
) -> None:
    """Ask a natural-language question about a scan's knowledge graph."""
    from dotenv import load_dotenv

    load_dotenv()
    from fackel.agents.query import answer_query

    store, _ = _require_scan(scan_id)
    console.print(answer_query(store, question))


if __name__ == "__main__":
    app()
