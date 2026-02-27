"""Fackel CLI — pentest scan runner."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from fackel.agents.orchestrator.streaming import (
    set_event_callback,
    set_guidance_enabled,
    set_tool_approval,
)

from .renderer import EventRenderer

app = typer.Typer(help="Fackel CLI")
console = Console()

_VERSION = "0.1.0"


def _print_banner() -> None:
    """Display the Fackel startup banner."""
    console.print()
    console.print(
        Panel(
            "[bold bright_red]🔥 FACKEL[/bold bright_red]"
            f"  [dim]v{_VERSION}[/dim]\n"
            "[dim]Autonomous OSINT & Security Intelligence[/dim]",
            border_style="red",
            padding=(0, 2),
        )
    )


def _print_scan_header(target: str, *, active_scan: bool, approve_tools: bool) -> None:
    """Display a structured scan configuration summary."""
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Key", style="bold", width=12)
    table.add_column("Value")
    table.add_row("Target", f"[bold cyan]{target}[/bold cyan]")
    mode = "[green]Active[/green]" if active_scan else "[yellow]Passive only[/yellow]"
    table.add_row("Mode", mode)
    if approve_tools:
        table.add_row("Approval", "[yellow]Per-tool approval[/yellow]")
    console.print(table)
    console.print()


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


def _make_guidance_prompt(renderer: EventRenderer) -> Callable[[dict[str, Any]], str]:
    """Create a guidance prompt closure that pauses the Live area.

    Returns a callable ``(interrupt_data: dict) -> str`` that shows
    a Rich Panel with the phase description and collects free-text input
    from the operator.  Returns an empty string when the operator skips.
    """

    def guidance_prompt(interrupt_data: dict[str, Any]) -> str:
        renderer._persist_content()
        renderer._stop_live()
        phase = interrupt_data.get("phase", "?")
        description = interrupt_data.get("description", "")

        body = f"[bold]Phase:[/bold]  [cyan]{phase}[/cyan]\n\n{description}"
        console.print()
        console.print(
            Panel(
                body,
                title="[bold blue]📝 Operator Guidance[/bold blue]",
                border_style="blue",
                padding=(1, 2),
                expand=True,
            )
        )
        text = console.input("  [bold blue]Guidance[/bold blue] [dim](Enter to skip):[/dim] ")
        text = text.strip()
        if text:
            console.print(
                f"  [bold green]✓ Guidance recorded[/bold green]  [dim]{text[:60]}{'…' if len(text) > 60 else ''}[/dim]"
            )
        else:
            console.print("  [dim]— skipped[/dim]")
        console.print()
        return text

    return guidance_prompt


def _make_approval_prompt(
    renderer: EventRenderer,
) -> tuple[Any, Any]:
    """Create approval prompt closures that pause the Live area."""

    def approval_prompt(interrupt_data: dict[str, Any]) -> bool:
        renderer._persist_content()
        renderer._stop_live()
        question = interrupt_data.get("question", "Proceed with active scanning?")
        console.print()
        console.print(
            Panel(
                f"[bold yellow]{question}[/bold yellow]",
                title="[bold yellow]⚠ Approval Required[/bold yellow]",
                border_style="yellow",
                padding=(1, 2),
                expand=True,
            )
        )
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
        description = interrupt_data.get("description", str(interrupt_data))
        tool_name = interrupt_data.get("tool", "")
        args = interrupt_data.get("args", {})

        body_parts: list[str] = []
        if tool_name:
            body_parts.append(f"[bold]Tool:[/bold]  [cyan]{tool_name}[/cyan]")
        if args:
            args_str = ", ".join(f"{k}={v}" for k, v in args.items())
            body_parts.append(f"[bold]Args:[/bold]  [dim]{args_str}[/dim]")
        if description and description != str(interrupt_data):
            body_parts.append(f"\n{description}")

        body = "\n".join(body_parts) if body_parts else description
        console.print()
        console.print(
            Panel(
                body,
                title="[bold yellow]🔧 Tool Approval Required[/bold yellow]",
                border_style="yellow",
                padding=(1, 2),
                expand=True,
            )
        )
        approved = typer.confirm("  Approve tool execution?", default=True)
        if approved:
            tool_label = f"[cyan]{tool_name}[/cyan] " if tool_name else ""
            console.print(f"  [bold green]✓ Approved[/bold green]  {tool_label}")
        else:
            tool_label = f"[cyan]{tool_name}[/cyan] " if tool_name else ""
            console.print(f"  [bold red]✗ Rejected[/bold red]  {tool_label}")
        console.print()
        return "approve" if approved else "reject"

    return approval_prompt, tool_approval_prompt


@app.command()
def scan(
    target: str | None = typer.Argument(
        None, help="Target domain or IP (omit for interactive mode)"
    ),
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
    guided: bool = typer.Option(
        False,
        "--guided",
        help="Enable per-phase operator guidance (provide instructions before each agent phase)",
    ),
) -> None:
    """Run a full scan workflow and emit the final report."""
    from dotenv import load_dotenv

    from fackel.agents.orchestrator import run

    load_dotenv()
    from fackel.logging_config import configure_logging
    from fackel.provider_keys import get_provider_key_status

    configure_logging(verbose=verbose)

    _print_banner()

    if check_providers:
        _print_provider_status(get_provider_key_status())

    # --- Interactive intake when no target provided ---
    initial_guidance = ""
    if target is None:
        from .intake import interactive_intake

        intent = interactive_intake(console)
        target = intent.target
        active_scan = intent.active_scan
        initial_guidance = intent.guidance
        if initial_guidance:
            guided = True

    _print_scan_header(target, active_scan=active_scan, approve_tools=approve_tools)

    from fackel.provider_keys import get_unavailable_tool_names

    unavailable = get_unavailable_tool_names()
    if unavailable:
        console.print("[yellow]⚠ Tools disabled (missing API keys):[/yellow]")
        for tool_name, (provider, missing_vars) in unavailable.items():
            vars_str = ", ".join(missing_vars)
            console.print(f"  [dim]• {tool_name} — {provider} ({vars_str})[/dim]")
        console.print()

    renderer = EventRenderer(console, verbose=verbose)
    set_event_callback(renderer.handle)
    approval_prompt, tool_approval_prompt = _make_approval_prompt(renderer)

    if approve_tools:
        set_tool_approval(enabled=True, callback=tool_approval_prompt)
        console.print("[yellow]⚠ Tool-level approval enabled for active scanning tools[/yellow]")
        console.print()

    guidance_prompt: Callable[[dict[str, Any]], str] | None = None
    if guided:
        set_guidance_enabled(True)
        guidance_prompt = _make_guidance_prompt(renderer)
        console.print("[blue]📝 Per-phase operator guidance enabled[/blue]")
        console.print()

    started_at = time.perf_counter()

    result = _execute_scan(
        renderer,
        run,
        target,
        active_scan,
        approval_prompt,
        guidance_prompt,
        initial_guidance,
        started_at,
    )
    _render_report(result, output, target, started_at)


def _execute_scan(
    renderer: EventRenderer,
    run_fn: Any,
    target: str,
    active_scan: bool,
    approval_prompt: Any,
    guidance_prompt: Callable[[dict[str, Any]], str] | None,
    initial_guidance: str,
    started_at: float,
) -> dict[str, Any]:
    """Run the orchestrator and handle interrupts / errors."""
    try:
        result: dict[str, Any] = run_fn(
            target,
            active_scan=active_scan,
            approval_callback=approval_prompt,
            guidance_callback=guidance_prompt,
            initial_guidance=initial_guidance,
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
        set_guidance_enabled(False)


def _render_report(
    result: dict[str, Any],
    output: Path | None,
    target: str,
    started_at: float,
) -> None:
    """Display the LLM report on console and save the full report to disk."""
    report = result.get("report", "")
    duration = time.perf_counter() - started_at

    if not report.strip():
        typer.echo("\nError: no report generated.", err=True)
        raise typer.Exit(code=1)

    console.print()
    console.print(Rule("📝 Final Report", style="bold green"))
    console.print(Markdown(report))
    console.print()
    console.print(
        Panel(
            f"[green]✓ Scan complete[/green]  [dim]{duration:.1f}s elapsed[/dim]",
            border_style="green",
            padding=(0, 2),
        )
    )

    from fackel.report_writer import build_full_report

    full_md = build_full_report(result)

    if output is None:
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        safe_target = re.sub(r"[^\w.\-]", "_", target)
        ts = time.strftime("%Y%m%d_%H%M%S")
        output = reports_dir / f"{safe_target}_{ts}.md"

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(full_md, encoding="utf-8")
    console.print(f"[green]📄 Full report saved to {output}[/green]")


if __name__ == "__main__":
    app()
