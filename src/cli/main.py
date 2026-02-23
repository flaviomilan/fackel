"""Fackel CLI — pentest scan runner."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule

load_dotenv()

app = typer.Typer(help="Fackel CLI")
console = Console()


# ── Phase labels ───────────────────────────────────────────────────────────

_PHASE_LABELS = {
    "osint": "OSINT",
    "approval": "Approval",
    "port_scan": "Port Scan",
    "vuln_scan": "Vuln Scan",
    "triage": "Triage",
    "report": "Report",
}


# ── HIL approval handler ──────────────────────────────────────────────────


def _approval_prompt(interrupt_data: dict) -> bool:
    """Prompt the user to approve or reject active scanning."""
    question = interrupt_data.get("question", "Proceed with active scanning?")
    console.print()
    console.print(Panel(question, title="⚠ Approval Required", border_style="yellow"))
    return typer.confirm("Approve?", default=True)


# ── Event renderer ─────────────────────────────────────────────────────────


def _make_event_callback(verbose: bool):
    """Return a callback that prints agent ReAct events to the terminal."""

    def _callback(phase: str, event_type: str, data: dict[str, Any]) -> None:
        label = _PHASE_LABELS.get(phase, phase)

        if event_type == "start":
            console.print()
            console.print(Rule(f"▶ {label}", style="bold blue"))

        elif event_type == "tool_call":
            tool = data.get("tool", "?")
            args = data.get("args", {})
            args_str = ", ".join(
                f"{k}={v}" for k, v in args.items() if v not in ("", None)
            )
            console.print(f"  🔧 {tool}({args_str})", style="dim")

        elif event_type == "tool_error":
            tool = data.get("tool", "?")
            error = data.get("error", "unknown error")
            # Show a single clean line; strip tool banners / multi-line noise.
            first_line = error.strip().splitlines()[-1].strip() if error.strip() else "unknown error"
            console.print(f"  [red]✗ {tool}: {first_line}[/red]", style="dim")

        elif event_type == "tool_result":
            if verbose:
                tool = data.get("tool", "?")
                content = data.get("content", "")
                preview = content[:200] + "…" if len(content) > 200 else content
                console.print(f"  ← {tool}: {preview}", style="dim")

        elif event_type == "reasoning":
            if verbose:
                content = data.get("content", "")
                for line in content.splitlines():
                    console.print(f"  💭 {line}", style="dim italic")

        elif event_type == "summary":
            content = data.get("content", "")
            if content:
                console.print()
                console.print(Panel(
                    Markdown(content),
                    title=f"📋 {label} Summary",
                    border_style="cyan",
                    padding=(1, 2),
                ))

        elif event_type == "done":
            console.print(f"  [green]✓ {label} complete[/green]")

    return _callback


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain or IP"),
    active_scan: bool = typer.Option(
        True,
        "--active-scan/--no-active-scan",
        help="Enable active scanning phases",
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write report to file"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show LLM reasoning and detailed logs"
    ),
    check_providers: bool = typer.Option(
        False, "--check-providers", help="Print provider key status before scan"
    ),
) -> None:
    """Run a full scan workflow and emit the final report."""
    from fackel.agents.orchestrator import run
    from fackel.agents.orchestrator.nodes import set_event_callback
    from fackel.provider_keys import get_provider_key_status

    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(name)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    if verbose:
        logging.getLogger("fackel").setLevel(logging.DEBUG)

    if check_providers:
        typer.echo("Provider key status:")
        for spec, configured in get_provider_key_status():
            status = "configured" if configured else "missing"
            vars_str = ", ".join(spec.env_vars)
            typer.echo(f"  {spec.provider} ({vars_str}): {status}")
        typer.echo("")

    typer.echo(f"Target: {target}")
    typer.echo(f"Active scan: {'yes' if active_scan else 'no'}")

    # Show tools that will be skipped due to missing API keys.
    from fackel.provider_keys import get_unavailable_tool_names

    unavailable = get_unavailable_tool_names()
    if unavailable:
        console.print("[yellow]⚠ Tools disabled (missing API keys):[/yellow]")
        for tool_name, (provider, missing_vars) in unavailable.items():
            vars_str = ", ".join(missing_vars)
            console.print(f"  [dim]• {tool_name} — {provider} ({vars_str})[/dim]")
        console.print()

    # Register real-time event callback
    set_event_callback(_make_event_callback(verbose))
    started_at = time.perf_counter()

    try:
        result = run(
            target,
            active_scan=active_scan,
            approval_callback=_approval_prompt,
        )
    except KeyboardInterrupt:
        typer.echo("\nScan interrupted by user.", err=True)
        raise typer.Exit(code=130)
    except Exception as exc:
        typer.echo(f"\nScan failed: {exc}", err=True)
        raise typer.Exit(code=1)
    finally:
        set_event_callback(None)

    report = result.get("report", "")
    duration = time.perf_counter() - started_at

    if not report.strip():
        typer.echo("\nError: no report generated.", err=True)
        raise typer.Exit(code=1)

    console.print()
    console.print(Rule("Final Report", style="bold green"))
    if output:
        output.write_text(report, encoding="utf-8")
        console.print(Markdown(report))
        console.print(f"\n[dim]Report saved to {output} ({duration:.1f}s)[/dim]")
    else:
        console.print(Markdown(report))
        console.print(f"\n[dim]Completed in {duration:.1f}s[/dim]")


if __name__ == "__main__":
    app()
