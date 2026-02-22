"""Fackel CLI — pentest scan runner."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

import typer
from dotenv import load_dotenv

load_dotenv()

app = typer.Typer(help="Fackel CLI")


# ── Phase labels ───────────────────────────────────────────────────────────

_PHASE_LABELS = {
    "osint": "OSINT",
    "port_scan": "Port Scan",
    "report": "Report",
}


# ── Event renderer ─────────────────────────────────────────────────────────


def _make_event_callback(verbose: bool):
    """Return a callback that prints agent ReAct events to the terminal."""

    def _callback(phase: str, event_type: str, data: dict[str, Any]) -> None:
        label = _PHASE_LABELS.get(phase, phase)

        if event_type == "start":
            typer.echo(f"\n{'─' * 60}")
            typer.echo(f"▶ {label}")
            typer.echo(f"{'─' * 60}")

        elif event_type == "tool_call":
            tool = data.get("tool", "?")
            args = data.get("args", {})
            args_str = ", ".join(f"{k}={v}" for k, v in args.items())
            typer.echo(f"  🔧 Calling: {tool}({args_str})")

        elif event_type == "tool_result":
            tool = data.get("tool", "?")
            content = data.get("content", "")
            preview = content[:200] + "…" if len(content) > 200 else content
            typer.echo(f"  ← {tool}: {preview}")

        elif event_type == "reasoning":
            if verbose:
                content = data.get("content", "")
                for line in content.splitlines():
                    typer.echo(f"  💭 {line}")

        elif event_type == "done":
            typer.echo(f"  ✓ {label} complete")

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
            typer.echo(f"  {spec.provider} ({spec.env_var}): {status}")
        typer.echo("")

    typer.echo(f"Target: {target}")
    typer.echo(f"Active scan: {'yes' if active_scan else 'no'}")

    # Register real-time event callback
    set_event_callback(_make_event_callback(verbose))
    started_at = time.perf_counter()

    try:
        result = run(target, active_scan=active_scan)
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

    typer.echo(f"\n{'═' * 60}")
    if output:
        output.write_text(report, encoding="utf-8")
        typer.echo(f"Report saved to {output} ({duration:.1f}s)")
    else:
        typer.echo(report)
        typer.echo(f"\nCompleted in {duration:.1f}s")


if __name__ == "__main__":
    app()
