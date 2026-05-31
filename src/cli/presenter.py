"""Shared presentation for both CLI surfaces (one-shot ``scan`` and the harness).

Previously ``main.py`` and ``harness.py`` each rendered the banner, scan header,
final report and approval prompts their own way, so the same information looked
different depending on entry point.  These helpers are the single rendering path;
both surfaces call them, and only the *confirmation mechanism* (``typer.confirm``
vs ``prompt_toolkit``) stays surface-specific.

All glyphs/colours come from :mod:`cli.theme`.
"""

from __future__ import annotations

import time
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Any

from rich.console import Console, Group
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from cli import theme

# Block wordmark (figlet "ANSI Shadow"), painted top-to-bottom with the Fackel
# brand gradient.  Shown when the terminal is wide enough; narrower terminals fall
# back to a compact panel.
_WORDMARK: tuple[str, ...] = (
    "███████╗ █████╗  ██████╗██╗  ██╗███████╗██╗     ",
    "██╔════╝██╔══██╗██╔════╝██║ ██╔╝██╔════╝██║     ",
    "█████╗  ███████║██║     █████╔╝ █████╗  ██║     ",
    "██╔══╝  ██╔══██║██║     ██╔═██╗ ██╔══╝  ██║     ",
    "██║     ██║  ██║╚██████╗██║  ██╗███████╗███████╗",
    "╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝",
)

# Brand palette anchors (cyan → teal → emerald → mint), interpolated to one stop
# per wordmark row for a smooth gradient.
_BRAND_ANCHORS: tuple[str, ...] = ("#08f0f1", "#07a4b3", "#01efb0", "#5bfec2")
BRAND_PRIMARY = _BRAND_ANCHORS[0]  # brightest cyan — used for compact fallbacks


def _lerp_hex(a: str, b: str, t: float) -> str:
    """Linearly interpolate between two ``#rrggbb`` colours at fraction *t*."""
    ca = tuple(int(a[i : i + 2], 16) for i in (1, 3, 5))
    cb = tuple(int(b[i : i + 2], 16) for i in (1, 3, 5))
    r, g, bl = (round(ca[k] + (cb[k] - ca[k]) * t) for k in range(3))
    return f"#{r:02x}{g:02x}{bl:02x}"


def _gradient(anchors: tuple[str, ...], n: int) -> tuple[str, ...]:
    """Resample *anchors* into *n* evenly-spaced gradient stops."""
    if n <= 1:
        return (anchors[0],)
    segments = len(anchors) - 1
    stops: list[str] = []
    for i in range(n):
        pos = i / (n - 1) * segments
        j = min(int(pos), segments - 1)
        stops.append(_lerp_hex(anchors[j], anchors[j + 1], pos - j))
    return tuple(stops)


_BRAND_GRADIENT = _gradient(_BRAND_ANCHORS, len(_WORDMARK))


def resolve_version() -> str:
    """Return the installed package version, or a dev sentinel out of a checkout."""
    try:
        return _pkg_version("fackel")
    except PackageNotFoundError:  # pragma: no cover - only when not installed
        return "0.0.0+dev"


def _fmt_args(args: dict[str, Any]) -> str:
    """Render tool args as a stable ``k=v, k=v`` string (shared by approvals)."""
    return ", ".join(f"{k}={v}" for k, v in args.items())


# -- framing ---------------------------------------------------------------


def print_banner(console: Console) -> None:
    """Display the Fackel startup banner (shared by both surfaces).

    Wide terminals get the flame-gradient block wordmark; narrow ones fall back to
    a compact panel so nothing wraps."""
    version = resolve_version()
    console.print()
    if console.size.width < len(_WORDMARK[0]) + 2:
        console.print(
            Panel(
                f"[bold {BRAND_PRIMARY}]{theme.glyph('scan')} FACKEL[/bold {BRAND_PRIMARY}]"
                f"  [dim]v{version}[/dim]\n"
                "[dim]Autonomous OSINT & Security Intelligence[/dim]",
                border_style=BRAND_PRIMARY,
                padding=(0, 2),
            )
        )
        return
    rows = [
        Text(line, style=f"bold {style}")
        for line, style in zip(_WORDMARK, _BRAND_GRADIENT, strict=True)
    ]
    subtitle = Text.from_markup(
        f"  {theme.glyph('scan')} [dim]Autonomous OSINT & Security Intelligence[/dim]"
        f"   [dim]v{version}[/dim]"
    )
    console.print(Group(*rows, Text(""), subtitle))
    console.print()


def print_scan_header(
    console: Console, target: str, *, active_scan: bool, approve_tools: bool
) -> None:
    """Display the Target/Mode/Approval configuration table."""
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Key", style="bold", width=12)
    table.add_column("Value")
    table.add_row("Target", f"[{theme.color('accent')}]{target}[/{theme.color('accent')}]")
    mode = (
        f"[{theme.color('success')}]Active[/{theme.color('success')}]"
        if active_scan
        else f"[{theme.color('warn')}]Passive only[/{theme.color('warn')}]"
    )
    table.add_row("Mode", mode)
    if approve_tools:
        table.add_row(
            "Approval", f"[{theme.color('warn')}]Per-tool approval[/{theme.color('warn')}]"
        )
    console.print(table)
    console.print()


# -- approvals (rendering only; confirmation mechanism is the caller's) -----


def render_gate_approval(console: Console, question: str) -> None:
    """Render the active-scan gate approval panel."""
    console.print()
    console.print(
        Panel(
            f"[bold {theme.color('warn')}]{question}[/bold {theme.color('warn')}]",
            title=f"[bold {theme.color('warn')}]{theme.glyph('approval')} Approval Required"
            f"[/bold {theme.color('warn')}]",
            border_style=theme.color("warn"),
            padding=(1, 2),
            expand=True,
        )
    )


def render_tool_approval(
    console: Console, tool: str, args: dict[str, Any], *, description: str = ""
) -> None:
    """Render the per-tool approval panel (args shown as ``k=v``)."""
    body_parts: list[str] = []
    if tool:
        body_parts.append(
            f"[bold]Tool:[/bold]  [{theme.color('accent')}]{tool}[/{theme.color('accent')}]"
        )
    if args:
        body_parts.append(f"[bold]Args:[/bold]  [dim]{_fmt_args(args)}[/dim]")
    if description:
        body_parts.append(f"\n{description}")
    body = "\n".join(body_parts) if body_parts else (description or str(args))
    console.print()
    console.print(
        Panel(
            body,
            title=f"[bold {theme.color('warn')}]{theme.glyph('approval')} Tool Approval Required"
            f"[/bold {theme.color('warn')}]",
            border_style=theme.color("warn"),
            padding=(1, 2),
            expand=True,
        )
    )


# -- final report ----------------------------------------------------------


def present_report(
    console: Console,
    result: dict[str, Any],
    target: str,
    duration: float,
    *,
    output: Path | None = None,
) -> bool:
    """Render the report to the console and persist the full Markdown to disk.

    Returns ``True`` if a report was rendered, ``False`` when the result carried
    no report (caller decides how to signal that)."""
    report = result.get("report", "")
    if not report.strip():
        console.print(f"[{theme.color('warn')}]no report generated[/{theme.color('warn')}]")
        return False

    console.print()
    console.print(Rule(f"{theme.glyph('report')} Report", style=theme.color("report")))
    console.print(Markdown(report))
    console.print()
    console.print(
        Panel(
            f"[{theme.color('success')}]{theme.glyph('done')} Scan complete[/{theme.color('success')}]"
            f"  [dim]{duration:.1f}s elapsed[/dim]",
            border_style=theme.color("success"),
            padding=(0, 2),
        )
    )

    from fackel.report_writer import build_full_report

    if output is None:
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        safe = target.replace("/", "_").replace(":", "_")
        ts = time.strftime("%Y%m%d_%H%M%S")
        output = reports_dir / f"{safe}_{ts}.md"

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(build_full_report(result), encoding="utf-8")
    console.print(
        f"[{theme.color('success')}]{theme.glyph('saved')} Full report saved to {output}"
        f"[/{theme.color('success')}]"
    )
    return True
