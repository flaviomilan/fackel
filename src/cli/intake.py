"""Interactive intake — conversational scan setup when no target is provided.

Uses the configured LLM with structured output to extract scan parameters
from free-text operator input.  Falls back to a simple prompt when the
LLM cannot parse the intent.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from rich.console import Console
from rich.panel import Panel

from fackel.agents.prompts import load_template


class ScanIntent(BaseModel):
    """Structured scan parameters extracted from operator input."""

    target: str = Field(
        default="",
        description="Domain or IP to scan (empty if not identified)",
    )
    active_scan: bool = Field(
        default=True,
        description="Whether to enable active scanning phases",
    )
    guidance: str = Field(
        default="",
        description="Operator guidance for the first phase (empty if none)",
    )


def interactive_intake(console: Console) -> ScanIntent:
    """Run interactive chat to collect scan parameters from the operator.

    Shows a conversational prompt, sends the input to the configured LLM
    with structured output, and returns the parsed :class:`ScanIntent`.
    Loops until a valid target is obtained.
    """
    console.print()
    console.print(
        Panel(
            "[bold]Nenhum alvo informado.[/bold]\n\n"
            "Descreva o que deseja fazer — por exemplo:\n"
            '[dim]"Quero fazer um scan completo no eversafe.info focando em subdomínios"[/dim]\n'
            '[dim]"Reconhecimento passivo no 184.72.230.53"[/dim]\n'
            '[dim]"Scan the domain example.com, skip WordPress scanning"[/dim]',
            title="[bold blue]💬 Interactive Mode[/bold blue]",
            border_style="blue",
            padding=(1, 2),
            expand=True,
        )
    )

    while True:
        console.print()
        user_input = console.input("[bold blue]🔥 fackel>[/bold blue] ").strip()
        if not user_input:
            continue

        intent = _parse_intent(user_input)

        if not intent.target:
            console.print(
                "[yellow]Não consegui identificar um alvo (domínio ou IP). "
                "Tente novamente.[/yellow]"
            )
            continue

        _show_intent_summary(console, intent)
        return intent


def _parse_intent(user_input: str) -> ScanIntent:
    """Use the configured LLM to extract scan intent from free text."""
    try:
        from fackel.agents.config import build_llm

        llm = build_llm("intake", temperature=0)
        structured_llm = llm.with_structured_output(ScanIntent)
        result: Any = structured_llm.invoke(
            [
                {"role": "system", "content": load_template("intake_system")},
                {"role": "user", "content": user_input},
            ]
        )
        if isinstance(result, ScanIntent):
            return result
        return ScanIntent()  # fallback
    except Exception:
        # If LLM fails, do a best-effort regex extraction
        return _fallback_parse(user_input)


def _fallback_parse(user_input: str) -> ScanIntent:
    """Regex-based fallback when the LLM is unavailable."""
    import re

    # Try to find a domain or IP in the input
    domain_pattern = re.compile(
        r"(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})"
    )
    ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

    match = domain_pattern.search(user_input) or ip_pattern.search(user_input)
    target = match.group(0) if match else ""

    passive_keywords = {"passiv", "reconhecimento", "reconnaissance", "osint only", "no-active"}
    active = not any(kw in user_input.lower() for kw in passive_keywords)

    return ScanIntent(target=target, active_scan=active, guidance="")


def _show_intent_summary(console: Console, intent: ScanIntent) -> None:
    """Display a confirmation panel with the extracted parameters."""
    mode = "[green]Active[/green]" if intent.active_scan else "[yellow]Passive only[/yellow]"
    lines = [
        f"[bold]Target:[/bold]  [cyan]{intent.target}[/cyan]",
        f"[bold]Mode:[/bold]    {mode}",
    ]
    if intent.guidance:
        lines.append(f"[bold]Guidance:[/bold] [dim]{intent.guidance}[/dim]")

    console.print()
    console.print(
        Panel(
            "\n".join(lines),
            title="[bold green]✓ Scan configurado[/bold green]",
            border_style="green",
            padding=(1, 2),
            expand=True,
        )
    )
