from __future__ import annotations

import json
from pathlib import Path

import typer

from fackel.agents.graph_agent import LangGraphAgent

app = typer.Typer(help="Fackel – Agente Autônomo de OSINT")


@app.command()
def run(
    domain: str = typer.Argument(..., help="Domínio ou host alvo"),
    active_scan: bool = typer.Option(False, help="Habilita ferramentas ativas (ex: Nmap)"),
    output: Path | None = typer.Option(None, help="Salvar relatório HTML/Markdown"),
    save_json: bool = typer.Option(True, help="Salvar saída estruturada (JSON)"),
):
    agent = LangGraphAgent(active_scan=active_scan)
    result = agent.run(domain)

    summary = result["summary"]
    store = result["store"]

    typer.echo(summary)

    if output:
        output_path = Path(output)
        output_path.write_text(summary, encoding="utf-8")
        typer.echo(f"[Exporter] Markdown salvo em {output_path}")
        if save_json:
            json_path = output_path.with_suffix(".json")
            store.save_json(str(json_path))
            typer.echo(f"[Exporter] JSON estruturado salvo em {json_path}")
    else:
        if save_json:
            json_path = Path(f"{domain}_report.json")
            store.save_json(str(json_path))
            typer.echo(f"[Exporter] JSON estruturado salvo em {json_path}")


@app.command()
def doctor():
    """Mostra informações básicas do ambiente."""
    import platform
    import sys

    typer.echo(f"Python: {sys.version.split()[0]}")
    typer.echo(f"Plataforma: {platform.platform()}")
    typer.echo("Ferramentas disponíveis serão calculadas em runtime pelo agente.")


if __name__ == "__main__":
    app()
