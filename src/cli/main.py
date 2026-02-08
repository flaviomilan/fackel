from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse


import typer
from dotenv import load_dotenv

from fackel.agents.graph_agent import LangGraphAgent
from fackel.agents.reporter import LLMReporter
from fackel.core.store import StructuredStore
from fackel.reporting.renderer import render_structured_summary
from fackel.schemas.state import AgentState

# Load environment variables once at startup so all commands share them
load_dotenv()


def _safe_stem(target: str) -> str:
    """Generate a filesystem-safe stem from a domain or URL."""
    parsed = urlparse(target)
    base = parsed.netloc or parsed.path or target
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", base)
    return safe or "report"


app = typer.Typer(help="Fackel – Agente Autônomo de OSINT")


@app.command()
def run(
    domain: str = typer.Argument(..., help="Domínio ou host alvo"),
    active_scan: bool = typer.Option(
        False, help="Habilita ferramentas ativas (ex: Nmap)"
    ),
    use_llm_planner: bool = typer.Option(
        False, help="Habilita planner LLM (requer OPENAI_API_KEY e langchain-openai)"
    ),
    planner_model: str = typer.Option(
        "gpt-4o-mini", help="Modelo LLM usado no planner"
    ),

    planner_temperature: float = typer.Option(0.1, help="Temperatura do planner LLM"),
    output: Path | None = typer.Option(None, help="Salvar relatório HTML/Markdown"),
    save_json: bool = typer.Option(True, help="Salvar saída estruturada (JSON)"),
    resume: bool = typer.Option(
        False, help="Carregar relatório existente (JSON) se houver, evitando novo scan"
    ),
):
    if resume:
        safe_stem = _safe_stem(domain)
        json_path = Path(f"{safe_stem}_report.json")
        if json_path.exists():
            typer.echo(f"📁 Carregando dados existentes de: {json_path}")
            try:
                store = StructuredStore.load_json(str(json_path))
                
                # Generate LLM Report
                reporter = LLMReporter(model=planner_model, temperature=planner_temperature)
                dummy_state = AgentState(domain=domain, active_scan=active_scan, store=store)
                llm_report = reporter.generate(dummy_state)
                
                summary = render_structured_summary(store)
                if llm_report:
                    summary += "\n\n" + "-" * 40 + "\n\n"
                    summary += "### LLM Analyst Report\n\n"
                    summary += llm_report
                
                typer.echo(summary)
                _write_outputs(domain, summary, store, output, save_json)
                return
            except Exception as e:
                typer.echo(f"⚠️ Erro ao carregar JSON: {e}. Iniciando novo scan.")
        else:
            typer.echo(f"ℹ️ Arquivo {json_path} não encontrado. Iniciando novo scan.")

    agent = LangGraphAgent(
        active_scan=active_scan,
        use_llm_planner=use_llm_planner,
        planner_model=planner_model,
        planner_temperature=planner_temperature,
    )
    result = agent.run(domain)
    summary = result["summary"]
    store = result["store"]

    typer.echo(summary)
    _write_outputs(domain, summary, store, output, save_json)


@app.command()
def doctor():
    """Mostra informações básicas do ambiente."""
    import platform
    import sys

    typer.echo(f"Python: {sys.version.split()[0]}")
    typer.echo(f"Plataforma: {platform.platform()}")
    typer.echo("Ferramentas disponíveis serão calculadas em runtime pelo agente.")



from cli.web import serve_api

@app.command(name="serve")
def serve(
    host: str = typer.Option("0.0.0.0", help="Host interface to bind"),
    port: int = typer.Option(8000, help="Port to listen on"),
    reload: bool = typer.Option(False, help="Enable auto-reload for dev"),
):
    """Start the API server (requires fastapi and uvicorn)."""
    serve_api(host, port, reload)


if __name__ == "__main__":
    app()


def _write_outputs(
    domain: str, summary: str, store, output: Path | None, save_json: bool
) -> None:
    """Persist outputs; keeps console echo logic together."""
    if output:
        output_path = Path(output)
        output_path.write_text(summary, encoding="utf-8")
        typer.echo(f"[Exporter] Markdown salvo em {output_path}")
        if save_json:
            json_path = output_path.with_suffix(".json")
            store.save_json(str(json_path))
            typer.echo(f"[Exporter] JSON estruturado salvo em {json_path}")
        return

    if save_json:
        safe_stem = _safe_stem(domain)
        json_path = Path(f"{safe_stem}_report.json")
        store.save_json(str(json_path))
        typer.echo(f"[Exporter] JSON estruturado salvo em {json_path}")
