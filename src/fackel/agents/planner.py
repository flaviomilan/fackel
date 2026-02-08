from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List

from fackel.core.observability import get_observability, observe, get_langfuse_handler
from fackel.core.registry import ToolRegistry
from fackel.schemas.state import AgentState


@dataclass
class PlannerResult:
    plan: list[str]
    prompt: str
    raw_output: str


class LLMPlanner:
    """Optional LLM-based planner.

    Keeps surface area small: caller provides registry + state and planner returns
    an ordered list of tool names. Use only in authorized/paid contexts.
    """

    def __init__(self, model: str = "gpt-4o-mini", temperature: float = 0.1):
        try:
            from langchain_openai import ChatOpenAI
        except Exception as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "langchain-openai não instalado; instale para habilitar o planner LLM"
            ) from exc

        # Initialize with Langfuse callback handler
        callbacks = get_langfuse_handler()
        self.llm = ChatOpenAI(
            model=model,
            temperature=temperature,
            callbacks=callbacks if callbacks else None,
        )
        self.model = model
        self.observability = get_observability()

    @observe(name="llm_planning")
    def plan(self, state: AgentState, registry: ToolRegistry) -> PlannerResult:
        """Return plan plus prompt/raw output for tracing."""
        available = registry.names()
        completed = ", ".join(state.completed) if state.completed else "(nenhum)"
        errors = "; ".join(state.errors[-5:]) if state.errors else "(nenhum)"
        evidence_count = (
            len(state.store.report.evidence)
            if state.store and state.store.report
            else 0
        )

        prompt = f"""
Você é o planner de um agente de pentest/autonomous recon. Escolha a próxima sequência de ferramentas.
Contexto:
- Domínio: {state.domain}
- active_scan: {state.active_scan}
- Ferramentas disponíveis: {", ".join(available)}
- Já executadas: {completed}
- Erros recentes: {errors}
- Evidências coletadas: {evidence_count}

Regras:
- Respeite active_scan: só use ferramentas ativas se active_scan=True.
- Priorize cobertura ampla primeiro (WHOIS/DNS/search/cert infra) depois validações mais pesadas.
- Responda apenas um JSON com a lista ordenada de nomes das ferramentas.
"""

        resp = self.llm.invoke(prompt)  # type: ignore[arg-type]
        text = resp if isinstance(resp, str) else getattr(resp, "content", "[]")
        
        # Track LLM call with Langfuse
        self.observability.track_llm_call(
            component="planner",
            model=self.model,
            prompt=prompt,
            response=resp,
            metadata={
                "domain": state.domain,
                "active_scan": state.active_scan,
                "available_tools": len(available),
                "completed_tools": len(state.completed) if state.completed else 0,
            },
        )
        
        plan: List[str] = []
        try:
            data = json.loads(text)
            if isinstance(data, list):
                plan = [x for x in data if isinstance(x, str)]
        except Exception:
            plan = []

        if not plan:
            plan = registry.plan(set(available), state.active_scan)

        return PlannerResult(plan=plan, prompt=prompt, raw_output=text)
