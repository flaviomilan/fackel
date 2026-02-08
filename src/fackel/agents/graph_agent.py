from __future__ import annotations

import logging
import os
import time
from typing import Any

from langgraph.graph import END, StateGraph

from capabilities import detect_capabilities
from collectors.collectors import get_tool_registry
from fackel.core.normalizers import BUILTIN_NORMALIZERS, NormalizerRegistry
from fackel.core.store import StructuredStore
from fackel.reporting import render_structured_summary
from fackel.schemas.state import AgentState

try:
    from langfuse import Langfuse
except Exception:  # pragma: no cover - optional dependency failure should not break agent
    Langfuse = None


class LangGraphAgent:
    def __init__(self, active_scan: bool = False):
        self.active_scan = active_scan
        self.capabilities = detect_capabilities()
        self.tool_registry = get_tool_registry()
        self.normalizers = NormalizerRegistry()
        # Register builtin normalizers
        for name in self.tool_registry.names():
            self.normalizers.register(name, BUILTIN_NORMALIZERS)

        self._langfuse_client = self._init_langfuse()
        self._langfuse_trace = None
        self._langfuse_trace_cm = None
        self._session_id = None
        self._user_id = os.getenv("LANGFUSE_USER_ID") or "fackel"
        self._environment = os.getenv("LANGFUSE_TRACING_ENVIRONMENT") or "local"
        self._release = os.getenv("LANGFUSE_RELEASE")

        self.logger = logging.getLogger("fackel.agent")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("[%(levelname)s] %(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

        self.graph = self._build_graph()

    def _init_langfuse(self):
        if Langfuse is None:
            logging.getLogger("fackel.agent").info("Langfuse não instalado; tracing desabilitado")
            return None
        pk = os.getenv("LANGFUSE_PUBLIC_KEY")
        sk = os.getenv("LANGFUSE_SECRET_KEY")
        if not (pk and sk):
            logging.getLogger("fackel.agent").info("Langfuse sem credenciais; defina LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY para habilitar tracing")
            return None
        try:
            return Langfuse(
                public_key=pk,
                secret_key=sk,
                host=os.getenv("LANGFUSE_HOST"),
            )
        except Exception as exc:
            logging.getLogger("fackel.agent").warning(f"Langfuse indisponível: {exc}")
            return None

    def _start_trace(self, domain: str):
        if not self._langfuse_client:
            return None
        try:
            session_id = self._session_id or domain
            if hasattr(self._langfuse_client, "start_as_current_span"):
                cm = self._langfuse_client.start_as_current_span(
                    name="fackel.run",
                    input={
                        "domain": domain,
                        "active_scan": self.active_scan,
                        "session_id": session_id,
                        "user_id": self._user_id,
                    },
                    metadata={
                        "active_scan": self.active_scan,
                        "session_id": session_id,
                        "user_id": self._user_id,
                    },
                )
                span = cm.__enter__()
                self._langfuse_trace_cm = cm
                return span
            else:
                logging.getLogger("fackel.agent").warning(
                    "Langfuse client não expõe start_as_current_span; tracing desabilitado"
                )
                return None
        except Exception as exc:
            logging.getLogger("fackel.agent").warning(
                f"Falha ao iniciar trace Langfuse; continuando sem tracing: {exc}"
            )
            return None

    def _record_tool_span(
        self,
        tool: str,
        domain: str,
        output: Any,
        error: Exception | None = None,
        duration_ms: float | None = None,
    ):
        if not self._langfuse_trace:
            return
        try:
            session_id = self._session_id or domain
            safe_output = output
            if isinstance(output, str) and len(output) > 2000:
                safe_output = output[:2000] + "..."
            child = self._langfuse_client.start_span(
                name=f"tool.{tool}",
                input={
                    "domain": domain,
                    "tool": tool,
                    "session_id": session_id,
                    "user_id": self._user_id,
                    "environment": self._environment,
                },
                output=safe_output if error is None else None,
                metadata={
                    "error": str(error) if error else None,
                    "session_id": session_id,
                    "user_id": self._user_id,
                    "status": "error" if error else "ok",
                    "completed": tool if error is None else None,
                    "duration_ms": duration_ms,
                    "environment": self._environment,
                    "release": self._release,
                },
            )
            child.end()
        except Exception:
            return

    def _initial_plan(self) -> list[str]:
        available = self.capabilities.available
        return self.tool_registry.plan(available, self.active_scan)

    def _build_graph(self):
        sg = StateGraph(AgentState)
        sg.add_node("plan", self._plan_node)
        sg.add_node("run", self._run_node)

        sg.add_edge("plan", "run")
        sg.add_conditional_edges(
            "run",
            self._should_continue,
            {"continue": "run", "stop": END},
        )
        sg.set_entry_point("plan")
        return sg.compile()

    def _plan_node(self, state: AgentState) -> AgentState:
        if not state.plan:
            state.plan = self._initial_plan()
        return state

    def _run_node(self, state: AgentState) -> AgentState:
        if not state.plan:
            return state
        tool_name = state.plan.pop(0)
        tool_fn = self.tool_registry.get(tool_name)
        self.logger.info(f"Executando tool: {tool_name} (restantes: {len(state.plan)})")
        if not tool_fn:
            state.errors.append(f"tool {tool_name} not found")
            state.confidence -= 0.05
            return state
        try:
            start_ts = time.perf_counter()
            # Tools decorated with @tool return StructuredTool; prefer .func
            if hasattr(tool_fn, "func"):
                raw_output = tool_fn.func(state.domain)
            elif hasattr(tool_fn, "invoke"):
                raw_output = tool_fn.invoke({"domain": state.domain})
            elif callable(tool_fn):
                raw_output = tool_fn(state.domain)
            else:
                raise TypeError("tool is not callable")
            duration_ms = (time.perf_counter() - start_ts) * 1000
            self.normalizers.normalize(tool_name, raw_output, state.store)
            state.last_result = str(raw_output)
            state.completed.append(tool_name)
            state.confidence = min(1.0, state.confidence + 0.02)
            self._record_tool_span(tool_name, state.domain, raw_output, None, duration_ms)
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_ts) * 1000 if "start_ts" in locals() else None
            state.errors.append(f"{tool_name}: {exc}")
            state.confidence = max(0.0, state.confidence - 0.1)
            self._record_tool_span(tool_name, state.domain, None, exc, duration_ms)
        return state

    def _should_continue(self, state: AgentState) -> str:
        if not state.plan:
            return "stop"
        if len(state.completed) >= 25:
            return "stop"
        return "continue"

    def run(self, domain: str) -> dict[str, Any]:
        state = AgentState(domain=domain, active_scan=self.active_scan, store=StructuredStore(domain=domain))
        self._session_id = os.getenv("LANGFUSE_SESSION_ID") or domain
        self.logger.info(f"Iniciando execução para {domain} | active_scan={self.active_scan}")
        self._langfuse_trace = self._start_trace(domain)
        raw_state = self.graph.invoke(state)
        final_state = state if isinstance(raw_state, AgentState) else AgentState(**raw_state)
        summary = render_structured_summary(final_state.store)
        self.logger.info("Execução concluída")
        if self._langfuse_trace:
            try:
                self._langfuse_trace.update(
                    output=summary,
                    metadata={
                        "completed": final_state.completed,
                        "errors": final_state.errors,
                        "confidence": final_state.confidence,
                        "session_id": self._session_id or domain,
                        "user_id": self._user_id,
                        "environment": self._environment,
                        "release": self._release,
                    },
                )
            except Exception:
                pass
        if self._langfuse_trace_cm:
            try:
                self._langfuse_trace_cm.__exit__(None, None, None)
            except Exception:
                pass
        return {
            "summary": summary,
            "store": final_state.store,
            "confidence": final_state.confidence,
            "errors": final_state.errors,
            "completed": final_state.completed,
        }
