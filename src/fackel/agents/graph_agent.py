from __future__ import annotations

from typing import Any, Dict, List

from langgraph.graph import END, StateGraph

from collectors.collectors import ACTIVE_TOOL_NAMES, PASSIVE_TOOL_NAMES, TOOL_REGISTRY
from fackel.core.normalizers import BUILTIN_NORMALIZERS, NormalizerRegistry
from fackel.core.store import StructuredStore
from fackel.reporting import render_structured_summary
from fackel.schemas.state import AgentState
from capabilities import detect_capabilities


class LangGraphAgent:
    def __init__(self, active_scan: bool = False):
        self.active_scan = active_scan
        self.capabilities = detect_capabilities()
        self.normalizers = NormalizerRegistry()
        # Register builtin normalizers
        for name in TOOL_REGISTRY.keys():
            self.normalizers.register(name, BUILTIN_NORMALIZERS)

        self.graph = self._build_graph()

    def _initial_plan(self) -> List[str]:
        available = self.capabilities.available
        plan = [name for name in PASSIVE_TOOL_NAMES if name in available]
        if self.active_scan:
            plan.extend([name for name in ACTIVE_TOOL_NAMES if name in available])
        return plan

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
        tool_fn = TOOL_REGISTRY.get(tool_name)
        if not tool_fn:
            state.errors.append(f"tool {tool_name} not found")
            state.confidence -= 0.05
            return state
        try:
            # Tools decorated with @tool return StructuredTool; prefer .func
            if hasattr(tool_fn, "func"):
                raw_output = tool_fn.func(state.domain)
            elif hasattr(tool_fn, "invoke"):
                raw_output = tool_fn.invoke({"domain": state.domain})
            elif callable(tool_fn):
                raw_output = tool_fn(state.domain)
            else:
                raise TypeError("tool is not callable")
            self.normalizers.normalize(tool_name, raw_output, state.store)
            state.last_result = str(raw_output)
            state.completed.append(tool_name)
            state.confidence = min(1.0, state.confidence + 0.02)
        except Exception as exc:
            state.errors.append(f"{tool_name}: {exc}")
            state.confidence = max(0.0, state.confidence - 0.1)
        return state

    def _should_continue(self, state: AgentState) -> str:
        if not state.plan:
            return "stop"
        if len(state.completed) >= 25:
            return "stop"
        return "continue"

    def run(self, domain: str) -> Dict[str, Any]:
        state = AgentState(domain=domain, active_scan=self.active_scan, store=StructuredStore(domain=domain))
        raw_state = self.graph.invoke(state)
        final_state = state if isinstance(raw_state, AgentState) else AgentState(**raw_state)
        summary = render_structured_summary(final_state.store)
        return {
            "summary": summary,
            "store": final_state.store,
            "confidence": final_state.confidence,
            "errors": final_state.errors,
            "completed": final_state.completed,
        }
