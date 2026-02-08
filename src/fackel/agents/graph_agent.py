from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any

from langgraph.graph import END, StateGraph

from capabilities import detect_capabilities
from collectors.collectors import get_tool_registry

from fackel.agents.executor import ToolExecutor
from fackel.agents.planner import LLMPlanner
from fackel.agents.reporter import LLMReporter
from fackel.agents.policy import ToolPolicyEngine
from fackel.core.normalizers import BUILTIN_NORMALIZERS, NormalizerRegistry
from fackel.core.bootstrap import setup_tracking
from fackel.core.observability import get_observability
from fackel.core.store import StructuredStore
from fackel.core.telemetry import TelemetryService
from fackel.reporting.renderer import render_structured_summary
from fackel.schemas.state import AgentState


class LangGraphAgent:
    def __init__(
        self,
        active_scan: bool = False,
        use_llm_planner: bool = False,
        planner_model: str = "gpt-4o-mini",
        planner_temperature: float = 0.1,
        enable_tracking: bool = True,
        save_to_db: bool = True,
        mongo_uri: str = "mongodb://localhost:27017/",
        db_name: str = "fackel",
    ):
        self.active_scan = active_scan
        self.capabilities = detect_capabilities()
        self.tool_registry = get_tool_registry()
        
        # Setup persistence
        self.save_to_db = save_to_db
        self.scan_repo = None
        self.embedding_svc = None
        
        if save_to_db:
            try:
                from pymongo import MongoClient
                from fackel.core.scan_repository import MongoScanRepository
                from fackel.query.embeddings import ScanEmbeddingService
                
                client = MongoClient(mongo_uri)
                db = client[db_name]
                
                self.scan_repo = MongoScanRepository(db)
                self.embedding_svc = ScanEmbeddingService(db)
                
                logging.getLogger("fackel.agent").info("✓ Scan persistence enabled")
            except Exception as e:
                logging.getLogger("fackel.agent").warning(
                    f"Scan persistence disabled: {e}"
                )
                self.save_to_db = False

        self.normalizers = NormalizerRegistry()
        for name in self.tool_registry.names():
            self.normalizers.register(name, BUILTIN_NORMALIZERS)

        self.use_llm_planner = use_llm_planner
        self._planner = None
        if self.use_llm_planner:
            try:
                self._planner = LLMPlanner(
                    model=planner_model, temperature=planner_temperature
                )
            except Exception as exc:
                logging.getLogger("fackel.agent").warning(
                    f"Planner LLM init failed: {exc}"

                )
                self.use_llm_planner = False

        self._reporter = LLMReporter()

        self.telemetry = TelemetryService()
        self.tracking = setup_tracking(enable_tracking)
        self.observability = get_observability()
        self.logger = logging.getLogger("fackel.agent")
        if not self.logger.handlers:
            logging.basicConfig(
                format="[%(levelname)s] %(message)s", level=logging.INFO
            )
        
        self.executor = ToolExecutor(
            normalizers=self.normalizers,
            tracking=self.tracking,
            telemetry=self.telemetry,
        )

        self.policy = ToolPolicyEngine()

        self.graph = self._build_graph()

    def run(self, domain: str) -> dict[str, Any]:
        """Entry point for the agent execution."""
        self._start_trace(domain)
        
        # Start Langfuse trace for the entire scan
        with self.observability.trace_scan(
            domain=domain,
            active_scan=self.active_scan,
            metadata={"mode": "sync"},
        ):
            initial_state = AgentState(
                domain=domain,
                active_scan=self.active_scan,
                store=StructuredStore(domain),
            )
            
            # Invoke the graph
            final_state = self.graph.invoke(initial_state)
        

        # Validate state type (dict vs Pydantic)
        if isinstance(final_state, dict):
            store = final_state.get("store")
            final_report = final_state.get("final_report")
            analysis_log = final_state.get("analysis_log")
        else:
            store = final_state.store
            final_report = final_state.final_report
            analysis_log = getattr(final_state, "analysis_log", [])

            # Generate summary
            summary = render_structured_summary(store)
            
                # Add quality scores to trace
            if store and store.report:
                findings_count = len(store.report.findings)
                critical_findings = sum(
                    1 for f in store.report.findings 
                    if f.severity in ["critical", "high"]
                )
                
                self.observability.add_trace_score(
                    name="findings_count",
                    value=findings_count,
                    comment=f"{findings_count} total findings",
                )
                
                self.observability.add_trace_score(
                    name="critical_findings",
                    value=critical_findings,
                    comment=f"{critical_findings} critical/high findings",
                )
                
                # Coverage score
                if isinstance(final_state, dict):
                    completed = final_state.get("completed", [])
                    errors = final_state.get("errors", {})
                else:
                    completed = final_state.completed
                    errors = final_state.errors
                
                coverage = len(completed) / max(1, len(completed) + len(errors))
                self.observability.add_trace_score(
                    name="scan_coverage",
                    value=coverage,
                    comment=f"{len(completed)} tools executed",
                )
            else:
                critical_findings = 0
            
            # Add tags
            tags = ["security", "recon"]
            if self.active_scan:
                tags.append("active_scan")
            if critical_findings > 0:
                tags.append("has_critical_findings")
            self.observability.add_trace_tags(tags)
            
            # Persist scan to database
            if self.save_to_db and self.scan_repo and store and store.report:
                try:
                    scan_id = self.scan_repo.save_scan(
                        domain=domain,
                        report=store.report,
                        metadata={
                            "active_scan": self.active_scan,
                            "tool_count": len(completed) if completed else 0,
                            "findings_count": findings_count,
                            "critical_findings": critical_findings,
                        }
                    )
                    self.logger.info(f"✅ Scan saved to database: {scan_id}")
                    
                    # Store scan_id for final event
                    # We'll add this to the state so it can be accessed in stream_run
                    if hasattr(final_state, '__dict__'):
                        final_state.__dict__['_scan_id'] = scan_id
                    elif isinstance(final_state, dict):
                        final_state['_scan_id'] = scan_id
                    
                    # Generate embedding asynchronously (non-blocking)
                    if self.embedding_svc:
                        import asyncio
                        try:
                            asyncio.create_task(
                                self.embedding_svc.embed_scan(
                                    scan_id, domain, store.report
                                )
                            )
                        except RuntimeError:
                            # No event loop running, skip embedding
                            self.logger.debug("Skipping embedding (no async loop)")
                    
                except Exception as e:
                    self.logger.warning(f"Failed to save scan: {e}")
            
            # Flush to ensure all data is sent
            self.observability.flush()
        
        if final_report:
            summary += "\n\n" + "-" * 40 + "\n\n"
            summary += "### LLM Analyst Report\n\n"
            summary += final_report

        if analysis_log:
             summary += "\n\n" + "-" * 40 + "\n\n"
             summary += "### Detalhes da Análise Incremental (Por Ferramenta)\n"
             for log in analysis_log:
                 summary += f"\n#### Ferramenta: {log['tool']}\n"
                 summary += f"{log['analysis']}\n"

        return {
            "summary": summary,
            "store": store,
            "state": final_state
        }

    def stream_run(self, domain: str):
        """
        Executes the agent in streaming mode, yielding updates as steps complete.
        Useful for Web UIs/Frontends to show progress bars, logs, and partial results.
        """
        self._start_trace(domain)
        initial_state = AgentState(
            domain=domain,
            active_scan=self.active_scan,
            store=StructuredStore(domain),
        )
        
        # Track scan_id for final event
        scan_id = None

        # LangGraph stream yields dictionaries like {'node_name': {updated_state_keys}}
        for step in self.graph.stream(initial_state):
            for node_name, state_update in step.items():
                base_event = {
                    "type": "step_update",
                    "step": node_name,
                    "timestamp": datetime.now().isoformat(),
                    "details": {}
                }

                # Enhance event details based on the node
                if node_name == "plan":
                    current_plan = state_update.get("plan", [])
                    base_event["details"]["current_plan"] = current_plan
                    base_event["details"]["remaining"] = len(current_plan)

                elif node_name == "run":
                    completed = state_update.get("completed", [])
                    last_tool = completed[-1] if completed else None
                    base_event["details"]["last_tool"] = last_tool
                    base_event["details"]["completed_count"] = len(completed)
                    
                    # Emit base event first
                    yield base_event

                    # Emit partial report if we have incremental analysis
                    logs = state_update.get("analysis_log", [])
                    if logs:
                        latest = logs[-1]
                        partial_event = {
                            "type": "partial_report",
                            "step": node_name,
                            "timestamp": datetime.now().isoformat(),
                            "details": {
                                "tool": latest.get("tool"),
                                "analysis": latest.get("analysis"),
                                "timestamp": latest.get("timestamp"),
                            },
                        }
                        yield partial_event
                    
                    # Emit policy decisions if any
                    policy_decisions = getattr(state_update, "_policy_decisions", None) or state_update.get("_policy_decisions", [])
                    if policy_decisions:
                        policy_event = {
                            "type": "policy_decision",
                            "step": node_name,
                            "timestamp": datetime.now().isoformat(),
                            "details": {
                                "decisions": policy_decisions,
                                "tools_added": [d["tool"] for d in policy_decisions],
                            },
                        }
                        yield policy_event
                    
                    continue

                elif node_name == "report":
                    # Provide full artifacts so frontends can render immediately
                    final_report = state_update.get("final_report", "")
                    analysis_log = state_update.get("analysis_log", [])
                    store = state_update.get("store")
                    summary = render_structured_summary(store) if store else ""
                    
                    # Extract scan_id if available
                    scan_id = state_update.get("_scan_id")

                    final_event = {
                        "type": "final_report",
                        "step": node_name,
                        "timestamp": datetime.now().isoformat(),
                        "scan_id": scan_id,  # ✨ ADD scan_id here
                        "domain": domain,
                        "details": {
                            "final_report": final_report,
                            "summary": summary,
                            "analysis_log": analysis_log,
                        },
                    }
                    yield final_event
                    continue

                yield base_event

    def _start_trace(self, domain: str):
        return self.telemetry.trace_run(domain, self.active_scan)

    def _deterministic_plan(self, completed: list[str]) -> list[str]:
        available = self.capabilities.available
        plan = self.tool_registry.plan(available, self.active_scan)
        return [name for name in plan if name not in completed]


    def _build_graph(self):
        sg = StateGraph(AgentState)
        sg.add_node("plan", self._plan_node)
        sg.add_node("run", self._run_node)
        sg.add_node("report", self._report_node)

        sg.add_edge("plan", "run")
        sg.add_conditional_edges(
            "run",
            self._should_continue,
            {"continue": "plan", "stop": "report"},
        )
        sg.add_edge("report", END)
        sg.set_entry_point("plan")
        return sg.compile()

    def _should_continue(self, state: AgentState) -> str:
        if not state.plan:
            return "stop"
        return "continue"

    def _report_node(self, state: AgentState) -> AgentState:
        self.logger.info("Generating final report...")
        state.final_report = self._reporter.generate(state)
        return state

    def _plan_node(self, state: AgentState) -> AgentState:
        deterministic_plan = self._deterministic_plan(state.completed)
        if self.use_llm_planner and self._planner:
            try:
                result = self._planner.plan(state, self.tool_registry)
                filtered = [name for name in result.plan if name in deterministic_plan]
                state.plan = filtered if filtered else deterministic_plan
                state.decisions.append(f"planner.llm:{state.plan}")
                self.telemetry.record_planner(
                    state.domain, result.prompt, result.raw_output, state.plan
                )
                return state
            except Exception as exc:
                self.logger.warning(f"Planner LLM failed; falling back: {exc}")
                self.telemetry.record_planner(
                    state.domain, "", "", deterministic_plan, exc
                )

        state.plan = deterministic_plan
        state.decisions.append(f"planner.deterministic:{state.plan}")
        return state

    def _run_node(self, state: AgentState) -> AgentState:
        if not state.plan:
            return state

        tool_name = state.plan.pop(0)
        tool_fn = self.tool_registry.get(tool_name)
        self.logger.info(f"Running tool: {tool_name} (remaining: {len(state.plan)})")

        if not tool_fn:
            state.errors.append(f"tool {tool_name} not found")
            state.confidence -= 0.05
            return state

        result = self.executor.execute(tool_name, tool_fn, state.domain, state.store)

        if result.success:
            state.last_result = str(result.output)
            state.completed.append(tool_name)
            state.confidence = min(1.0, state.confidence + 0.02)
            
            # --- Incremental Analysis ---
            if self._reporter and self._reporter.llm:
                try:
                    # Convert output to string (may be dict/list/any type)
                    output_str = str(result.output) if result.output is not None else ""
                    
                    # Analyze specific tool output
                    analysis = self._reporter.analyze_incremental(tool_name, output_str, state.domain)
                    
                    # Only add to log if analysis produced content
                    if analysis and analysis.strip():
                        # Create new list to avoid mutation issues (though LangGraph immutable state handles it, being explicit helps)
                        new_logs = list(state.analysis_log) if state.analysis_log else []
                        new_logs.append({
                            "tool": tool_name, 
                            "analysis": analysis,
                            "timestamp": datetime.now().isoformat()
                        })
                        state.analysis_log = new_logs
                        self.logger.info(f"✓ Incremental analysis completed for {tool_name} ({len(analysis)} chars)")
                    else:
                        self.logger.debug(f"⊘ Skipped analysis for {tool_name} (no significant findings)")
                except Exception as e:
                    self.logger.warning(f"✗ Incremental analysis failed for {tool_name}: {e}")
            # -----------------------------

            # --- Adaptive policy: enqueue tools based on detected tech ---
            policy_proposals = []
            try:
                proposals = self.policy.apply(state)
                if proposals:
                    valid = [p for p in proposals if self.tool_registry.get(p.tool)]
                    skipped = [p for p in proposals if p not in valid]

                    if valid:
                        state.plan.extend([p.tool for p in valid])
                        for p in valid:
                            state.decisions.append(f"policy.{p.rule}:{p.tool}:{p.reason}")
                            policy_proposals.append({
                                "tool": p.tool,
                                "rule": p.rule,
                                "reason": p.reason,
                            })
                        self.logger.info(
                            "Policy added tools: %s", [p.tool for p in valid]
                        )
                    if skipped:
                        self.logger.info(
                            "Policy skipped unknown tools: %s", [p.tool for p in skipped]
                        )
            except Exception as exc:  # noqa: BLE001
                self.logger.warning(f"Policy evaluation failed: {exc}")
            
            # Store policy decisions for streaming exposure
            if policy_proposals:
                if not hasattr(state, "_policy_decisions"):
                    state._policy_decisions = []
                state._policy_decisions.extend(policy_proposals)

        else:
            state.errors.append(f"{tool_name}: {result.error}")
        
        return state
