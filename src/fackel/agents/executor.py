from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from fackel.core.normalizers.registry import NormalizerRegistry
from fackel.core.store import StructuredStore
from fackel.core.telemetry import TelemetryService
from fackel.core.tracking import RawToolEvent, TrackingService


class ToolExecutor:
    def __init__(
        self,
        normalizers: NormalizerRegistry,
        tracking: TrackingService | None,
        telemetry: TelemetryService,
    ):
        self.normalizers = normalizers
        self.tracking = tracking
        self.telemetry = telemetry
        self.logger = logging.getLogger("fackel.executor")

    def execute(
        self,
        tool_name: str,
        tool_fn: Callable | Any,
        domain: str,
        store: StructuredStore,
    ) -> ExecResult:
        self.logger.info(f"Executing tool: {tool_name}")
        start_ts = time.perf_counter()
        
        try:
            raw_output = self._invoke_tool(tool_fn, domain)
            duration_ms = (time.perf_counter() - start_ts) * 1000

            # 1. Legacy normalization
            self.normalizers.normalize(tool_name, raw_output, store)

            # 2. Telemetry
            self.telemetry.record_tool(
                tool_name, domain, raw_output, duration_ms=duration_ms
            )

            # 3. New Tracking
            if self.tracking:
                payload = (
                    raw_output if isinstance(raw_output, dict) else {"raw": raw_output}
                )
                self.tracking.process(
                    RawToolEvent(
                        tool=tool_name,
                        run_id=domain,
                        observed_at=datetime.now(timezone.utc),
                        payload=payload,
                    )
                )

            return ExecResult(
                success=True, output=raw_output, duration_ms=duration_ms
            )

        except Exception as exc:
            duration_ms = (time.perf_counter() - start_ts) * 1000
            self.logger.error(f"Tool {tool_name} failed: {exc}")
            self.telemetry.record_tool(tool_name, domain, None, error=exc)
            return ExecResult(success=False, error=str(exc))

    def _invoke_tool(self, tool_fn: Any, domain: str) -> Any:
        # Support both LangChain tools and raw callables
        if hasattr(tool_fn, "func"):
            return tool_fn.func(domain)
        elif hasattr(tool_fn, "invoke"):
            return tool_fn.invoke({"domain": domain})
        elif callable(tool_fn):
            return tool_fn(domain)
        else:
            raise TypeError(f"Tool {tool_fn} is not callable")


class ExecResult:
    def __init__(
        self,
        success: bool,
        output: Any = None,
        error: str | None = None,
        duration_ms: float = 0.0,
    ):
        self.success = success
        self.output = output
        self.error = error
        self.duration_ms = duration_ms

    def __str__(self) -> str:
        return str(self.output) if self.success else f"Error: {self.error}"
