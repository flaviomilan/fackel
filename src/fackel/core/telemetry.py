import logging
import os
from contextlib import contextmanager
from typing import Any

try:
    from langfuse import Langfuse
except ImportError:
    Langfuse = None


logger = logging.getLogger("fackel.telemetry")


class TelemetryService:
    def __init__(self):
        self._client = self._init_langfuse()
        self._session_id: str | None = None
        self._user_id = os.getenv("LANGFUSE_USER_ID") or "fackel"
        self._environment = os.getenv("LANGFUSE_TRACING_ENVIRONMENT") or "local"
        self._release = os.getenv("LANGFUSE_RELEASE")
        self._trace_context = None

    def _init_langfuse(self) -> Langfuse | None:
        if Langfuse is None:
            logger.info("Langfuse not installed; tracing disabled")
            return None

        pk = os.getenv("LANGFUSE_PUBLIC_KEY")
        sk = os.getenv("LANGFUSE_SECRET_KEY")
        if not (pk and sk):
            logger.debug("Langfuse credentials missing; tracing disabled")
            return None

        try:
            return Langfuse(
                public_key=pk,
                secret_key=sk,
                host=os.getenv("LANGFUSE_HOST"),
            )
        except Exception as exc:
            logger.warning(f"Langfuse init failed: {exc}")
            return None

    @contextmanager
    def trace_run(self, domain: str, active_scan: bool):
        if not self._client:
            yield None
            return

        session_id = self._session_id or domain
        name = "fackel.run"
        try:
            if hasattr(self._client, "start_as_current_span"):
                with self._client.start_as_current_span(
                    name=name,
                    input={
                        "domain": domain,
                        "active_scan": active_scan,
                        "session_id": session_id,
                        "user_id": self._user_id,
                    },
                    metadata={
                        "active_scan": active_scan,
                        "session_id": session_id,
                        "environment": self._environment,
                    },
                ) as span:
                    self._trace_context = span
                    yield span
            else:
                yield None
        except Exception as exc:
            logger.error(f"Failed to trace run: {exc}")
            yield None
        finally:
            self._trace_context = None

    def record_tool(
        self,
        tool: str,
        domain: str,
        output: Any,
        error: Exception | None = None,
        duration_ms: float | None = None,
    ):
        if not self._client or not self._trace_context:
            return

        safe_output = (
            str(output)[:2000] + "..."
            if isinstance(output, str) and len(output) > 2000
            else output
        )

        try:
            self._client.start_span(
                name=f"tool.{tool}",
                input={"domain": domain, "tool": tool},
                output=safe_output if not error else None,
                metadata={
                    "status": "error" if error else "ok",
                    "error": str(error) if error else None,
                    "duration_ms": duration_ms,
                    "environment": self._environment,
                },
            ).end()
        except Exception:
            pass

    def record_planner(
        self,
        domain: str,
        prompt: str,
        output: str,
        plan: list[str],
        error: Exception | None = None,
    ):
        if not self._client or not self._trace_context:
            return

        try:
            self._client.start_span(
                name="planner.decision",
                input={"domain": domain, "prompt": prompt},
                output={"raw": output, "plan": plan},
                metadata={
                    "status": "error" if error else "ok",
                    "error": str(error) if error else None,
                    "environment": self._environment,
                },
            ).end()
        except Exception:
            pass
