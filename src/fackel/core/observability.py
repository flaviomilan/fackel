"""
Advanced Langfuse observability with full feature coverage.

This module provides comprehensive LLM monitoring including:
- Automatic LLM call tracking with token usage
- Custom spans with tags and metadata
- Scores and quality metrics
- Embedding tracking
- Error monitoring
- Cost tracking
"""

from __future__ import annotations

import functools
import logging
import os
import time
from contextlib import contextmanager
from typing import Any, Callable, Optional

try:
    from langfuse import Langfuse
    from langfuse.decorators import langfuse_context, observe
    from langfuse.callback import CallbackHandler
    LANGFUSE_AVAILABLE = True
except ImportError:
    LANGFUSE_AVAILABLE = False
    CallbackHandler = None
    # Create dummy decorators for when Langfuse is not installed
    def observe(*args, **kwargs):
        def decorator(func):
            return func
        return decorator if not args else decorator(args[0])
    
    class DummyContext:
        def update_current_trace(self, **kwargs): pass
        def update_current_observation(self, **kwargs): pass
        def score_current_observation(self, **kwargs): pass
        def score_current_trace(self, **kwargs): pass
        def get_current_trace_id(self): return None
        def get_current_observation_id(self): return None
    
    langfuse_context = DummyContext()


logger = logging.getLogger("fackel.observability")


class ObservabilityService:
    """
    Enhanced observability service with full Langfuse feature support.
    
    Features:
    - Automatic trace creation with rich metadata
    - Tool execution tracking with durations
    - LLM call tracking with token usage and costs
    - Embedding tracking
    - Custom scores (quality, cost, latency)
    - Tags and metadata for filtering
    - Error tracking and alerting
    """
    
    def __init__(self):
        self._client = self._init_langfuse()
        self._user_id = os.getenv("LANGFUSE_USER_ID", "fackel")
        self._environment = os.getenv("LANGFUSE_TRACING_ENVIRONMENT", "local")
        self._release = os.getenv("LANGFUSE_RELEASE")
        self._session_id: str | None = None
        self._current_domain: str | None = None
        self._trace_id: str | None = None
        
        # Cost tracking (per 1M tokens)
        self._model_costs = {
            "gpt-4o-mini": {"input": 0.15, "output": 0.60},
            "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
            "text-embedding-3-small": {"input": 0.02, "output": 0.00},
        }
        
        if self._client:
            logger.info(f"Langfuse observability enabled (env={self._environment})")
        else:
            logger.info("Langfuse observability disabled (no credentials or import error)")
    
    def _init_langfuse(self) -> Langfuse | None:
        """Initialize Langfuse client with enhanced configuration."""
        if not LANGFUSE_AVAILABLE:
            logger.debug("Langfuse not installed; install with: pip install langfuse")
            return None
        
        pk = os.getenv("LANGFUSE_PUBLIC_KEY")
        sk = os.getenv("LANGFUSE_SECRET_KEY")
        host = os.getenv("LANGFUSE_HOST", "http://localhost:3000")
        
        if not (pk and sk):
            logger.debug("Langfuse credentials missing; set LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY")
            return None
        
        try:
            client = Langfuse(
                public_key=pk,
                secret_key=sk,
                host=host,
                enabled=True,
                debug=False,
            )
            # Test connection
            client.auth_check()
            return client
        except Exception as exc:
            logger.warning(f"Langfuse init failed: {exc}")
            return None
    
    @property
    def enabled(self) -> bool:
        """Check if observability is enabled."""
        return self._client is not None
    
    def set_session(self, session_id: str):
        """Set session ID for grouping multiple runs."""
        self._session_id = session_id
    
    @contextmanager
    def trace_scan(
        self,
        domain: str,
        active_scan: bool,
        metadata: Optional[dict[str, Any]] = None,
    ):
        """
        Create a trace for an entire scan run.
        
        Usage:
            with observability.trace_scan("example.com", active_scan=True):
                # All operations here will be grouped under this trace
                pass
        """
        if not self._client:
            yield None
            return
        
        self._current_domain = domain
        session_id = self._session_id or f"scan_{domain}"
        
        trace_metadata = {
            "domain": domain,
            "active_scan": active_scan,
            "environment": self._environment,
            "session_id": session_id,
        }
        if self._release:
            trace_metadata["release"] = self._release
        if metadata:
            trace_metadata.update(metadata)
        
        try:
            trace = self._client.trace(
                name="fackel_scan",
                user_id=self._user_id,
                session_id=session_id,
                input={"domain": domain, "active_scan": active_scan},
                metadata=trace_metadata,
                tags=["security", "recon", "active" if active_scan else "passive"],
            )
            self._trace_id = trace.id
            
            # Update context for decorators
            langfuse_context.update_current_trace(
                session_id=session_id,
                user_id=self._user_id,
                tags=["security", "recon"],
                metadata=trace_metadata,
            )
            
            yield trace
            
            # Flush to ensure all data is sent
            self._client.flush()
        except Exception as exc:
            logger.error(f"Failed to create trace: {exc}")
            yield None
        finally:
            self._current_domain = None
            self._trace_id = None
    
    @observe(name="tool_execution")
    def track_tool_execution(
        self,
        tool_name: str,
        domain: str,
        execution_fn: Callable[[], Any],
    ) -> tuple[Any, float, Exception | None]:
        """
        Track a tool execution with automatic timing and error handling.
        
        Returns:
            tuple: (result, duration_ms, error)
        """
        start_time = time.time()
        result = None
        error = None
        
        # Update observation with tool context
        langfuse_context.update_current_observation(
            name=f"tool.{tool_name}",
            metadata={
                "tool": tool_name,
                "domain": domain,
                "environment": self._environment,
            },
        )
        
        try:
            result = execution_fn()
            status = "success"
        except Exception as exc:
            error = exc
            status = "error"
            logger.error(f"Tool {tool_name} failed: {exc}")
        
        duration_ms = (time.time() - start_time) * 1000
        
        # Add tags and scores
        langfuse_context.update_current_observation(
            metadata={
                "status": status,
                "duration_ms": duration_ms,
                "has_error": error is not None,
            },
        )
        
        # Score based on duration (faster is better)
        latency_score = 1.0 if duration_ms < 1000 else (0.5 if duration_ms < 5000 else 0.2)
        langfuse_context.score_current_observation(
            name="latency",
            value=latency_score,
            comment=f"{duration_ms:.0f}ms",
        )
        
        if error:
            langfuse_context.score_current_observation(
                name="success",
                value=0.0,
                comment=str(error)[:200],
            )
        else:
            langfuse_context.score_current_observation(
                name="success",
                value=1.0,
            )
        
        return result, duration_ms, error
    
    @observe(name="llm_call")
    def track_llm_call(
        self,
        component: str,
        model: str,
        prompt: str,
        response: Any,
        metadata: Optional[dict[str, Any]] = None,
    ):
        """
        Track an LLM call with token usage and cost calculation.
        
        Args:
            component: Name of component making the call (e.g., "planner", "analyzer")
            model: Model name (e.g., "gpt-4o-mini")
            prompt: Input prompt
            response: LLM response (should have response_metadata)
            metadata: Additional metadata
        """
        if not self._client:
            return
        
        # Extract token usage from response
        input_tokens = 0
        output_tokens = 0
        total_cost = 0.0
        
        if hasattr(response, "response_metadata"):
            usage = response.response_metadata.get("token_usage", {})
            input_tokens = usage.get("prompt_tokens", 0)
            output_tokens = usage.get("completion_tokens", 0)
            
            # Calculate cost
            if model in self._model_costs:
                costs = self._model_costs[model]
                total_cost = (
                    (input_tokens / 1_000_000) * costs["input"] +
                    (output_tokens / 1_000_000) * costs["output"]
                )
        
        response_text = ""
        if isinstance(response, str):
            response_text = response
        elif hasattr(response, "content"):
            response_text = response.content
        
        # Update observation
        obs_metadata = {
            "component": component,
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "cost_usd": total_cost,
            "environment": self._environment,
        }
        if metadata:
            obs_metadata.update(metadata)
        
        langfuse_context.update_current_observation(
            input=prompt[:5000],  # Truncate long prompts
            output=response_text[:5000],  # Truncate long responses
            metadata=obs_metadata,
            usage={
                "input": input_tokens,
                "output": output_tokens,
                "total": input_tokens + output_tokens,
                "unit": "TOKENS",
            },
        )
        
        # Score based on cost (lower is better)
        cost_score = 1.0 if total_cost < 0.01 else (0.5 if total_cost < 0.05 else 0.2)
        langfuse_context.score_current_observation(
            name="cost_efficiency",
            value=cost_score,
            comment=f"${total_cost:.4f}",
        )
        
        # Token efficiency score (output/input ratio)
        if input_tokens > 0:
            efficiency = min(1.0, output_tokens / input_tokens)
            langfuse_context.score_current_observation(
                name="token_efficiency",
                value=efficiency,
                comment=f"{output_tokens}/{input_tokens} tokens",
            )
    
    @observe(name="embedding_call")
    def track_embedding(
        self,
        text: str,
        model: str = "text-embedding-3-small",
        cached: bool = False,
        metadata: Optional[dict[str, Any]] = None,
    ):
        """
        Track an embedding generation call.
        
        Args:
            text: Input text
            model: Embedding model name
            cached: Whether result came from cache
            metadata: Additional metadata
        """
        if not self._client:
            return
        
        # Estimate tokens (rough: 1 token ≈ 4 chars)
        estimated_tokens = len(text) // 4
        
        obs_metadata = {
            "model": model,
            "cached": cached,
            "estimated_tokens": estimated_tokens,
            "text_length": len(text),
            "environment": self._environment,
        }
        if metadata:
            obs_metadata.update(metadata)
        
        langfuse_context.update_current_observation(
            input=text[:1000],  # Truncate for storage
            metadata=obs_metadata,
        )
        
        # Score cache hit (cached is much better)
        if cached:
            langfuse_context.score_current_observation(
                name="cache_hit",
                value=1.0,
                comment="Cache hit - no API call",
            )
        else:
            langfuse_context.score_current_observation(
                name="cache_hit",
                value=0.0,
                comment="Cache miss - API call made",
            )
    
    def add_trace_score(
        self,
        name: str,
        value: float,
        comment: Optional[str] = None,
    ):
        """
        Add a score to the current trace.
        
        Common scores:
        - overall_quality: 0-1
        - findings_count: number of findings
        - critical_findings: number of critical findings
        - scan_coverage: percentage of planned tools executed
        """
        if not self._client:
            return
        
        try:
            langfuse_context.score_current_trace(
                name=name,
                value=value,
                comment=comment,
            )
        except Exception as exc:
            logger.debug(f"Failed to add trace score: {exc}")
    
    def add_trace_tags(self, tags: list[str]):
        """Add tags to current trace for filtering."""
        if not self._client:
            return
        
        try:
            langfuse_context.update_current_trace(
                tags=tags,
            )
        except Exception as exc:
            logger.debug(f"Failed to add trace tags: {exc}")
    
    def flush(self):
        """Flush all pending events to Langfuse."""
        if self._client:
            try:
                self._client.flush()
            except Exception as exc:
                logger.debug(f"Failed to flush: {exc}")


# Global singleton instance
_observability_instance: ObservabilityService | None = None


def get_observability() -> ObservabilityService:
    """Get global observability service instance."""
    global _observability_instance
    if _observability_instance is None:
        _observability_instance = ObservabilityService()
    return _observability_instance


def get_langfuse_handler() -> list | None:
    """
    Get Langfuse callback handler for LangChain integration.
    
    Returns:
        List with CallbackHandler if Langfuse is enabled, None otherwise.
        
    Usage:
        from langchain_openai import ChatOpenAI
        callbacks = get_langfuse_handler()
        llm = ChatOpenAI(model="gpt-4o-mini", callbacks=callbacks)
    """
    if not LANGFUSE_AVAILABLE or not CallbackHandler:
        return None
    
    pk = os.getenv("LANGFUSE_PUBLIC_KEY")
    sk = os.getenv("LANGFUSE_SECRET_KEY")
    host = os.getenv("LANGFUSE_HOST", "http://localhost:3000")
    
    if not (pk and sk):
        return None
    
    try:
        handler = CallbackHandler(
            public_key=pk,
            secret_key=sk,
            host=host,
            session_id=os.getenv("LANGFUSE_SESSION_ID"),
            user_id=os.getenv("LANGFUSE_USER_ID", "fackel"),
            enabled=True,
        )
        return [handler]
    except Exception as exc:
        logger.debug(f"Failed to create Langfuse callback handler: {exc}")
        return None


# Decorator for easy function instrumentation
def instrument(name: Optional[str] = None, tags: Optional[list[str]] = None):
    """
    Decorator to instrument any function with Langfuse observability.
    
    Usage:
        @instrument(name="my_function", tags=["analysis"])
        def my_function(arg1, arg2):
            return result
    """
    def decorator(func: Callable) -> Callable:
        span_name = name or f"{func.__module__}.{func.__name__}"
        
        @observe(name=span_name)
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if tags:
                langfuse_context.update_current_observation(
                    metadata={"tags": tags}
                )
            return func(*args, **kwargs)
        
        return wrapper
    return decorator
