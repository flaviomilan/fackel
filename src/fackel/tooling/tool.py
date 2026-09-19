"""``@fackel_tool`` — the project's standard tool decorator.

Thin, typed wrapper over LangChain's :func:`langchain_core.tools.tool` that also
sets ``handle_tool_error = True`` on the built tool, so every Fackel tool routes
``ToolException`` back to the LLM as an observation instead of crashing the
agent.  Using it removes the ``<tool>.handle_tool_error = True`` line that
previously trailed every tool module.

Usage mirrors ``@tool`` — always in its parametrised form::

    @fackel_tool(args_schema=CrtShInput)
    def crtsh_subdomain_enum(domain: str) -> dict[str, Any]:
        ...
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from langchain_core.tools import BaseTool
from langchain_core.tools import tool as _lc_tool


def fackel_tool(**kwargs: Any) -> Callable[[Callable[..., Any]], BaseTool]:
    """Like ``@tool(**kwargs)`` but sets ``handle_tool_error=True`` on the result."""

    def _wrap(fn: Callable[..., Any]) -> BaseTool:
        built = cast(BaseTool, _lc_tool(**kwargs)(fn))
        built.handle_tool_error = True
        return built

    return _wrap
