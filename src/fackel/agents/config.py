"""Centralized model configuration for all agents.

Each agent reads from ``FACKEL_MODEL_{AGENT}`` env-var, defaulting to
``gpt-4o-mini``.  One place to change, one convention to remember.
"""

from __future__ import annotations

import os


def get_model(agent_name: str) -> str:
    """Return the LLM model name for *agent_name*.

    Looks up ``FACKEL_MODEL_{AGENT_NAME}`` (upper-cased) in the
    environment, falling back to ``gpt-4o-mini``.
    """
    env_var = f"FACKEL_MODEL_{agent_name.upper()}"
    return os.getenv(env_var, "gpt-4o-mini")
