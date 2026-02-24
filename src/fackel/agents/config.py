"""Centralized model configuration for all agents.

Each agent reads from ``FACKEL_MODEL_{AGENT}`` env-var, defaulting to
``gpt-5-mini``.  One place to change, one convention to remember.
"""

from __future__ import annotations

import os

_DEFAULT_MODEL = "gpt-5-mini"


def get_model(agent_name: str) -> str:
    """Return the LLM model name for *agent_name*.

    Looks up ``FACKEL_MODEL_{AGENT_NAME}`` (upper-cased) in the
    environment, falling back to :data:`_DEFAULT_MODEL`.
    """
    env_var = f"FACKEL_MODEL_{agent_name.upper()}"
    return os.getenv(env_var, _DEFAULT_MODEL)
