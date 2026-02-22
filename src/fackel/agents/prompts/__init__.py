"""Prompt loader — composes soul + skill Markdown files into system prompts.

Usage::

    from fackel.agents.prompts import load_prompt

    prompt = load_prompt("osint")     # soul.md + skills/osint.md
    prompt = load_prompt("port_scan") # soul.md + skills/port_scan.md

The composed prompt is ``soul + "\\n\\n---\\n\\n" + skill`` so the LLM
receives a clear identity block followed by the task-specific instructions.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent


@lru_cache(maxsize=16)
def _read(path: Path) -> str:
    """Read and cache a Markdown file."""
    return path.read_text(encoding="utf-8").strip()


def load_prompt(skill: str) -> str:
    """Load soul + skill and return the composed system prompt.

    Parameters
    ----------
    skill:
        Name of the skill file (without ``.md`` extension).
        Must match a file under ``prompts/skills/<skill>.md``.

    Raises
    ------
    FileNotFoundError
        If the soul or skill file does not exist.
    """
    soul = _read(_PROMPTS_DIR / "soul.md")
    skill_text = _read(_PROMPTS_DIR / "skills" / f"{skill}.md")
    return f"{soul}\n\n---\n\n{skill_text}"
