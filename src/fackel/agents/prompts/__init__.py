"""Prompt loader — composes soul + skill Markdown files into system prompts.

Usage::

    from fackel.agents.prompts import load_prompt, load_template

    prompt = load_prompt("osint")        # soul.md + skills/osint.md
    prompt = load_prompt("port_scan")    # soul.md + skills/port_scan.md
    tmpl   = load_template("osint_task") # templates/osint_task.md (raw)

The composed prompt is ``soul + "\\n\\n---\\n\\n" + skill`` so the LLM
receives a clear identity block followed by the task-specific instructions.

Templates are raw Markdown files that may contain ``{placeholder}``
markers — callers format them with ``.format(**kwargs)``.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent


@lru_cache(maxsize=32)
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


def load_template(name: str) -> str:
    """Load a prompt template from ``templates/<name>.md``.

    Parameters
    ----------
    name:
        Name of the template file (without ``.md`` extension).

    Returns
    -------
    str
        Raw template text.  The caller is responsible for calling
        ``.format(**kwargs)`` if the template contains placeholders.

    Raises
    ------
    FileNotFoundError
        If the template file does not exist.
    """
    return _read(_PROMPTS_DIR / "templates" / f"{name}.md")


@lru_cache(maxsize=8)
def load_section_map(name: str) -> dict[str, str]:
    """Load a template with ``## key`` sections and return a dict.

    The file must contain H2 headings (``## section_name``) followed by
    body text.  Returns ``{section_name: body_text, ...}``.

    Parameters
    ----------
    name:
        Template file name (without ``.md``) under ``templates/``.
    """
    raw = load_template(name)
    sections: dict[str, str] = {}
    current_key: str | None = None
    buf: list[str] = []

    for line in raw.splitlines():
        match = re.match(r"^##\s+(\S+)", line)
        if match:
            if current_key is not None:
                sections[current_key] = "\n".join(buf).strip()
            current_key = match.group(1)
            buf = []
        else:
            buf.append(line)

    if current_key is not None:
        sections[current_key] = "\n".join(buf).strip()

    return sections
