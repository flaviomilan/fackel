"""Prompt loader — composes soul + skill Markdown files into system prompts.

Usage::

    from fackel.prompts import load_prompt, load_section, compose_prompt

    prompt = load_prompt("osint")     # soul.md + skills/osint.md
    prompt = load_prompt("port_scan") # soul.md + skills/port_scan.md

    # Load a single section by category/name path:
    section = load_section("stages/recon_initial")

    # Compose soul + skill + supplementary sections:
    prompt = compose_prompt(
        "osint",
        "stages/recon_initial",
        "tools/dns_resolution",
    )

The composed prompt is ``soul + "\\n\\n---\\n\\n" + skill`` so the LLM
receives a clear identity block followed by the task-specific instructions.
Supplementary sections are appended with the same separator, keeping each
block visually distinct for the LLM.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent

_SECTION_SEP = "\n\n---\n\n"


@lru_cache(maxsize=64)
def _read(path: Path) -> str:
    """Read and cache a Markdown file."""
    return path.read_text(encoding="utf-8").strip()


def load_section(path: str) -> str:
    """Load a single prompt section by relative path (no ``.md`` extension).

    Examples::

        load_section("stages/recon_initial")
        load_section("orchestrator/phase_transition")
        load_section("tools/port_scanning")
        load_section("contracts/nuclei")

    Raises
    ------
    FileNotFoundError
        If the section file does not exist.
    """
    return _read(_PROMPTS_DIR / f"{path}.md")


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
    return f"{soul}{_SECTION_SEP}{skill_text}"


def compose_prompt(skill: str, *extras: str) -> str:
    """Compose soul + skill + supplementary sections into a system prompt.

    Each section is separated by ``---`` so the LLM sees clearly delimited
    blocks: identity → skill instructions → supplementary guidance.

    Parameters
    ----------
    skill:
        Name of the skill file (without ``.md`` extension).
    extras:
        Relative paths to additional prompt sections to append.
        Example: ``"stages/recon_initial"``, ``"tools/port_scanning"``.

    Raises
    ------
    FileNotFoundError
        If any referenced file does not exist.
    """
    base = load_prompt(skill)
    if not extras:
        return base
    sections = [load_section(e) for e in extras]
    return base + _SECTION_SEP + _SECTION_SEP.join(sections)
