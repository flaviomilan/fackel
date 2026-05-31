"""Prompt loader — composes soul + skill Markdown files into system prompts.

Usage::

    from fackel.prompts import load_prompt, load_section, compose_prompt

    prompt = load_prompt("osint")     # soul.md + skills/osint.md
    prompt = load_prompt("port_scan") # soul.md + skills/port_scan.md

    # Load a single section by category/name path:
    section = load_section("tools/port_scanning")

    # Compose soul + skill + supplementary sections:
    prompt = compose_prompt(
        "vuln_scan",
        "tools/vuln_scanning",
        "contracts/nuclei",
    )

The composed prompt is ``soul + "\\n\\n---\\n\\n" + skill`` so the LLM
receives a clear identity block followed by the task-specific instructions.
Supplementary sections are appended with the same separator, keeping each
block visually distinct for the LLM.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

_PROMPTS_DIR = Path(__file__).parent

_SECTION_SEP = "\n\n---\n\n"

PromptProfile = Literal["full", "compact"]


def _resolve_profile(profile: PromptProfile | None) -> PromptProfile:
    """Resolve effective prompt profile.

    Order: explicit argument > Settings.prompt_profile > "full".
    Settings is imported lazily to avoid a circular import at module load.
    """
    if profile is not None:
        return profile
    try:
        from fackel.settings import get_settings  # local import: avoid cycle

        configured = get_settings().prompt_profile
    except Exception:  # pragma: no cover — defensive
        return "full"
    if configured not in ("full", "compact"):
        return "full"
    return configured  # type: ignore[return-value]


def _read_with_fallback(primary: Path, fallback: Path) -> str:
    """Return *primary* if it exists, else *fallback*."""
    if primary.exists():
        return _read(primary)
    return _read(fallback)


@lru_cache(maxsize=64)
def _read(path: Path) -> str:
    """Read and cache a Markdown file."""
    return path.read_text(encoding="utf-8").strip()


def load_section(path: str) -> str:
    """Load a single prompt section by relative path (no ``.md`` extension).

    Examples::

        load_section("stages/enumeration")
        load_section("orchestrator/phase_transition")
        load_section("tools/port_scanning")
        load_section("contracts/nuclei")

    Raises
    ------
    FileNotFoundError
        If the section file does not exist.
    """
    return _read(_PROMPTS_DIR / f"{path}.md")


def load_prompt(skill: str, *, profile: PromptProfile | None = None) -> str:
    """Load soul + skill and return the composed system prompt.

    Parameters
    ----------
    skill:
        Name of the skill file (without ``.md`` extension).
        Must match a file under ``prompts/skills/<skill>.md``.
    profile:
        ``"full"`` (default) loads ``soul.md`` + ``skills/<skill>.md``.
        ``"compact"`` loads ``soul_compact.md`` + ``skills/<skill>_compact.md``
        when present, falling back to the full file if no compact variant
        exists. Used to fit prompts within small-context LLM endpoints
        (e.g. GitHub Models free tier, capped at 8K tokens/request).
        When ``None``, the value of ``Settings.prompt_profile`` is used.

    Raises
    ------
    FileNotFoundError
        If the soul or skill file does not exist.
    """
    effective = _resolve_profile(profile)
    if effective == "compact":
        soul = _read_with_fallback(
            _PROMPTS_DIR / "soul_compact.md",
            _PROMPTS_DIR / "soul.md",
        )
        skill_text = _read_with_fallback(
            _PROMPTS_DIR / "skills" / f"{skill}_compact.md",
            _PROMPTS_DIR / "skills" / f"{skill}.md",
        )
    else:
        soul = _read(_PROMPTS_DIR / "soul.md")
        skill_text = _read(_PROMPTS_DIR / "skills" / f"{skill}.md")
    return f"{soul}{_SECTION_SEP}{skill_text}"


def compose_prompt(
    skill: str,
    *extras: str,
    profile: PromptProfile | None = None,
) -> str:
    """Compose soul + skill (+ supplementary sections) into a system prompt.

    In ``"compact"`` profile the supplementary ``extras`` are intentionally
    skipped: tool-specific guidance is already exposed to the LLM through
    each tool's schema/description, and the compact skill files inline the
    minimum playbook needed. This brings the OSINT system prompt from
    ~13K tokens down to ~1.5K tokens, fitting the GitHub Models free-tier
    8K request budget.

    Parameters
    ----------
    skill:
        Name of the skill file (without ``.md`` extension).
    extras:
        Relative paths to additional prompt sections to append (full profile
        only).
    profile:
        ``"full"``, ``"compact"``, or ``None`` to read from
        ``Settings.prompt_profile``.

    Raises
    ------
    FileNotFoundError
        If any referenced file does not exist (full profile).
    """
    effective = _resolve_profile(profile)
    base = load_prompt(skill, profile=effective)
    if effective == "compact" or not extras:
        return base
    sections = [load_section(e) for e in extras]
    return base + _SECTION_SEP + _SECTION_SEP.join(sections)
