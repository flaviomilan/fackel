"""Single source of truth for the CLI's visual vocabulary.

Centralises the glyphs, phase markers and semantic colour tokens that were
previously scattered across ``renderer.py``, ``main.py`` and ``harness.py``
(inline emoji, ``PHASE_ICONS``, ad-hoc ``"bold blue"``/``"bold red"`` styles).

Glyphs are **Nerd Font** by default (``FACKEL_NERD_FONT=1``).  When the terminal
font lacks Nerd Font patches, set ``FACKEL_NERD_FONT=0`` and every glyph falls back
to a width-1 ASCII/symbol that keeps table columns aligned.  Both the phase labels
and ordering are imported from :mod:`fackel.formatting` so there is still one
source for those.

``_GLYPHS`` maps each name to a ``(nerd_font, ascii_fallback)`` pair; fallbacks stay
within the width-1 symbol set (✓ ✗ → • ─) so columns do not shift when Nerd Font is off.
"""

from __future__ import annotations

from fackel.formatting import PHASE_LABELS, PHASE_ORDER
from fackel.settings import get_settings

_GLYPHS: dict[str, tuple[str, str]] = {
    "osint": ("", "▸"),
    "port_scan": ("", "▸"),
    "vuln_scan": ("", "▸"),
    "triage": ("", "▸"),
    "report": ("", "▸"),
    "approval": ("", "!"),
    "phase": ("", "▸"),
    "done": ("", "✓"),
    "error": ("", "✗"),
    "running": ("", "→"),
    "pending": ("", "○"),
    "active": ("", "●"),
    "bullet": ("", "•"),
    "scan": ("", "»"),
    "saved": ("", "+"),
    "stop": ("", "■"),
    "summary": ("", "≡"),
    "quality": ("", "%"),
}


def _use_nerd_font() -> bool:
    return get_settings().nerd_font


def glyph(name: str) -> str:
    """Return the Nerd Font glyph for *name*, or its ASCII fallback.

    Unknown names fall back to the generic phase marker so callers never raise."""
    nerd, ascii_ = _GLYPHS.get(name, _GLYPHS["phase"])
    return nerd if _use_nerd_font() else ascii_


def phase_glyph(phase: str) -> str:
    """Glyph for a pipeline *phase*, defaulting to the generic marker."""
    return glyph(phase if phase in _GLYPHS else "phase")


_COLORS: dict[str, str] = {
    "phase": "bold blue",
    "scan": "bold red",
    "report": "bold green",
    "success": "green",
    "warn": "yellow",
    "danger": "red",
    "dim": "dim",
    "accent": "cyan",
}


def color(token: str) -> str:
    """Return the Rich style for a semantic *token* (default: ``dim``)."""
    return _COLORS.get(token, "dim")


def phase_label(phase: str) -> str:
    """Human label for *phase* (re-exported from :mod:`fackel.formatting`)."""
    return PHASE_LABELS.get(phase, phase)


STEP_ORDER: tuple[str, ...] = (*PHASE_ORDER, "report")


def render_stepper(current: str) -> str:
    """Return a one-line pipeline breadcrumb with the *current* phase highlighted.

    Phases before *current* render done (green ✓), the current one active
    (bold cyan ●) and the rest pending (dim ○).  ``approval`` is interstitial and
    not in :data:`STEP_ORDER`, so it leaves the breadcrumb on the prior phase.
    Returns Rich markup; the renderer prints it at each phase transition so the
    operator always sees where they are in the run."""
    cur_idx = STEP_ORDER.index(current) if current in STEP_ORDER else -1
    sep = f"[dim] {glyph('running')} [/dim]" if _use_nerd_font() else "[dim] · [/dim]"
    cells: list[str] = []
    for i, phase in enumerate(STEP_ORDER):
        label = phase_label(phase)
        if cur_idx >= 0 and i < cur_idx:
            cells.append(f"[{color('success')}]{glyph('done')} {label}[/{color('success')}]")
        elif i == cur_idx:
            cells.append(
                f"[bold {color('accent')}]{glyph('active')} {label}[/bold {color('accent')}]"
            )
        else:
            cells.append(f"[dim]{glyph('pending')} {label}[/dim]")
    return sep.join(cells)
