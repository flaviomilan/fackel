"""Single source of truth for the CLI's visual vocabulary.

Centralises the glyphs, phase markers and semantic colour tokens that were
previously scattered across ``renderer.py``, ``main.py`` and ``harness.py``
(inline emoji, ``PHASE_ICONS``, ad-hoc ``"bold blue"``/``"bold red"`` styles).

Glyphs are **Nerd Font** by default (``FACKEL_NERD_FONT=1``).  When the terminal
font lacks Nerd Font patches, set ``FACKEL_NERD_FONT=0`` and every glyph falls back
to a width-1 ASCII/symbol that keeps table columns aligned.  Both the phase labels
and ordering are imported from :mod:`fackel.formatting` so there is still one
source for those.
"""

from __future__ import annotations

from fackel.formatting import PHASE_LABELS, PHASE_ORDER
from fackel.settings import get_settings

# -- glyphs ----------------------------------------------------------------
# Each entry is ``(nerd_font, ascii_fallback)``.  Fallbacks are restricted to the
# width-1 symbol set already used by the renderer (✓ ✗ → • ─) so column widths do
# not shift when Nerd Font is disabled.

_GLYPHS: dict[str, tuple[str, str]] = {
    # phase markers
    "osint": ("", "▸"),  # nf-fa-search
    "port_scan": ("", "▸"),  # nf-fa-plug
    "vuln_scan": ("", "▸"),  # nf-fa-shield
    "triage": ("", "▸"),  # nf-fa-bar_chart
    "report": ("", "▸"),  # nf-fa-file_text_o
    "approval": ("", "!"),  # nf-fa-exclamation_triangle
    "phase": ("", "▸"),  # nf-fa-play (generic/default phase)
    # tool / lane status
    "done": ("", "✓"),  # nf-fa-check
    "error": ("", "✗"),  # nf-fa-times
    "running": ("", "→"),  # nf-fa-arrow_right
    "pending": ("", "○"),  # nf-fa-circle_o
    "active": ("", "●"),  # nf-fa-dot_circle_o (stepper marker)
    "bullet": ("", "•"),  # nf-fa-circle
    # framing / actions
    "scan": ("", "»"),  # nf-fa-fire
    "saved": ("", "+"),  # nf-fa-save
    "stop": ("", "■"),  # nf-fa-stop
    "summary": ("", "≡"),  # nf-fa-clipboard
    "quality": ("", "%"),  # nf-fa-pie_chart
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


# -- semantic colour tokens ------------------------------------------------
# Map intent → Rich style.  Callers reference the intent (``color("phase")``)
# instead of repeating raw colour names, so the palette can shift in one place.

_COLORS: dict[str, str] = {
    "phase": "bold blue",  # phase rule / header
    "scan": "bold red",  # scan framing (Fackel's flame)
    "report": "bold green",  # report rule
    "success": "green",
    "warn": "yellow",
    "danger": "red",
    "dim": "dim",
    "accent": "cyan",
}


def color(token: str) -> str:
    """Return the Rich style for a semantic *token* (default: ``dim``)."""
    return _COLORS.get(token, "dim")


# -- labels / progress -----------------------------------------------------


def phase_label(phase: str) -> str:
    """Human label for *phase* (re-exported from :mod:`fackel.formatting`)."""
    return PHASE_LABELS.get(phase, phase)


def phase_step(phase: str) -> str:
    """Return a ``· n/N`` step suffix for *phase*, or ``""`` if not a scan phase.

    Uses :data:`fackel.formatting.PHASE_ORDER` so the breadcrumb stays in sync with
    the canonical pipeline ordering; ``report`` (outside that order) yields ``""``."""
    if phase in PHASE_ORDER:
        return f" · {PHASE_ORDER.index(phase) + 1}/{len(PHASE_ORDER)}"
    return ""


# Visible pipeline for the persistent stepper (PHASE_ORDER + the report stage).
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
