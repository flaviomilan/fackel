"""Interactive harness session — cross-scan memory.

Holds the lightweight state that lives across scans within a single ``fackel``
interactive session: which scans were run, the last target/scan for ``/ask``
grounding, and a compact "session memory" note (a summarized digest of prior
findings, produced by ``/compact``).  Per-scan knowledge graphs remain on disk
(loaded on demand via :func:`fackel.persistence.load_scan`); this object only
tracks references and the digest.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from fackel.persistence import InformationStore, load_scan
from fackel.settings import get_settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanRef:
    """A scan run during this session."""

    scan_id: str
    target: str
    when: float = field(default_factory=time.time)


@dataclass
class HarnessSession:
    """Mutable cross-scan state for one interactive session."""

    data_dir: Path = field(default_factory=lambda: Path(get_settings().data_dir).expanduser())
    scans: list[ScanRef] = field(default_factory=list)
    memory_note: str = ""

    def remember(self, scan_id: str, target: str) -> None:
        """Record a completed scan as the most recent."""
        self.scans.append(ScanRef(scan_id=scan_id, target=target))

    @property
    def last(self) -> ScanRef | None:
        return self.scans[-1] if self.scans else None

    def store_for(self, scan_id: str | None = None) -> InformationStore | None:
        """Load the knowledge-graph store for *scan_id* (default: the last scan)."""
        ref = next((s for s in self.scans if s.scan_id == scan_id), None) if scan_id else self.last
        if ref is None:
            return None
        try:
            return load_scan(ref.scan_id, self.data_dir)
        except Exception:
            logger.warning("session: failed to load scan %s", ref.scan_id, exc_info=True)
            return None

    def render_summary(self) -> str:
        """Human-readable session state for ``/context`` (Rich markup)."""
        lines = [f"[bold]Session[/bold] — {len(self.scans)} scan(s)"]
        for ref in self.scans[-10:]:
            ts = time.strftime("%H:%M:%S", time.localtime(ref.when))
            lines.append(f"  [cyan]{ref.scan_id}[/cyan]  {ref.target}  [dim]{ts}[/dim]")
        if self.memory_note:
            note_tokens = len(self.memory_note) // 3
            lines.append(f"[dim]session memory: ~{note_tokens} tokens[/dim]")
        return "\n".join(lines)
