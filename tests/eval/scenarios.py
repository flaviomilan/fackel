"""Loader for golden eval scenarios under ``tests/fixtures/eval``.

A scenario is a recorded scan outcome (``records``) plus the ground truth it
should recover (``ground_truth``) and the precision/recall/F1 floors it must
meet (``thresholds``).  See ``tests/fixtures/eval/README.md`` for the schema.

The loader is deterministic and offline — it rebuilds an
:class:`~fackel.persistence.store.InformationStore` from the recorded records so
the existing :func:`fackel.eval.evaluate_store` metrics can score it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from fackel.domain import InformationCandidate, InformationType
from fackel.persistence.store import InformationStore

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "eval"

_VALID_TYPE_VALUES = {member.value for member in InformationType}


def _resolve_type(value: str) -> InformationType:
    """Resolve a canonical ``InformationType`` *value*, rejecting unknowns loudly.

    ``InformationType(value)`` raises a bare ``ValueError`` naming only the bad
    value.  We pre-validate against the known value set so a typo'd type in a
    fixture fails with the full list of valid values instead — the enum's
    canonical values are uppercase and not always the obvious word (e.g.
    ``OPEN_PORT`` not ``PORT``, ``SECURITY_VULNERABILITY`` not ``VULNERABILITY``).
    """
    if value not in _VALID_TYPE_VALUES:
        raise ValueError(
            f"unknown InformationType value {value!r}; use one of {sorted(_VALID_TYPE_VALUES)}"
        )
    return InformationType(value)


@dataclass(frozen=True)
class Scenario:
    """A single golden eval scenario parsed from a ``*.scenario.json`` file."""

    name: str
    target: str
    description: str
    records: list[dict[str, str]]
    ground_truth: dict[str, list[str]]
    thresholds: dict[str, dict[str, dict[str, float]]] = field(default_factory=dict)
    path: Path | None = None

    @property
    def overall_floors(self) -> dict[str, float]:
        """PRF floors for the micro-averaged overall score (may be empty)."""
        return dict(self.thresholds.get("overall", {}))

    @property
    def per_type_floors(self) -> dict[str, dict[str, float]]:
        """PRF floors keyed by canonical ``InformationType`` value (may be empty)."""
        return {
            _resolve_type(k).value: dict(v) for k, v in self.thresholds.get("per_type", {}).items()
        }

    def build_store(self, base_dir: Path) -> InformationStore:
        """Rebuild an :class:`InformationStore` from this scenario's records."""
        store = InformationStore(self._scan_id(), base_dir)
        by_phase: dict[str, list[InformationCandidate]] = {}
        for rec in self.records:
            phase = rec.get("phase", "osint")
            by_phase.setdefault(phase, []).append(_to_candidate(rec, phase))
        for phase, candidates in by_phase.items():
            store.ingest(candidates, phase=phase)
        return store

    def ground_truth_typed(self) -> dict[InformationType, list[str]]:
        """Ground truth with keys coerced to :class:`InformationType`."""
        return {_resolve_type(k): list(v) for k, v in self.ground_truth.items()}

    def _scan_id(self) -> str:
        stem = self.path.stem if self.path else self.name
        return f"eval-{stem}".replace(" ", "-")


def _to_candidate(rec: dict[str, str], phase: str) -> InformationCandidate:
    value = rec["value"]
    tool = rec.get("tool", "unknown")
    return InformationCandidate(
        type=_resolve_type(rec["type"]),
        normalized_value=value,
        original_value=value,
        source_execution_id=f"e:{tool}:{value}",
        source_tool=tool,
        phase=phase,
    )


def load_scenario(path: Path) -> Scenario:
    """Parse one ``*.scenario.json`` file into a :class:`Scenario`."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return Scenario(
        name=data["name"],
        target=data["target"],
        description=data.get("description", ""),
        records=data["records"],
        ground_truth=data["ground_truth"],
        thresholds=data.get("thresholds", {}),
        path=path,
    )


def discover_scenarios(directory: Path = FIXTURES_DIR) -> list[Scenario]:
    """Load every ``*.scenario.json`` under *directory*, sorted by filename."""
    return [load_scenario(p) for p in sorted(directory.glob("*.scenario.json"))]


def floor_failures(actual: dict[str, float], floors: Iterable[tuple[str, float]]) -> list[str]:
    """Return human-readable messages for each PRF floor *actual* fails to meet."""
    failures: list[str] = []
    for metric, floor in floors:
        got = actual.get(metric)
        if got is None:
            continue
        if got + 1e-9 < floor:
            failures.append(f"{metric} {got:.3f} < floor {floor:.3f}")
    return failures
