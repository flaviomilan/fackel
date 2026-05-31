"""Golden scenario regression net for scan discovery quality.

Each ``*.scenario.json`` fixture is rebuilt into an ``InformationStore`` and
scored with :func:`fackel.eval.evaluate_store`; the test fails if any declared
precision/recall/F1 floor regresses.  Deterministic — no LLM, no network.

Run just these with ``make eval`` or ``pytest -m eval``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fackel.eval import evaluate_store
from fackel.eval.metrics import PRF

from .scenarios import Scenario, discover_scenarios, floor_failures

SCENARIOS = discover_scenarios()

pytestmark = pytest.mark.eval


def _prf_dict(prf: PRF) -> dict[str, float]:
    return {"precision": prf.precision, "recall": prf.recall, "f1": prf.f1}


def test_scenarios_exist() -> None:
    """Guard against an empty fixtures directory silently passing the suite."""
    assert SCENARIOS, "no *.scenario.json fixtures found under tests/fixtures/eval"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_scenario_meets_quality_floors(scenario: Scenario, tmp_path: Path) -> None:
    store = scenario.build_store(tmp_path)
    metrics = evaluate_store(store, scenario.ground_truth_typed())

    failures: list[str] = []

    overall_floors = scenario.overall_floors
    if overall_floors:
        failures += [
            f"overall: {msg}"
            for msg in floor_failures(_prf_dict(metrics.overall), overall_floors.items())
        ]

    for type_value, floors in scenario.per_type_floors.items():
        prf = metrics.per_type.get(type_value)
        assert prf is not None, (
            f"scenario '{scenario.name}' sets per_type floors for {type_value!r} "
            f"but it is absent from ground_truth"
        )
        failures += [
            f"{type_value}: {msg}" for msg in floor_failures(_prf_dict(prf), floors.items())
        ]

    assert not failures, "quality floor(s) regressed for '{}':\n  - {}".format(
        scenario.name, "\n  - ".join(failures)
    )
