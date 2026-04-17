"""Tests for the evaluation harness (recall / precision / cost metrics)."""

from __future__ import annotations

from pathlib import Path

from fackel.domain import InformationCandidate, InformationType
from fackel.eval import evaluate_store, prf, scan_cost_proxy
from fackel.persistence.store import InformationStore


def _cand(
    value: str, info_type: InformationType, tool: str = "dns_resolve"
) -> InformationCandidate:
    return InformationCandidate(
        type=info_type,
        normalized_value=value,
        original_value=value,
        source_execution_id=f"e:{tool}:{value}",
        source_tool=tool,
        phase="osint",
    )


class TestPRF:
    def test_perfect_match(self) -> None:
        r = prf(["a", "b"], ["a", "b"])
        assert (r.precision, r.recall, r.f1) == (1.0, 1.0, 1.0)

    def test_partial_match_counts(self) -> None:
        r = prf(["a", "b", "x"], ["a", "b", "c"])
        assert (r.tp, r.fp, r.fn) == (2, 1, 1)
        assert r.precision == round(2 / 3, 3)
        assert r.recall == round(2 / 3, 3)

    def test_case_and_whitespace_insensitive(self) -> None:
        r = prf([" A.Example.com "], ["a.example.com"])
        assert r.tp == 1 and r.fp == 0 and r.fn == 0

    def test_both_empty_is_perfect(self) -> None:
        assert prf([], []).f1 == 1.0

    def test_found_against_empty_expected_is_zero_precision(self) -> None:
        r = prf(["a"], [])
        assert r.precision == 0.0 and r.fp == 1


class TestEvaluateStore:
    def test_per_type_and_overall(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        store.ingest(
            [
                _cand("a.example.com", InformationType.SUBDOMAIN),
                _cand("b.example.com", InformationType.SUBDOMAIN),
                _cand("1.2.3.4", InformationType.IP_ADDRESS),
            ],
            phase="osint",
        )
        ground_truth = {
            InformationType.SUBDOMAIN: {"a.example.com", "b.example.com", "c.example.com"},
            "IP_ADDRESS": {"1.2.3.4"},
        }
        metrics = evaluate_store(store, ground_truth)

        # Subdomains: found 2 of 3 expected, no false positives.
        sub = metrics.per_type["SUBDOMAIN"]
        assert (sub.tp, sub.fp, sub.fn) == (2, 0, 1)
        # IPs: perfect.
        assert metrics.per_type["IP_ADDRESS"].f1 == 1.0
        # Overall micro-average: tp=3, fp=0, fn=1.
        assert (metrics.overall.tp, metrics.overall.fp, metrics.overall.fn) == (3, 0, 1)

    def test_cost_proxy(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        store.ingest([_cand("a.example.com", InformationType.SUBDOMAIN, "dns_resolve")], phase="o")
        store.ingest(
            [_cand("a.example.com", InformationType.SUBDOMAIN, "subfinder_enum")], phase="o"
        )
        cost = scan_cost_proxy(store)
        assert cost["records"] == 1  # deduped to one fingerprint
        assert cost["distinct_tools"] == 2  # corroborated by two tools
