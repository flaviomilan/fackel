"""Tests for the confidence/provenance scoring model."""

from __future__ import annotations

from pathlib import Path

from fackel.confidence import DEFAULT_TRUST, score_confidence
from fackel.domain import InformationCandidate, InformationType
from fackel.persistence.store import InformationStore


class TestScoreConfidence:
    def test_empty_uses_default(self) -> None:
        assert score_confidence([]) == DEFAULT_TRUST

    def test_unknown_tool_uses_default(self) -> None:
        assert score_confidence(["mystery_tool"]) == DEFAULT_TRUST

    def test_authoritative_source_scores_high(self) -> None:
        assert score_confidence(["dns_resolve"]) >= 0.9

    def test_low_trust_source_scores_low(self) -> None:
        assert score_confidence(["job_search"]) < 0.6

    def test_corroboration_increases_confidence(self) -> None:
        single = score_confidence(["dnsdumpster_lookup"])
        corroborated = score_confidence(
            ["dnsdumpster_lookup", "subfinder_enum", "crtsh_subdomain_enum"]
        )
        assert corroborated > single
        assert corroborated <= 1.0

    def test_distinct_sources_only(self) -> None:
        # Repeating the same source must not inflate confidence.
        assert score_confidence(["subfinder_enum", "subfinder_enum"]) == score_confidence(
            ["subfinder_enum"]
        )


class TestStoreConfidence:
    def _cand(self, tool: str, value: str = "a.example.com") -> InformationCandidate:
        return InformationCandidate(
            type=InformationType.SUBDOMAIN,
            normalized_value=value,
            original_value=value,
            source_execution_id="e",
            source_tool=tool,
            phase="osint",
        )

    def test_single_source_confidence(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        store.ingest([self._cand("dnsdumpster_lookup")], phase="osint")
        record = store.records_by_type(InformationType.SUBDOMAIN)[0]
        assert record.confidence == score_confidence(["dnsdumpster_lookup"])

    def test_corroboration_raises_record_confidence(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        store.ingest([self._cand("dnsdumpster_lookup")], phase="osint")
        before = store.records_by_type(InformationType.SUBDOMAIN)[0].confidence
        # A second, independent source for the same fact (separate batch).
        store.ingest([self._cand("subfinder_enum")], phase="osint")
        after = store.records_by_type(InformationType.SUBDOMAIN)[0].confidence
        assert after > before
