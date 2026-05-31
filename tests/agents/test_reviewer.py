"""Tests for the report reviewer / QA pass."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from fackel.agents.report.reviewer import _gaps, _must_cover, review_report
from fackel.domain import InformationCandidate, InformationType
from fackel.persistence.store import InformationStore


def _cand(info_type: InformationType, value: str, tool: str) -> InformationCandidate:
    return InformationCandidate(
        type=info_type,
        normalized_value=value,
        original_value=value,
        source_execution_id="e",
        source_tool=tool,
        phase="osint",
    )


class TestMustCover:
    def test_critical_always_included(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        store.ingest(
            [_cand(InformationType.SECURITY_VULNERABILITY, "CVE-2024-1", "nuclei_scan")],
            phase="vuln_scan",
        )
        assert ("SECURITY_VULNERABILITY", "CVE-2024-1") in _must_cover(store)

    def test_high_conf_asset_included_low_excluded(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        # dns_resolve → 0.95 (high); dnsdumpster_lookup → 0.65 (low)
        store.ingest([_cand(InformationType.IP_ADDRESS, "1.2.3.4", "dns_resolve")], phase="osint")
        store.ingest(
            [_cand(InformationType.SUBDOMAIN, "low.example.com", "dnsdumpster_lookup")],
            phase="osint",
        )
        must = _must_cover(store)
        assert ("IP_ADDRESS", "1.2.3.4") in must
        assert ("SUBDOMAIN", "low.example.com") not in must

    def test_gaps_detects_missing(self) -> None:
        must = [("X", "alpha.com"), ("Y", "beta.com")]
        assert _gaps("the report mentions alpha.com only", must) == [("Y", "beta.com")]


class TestReviewReport:
    def _store(self, tmp_path: Path) -> InformationStore:
        store = InformationStore("s", tmp_path)
        store.ingest(
            [
                _cand(InformationType.SECURITY_VULNERABILITY, "CVE-2024-1", "nuclei_scan"),
                _cand(InformationType.SUBDOMAIN, "www.example.com", "dns_resolve"),
            ],
            phase="osint",
        )
        return store

    @patch("fackel.agents.report.reviewer.build_llm")
    def test_incorporates_missing_and_footer_full(
        self, mock_build: MagicMock, tmp_path: Path
    ) -> None:
        draft = "# Report\nFound www.example.com."  # CVE missing
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content=draft + "\nAlso CVE-2024-1 was found.")
        mock_build.return_value = mock_llm

        out = review_report(draft, self._store(tmp_path))
        assert "## Review & Coverage" in out
        assert "2/2 high-value findings represented" in out
        assert "incorporated 1 of 1" in out
        assert "Still not represented" not in out

    @patch("fackel.agents.report.reviewer.build_llm")
    def test_llm_failure_keeps_draft_and_flags_gap(
        self, mock_build: MagicMock, tmp_path: Path
    ) -> None:
        draft = "# Report\nFound www.example.com."  # CVE missing
        mock_build.side_effect = RuntimeError("llm down")

        out = review_report(draft, self._store(tmp_path))
        assert out.startswith(draft)  # draft preserved
        assert "Still not represented: CVE-2024-1" in out  # honest about the gap
        assert "1/2 high-value findings represented" in out

    def test_no_high_value_returns_draft_unchanged(self, tmp_path: Path) -> None:
        store = InformationStore("s", tmp_path)
        # only a low-confidence asset → nothing must-cover
        store.ingest(
            [_cand(InformationType.SUBDOMAIN, "low.example.com", "dnsdumpster_lookup")],
            phase="osint",
        )
        draft = "# Report\nnothing critical."
        assert review_report(draft, store) == draft


class TestReviewNode:
    def test_updates_report_when_store_bound(self, monkeypatch, tmp_path: Path) -> None:
        from fackel.agents.orchestrator.nodes import report_and_gates
        from fackel.persistence import bind_store_for_scan

        monkeypatch.setattr(
            "fackel.agents.report.reviewer.review_report",
            lambda draft, store, **kw: draft + "\n[reviewed]",
        )
        with bind_store_for_scan("s", tmp_path) as store:
            store.ingest(
                [_cand(InformationType.SECURITY_VULNERABILITY, "CVE-1", "nuclei_scan")],
                phase="vuln_scan",
            )
            result = report_and_gates.review_node({"report": "draft"}, config={})
        assert result["report"] == "draft\n[reviewed]"

    def test_noop_without_store_or_draft(self) -> None:
        from fackel.agents.orchestrator.nodes import report_and_gates

        assert report_and_gates.review_node({"report": ""}, config={}) == {}
