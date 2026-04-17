"""Tests for store-sourced report data (anti information-loss)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from fackel.agents.report.report_data import build_asset_inventory_md, build_report_context
from fackel.domain import (
    EdgeCandidate,
    InformationCandidate,
    InformationType,
    RelationshipType,
    fingerprint,
)
from fackel.persistence.store import InformationStore


def _cand(
    info_type: InformationType, value: str, tool: str = "subfinder_enum"
) -> InformationCandidate:
    return InformationCandidate(
        type=info_type,
        normalized_value=value,
        original_value=value,
        source_execution_id="e",
        source_tool=tool,
        phase="osint",
    )


def _populated(tmp_path: Path) -> InformationStore:
    store = InformationStore("s", tmp_path)
    store.ingest(
        [
            _cand(InformationType.DOMAIN, "example.com", "target"),
            _cand(InformationType.SUBDOMAIN, "www.example.com"),
            _cand(InformationType.IP_ADDRESS, "1.2.3.4", "dns_resolve"),
            _cand(InformationType.EMAIL, "ann@example.com", "hunter_email_search"),
            _cand(InformationType.SECURITY_VULNERABILITY, "CVE-2024-9999", "nuclei_scan"),
        ],
        phase="osint",
    )
    www = fingerprint(InformationType.SUBDOMAIN, "www.example.com")
    ip = fingerprint(InformationType.IP_ADDRESS, "1.2.3.4")
    store.ingest_edges(
        [
            EdgeCandidate(
                source_fingerprint=www,
                target_fingerprint=ip,
                type=RelationshipType.RESOLVES_TO,
                phase="osint",
            )
        ],
        phase="osint",
    )
    return store


class TestBuildReportContext:
    def test_contains_all_entities_with_provenance(self, tmp_path: Path) -> None:
        ctx = build_report_context(_populated(tmp_path))
        for value in (
            "example.com",
            "www.example.com",
            "1.2.3.4",
            "ann@example.com",
            "CVE-2024-9999",
        ):
            assert value in ctx
        assert "confidence=" in ctx
        assert "sources=" in ctx
        assert "www.example.com --resolves_to--> 1.2.3.4" in ctx
        assert "authoritative" in ctx

    def test_empty_store_returns_empty(self, tmp_path: Path) -> None:
        assert build_report_context(InformationStore("s", tmp_path)) == ""


class TestBuildAssetInventory:
    def test_every_record_present_in_tables(self, tmp_path: Path) -> None:
        md = build_asset_inventory_md(_populated(tmp_path))
        assert "## Complete Asset Inventory" in md
        assert "5 record(s)" in md
        for value in (
            "example.com",
            "www.example.com",
            "1.2.3.4",
            "ann@example.com",
            "CVE-2024-9999",
        ):
            assert value in md
        assert "### SECURITY_VULNERABILITY (1)" in md
        assert "### Relationships (1)" in md

    def test_empty_store_returns_empty(self, tmp_path: Path) -> None:
        assert build_asset_inventory_md(InformationStore("s", tmp_path)) == ""


class TestReportNodeUsesStore:
    def test_node_grounds_report_in_store(self, monkeypatch, tmp_path: Path) -> None:
        from fackel.agents.orchestrator.nodes import report_and_gates
        from fackel.persistence import bind_store_for_scan

        captured: dict = {}

        def _fake_generate(**kwargs):
            captured.update(kwargs)
            return "REPORT"

        monkeypatch.setattr("fackel.agents.report.agent.generate_report", _fake_generate)

        with bind_store_for_scan("s", tmp_path) as store:
            store.ingest([_cand(InformationType.SUBDOMAIN, "www.example.com")], phase="osint")
            result = report_and_gates.report_node(
                {"target": "example.com", "active_scan": False}, config={}
            )

        assert result["report"] == "REPORT"
        assert "www.example.com" in result["asset_inventory"]
        assert captured["graph_context"] and "www.example.com" in captured["graph_context"]

    def test_node_noop_without_store(self, monkeypatch) -> None:
        from fackel.agents.orchestrator.nodes import report_and_gates

        captured: dict = {}

        def _fake_generate(**kwargs):
            captured.update(kwargs)
            return "REPORT"

        monkeypatch.setattr("fackel.agents.report.agent.generate_report", _fake_generate)
        result = report_and_gates.report_node(
            {"target": "example.com", "active_scan": False}, config={}
        )
        assert result["asset_inventory"] == ""
        assert captured["graph_context"] is None


class TestGenerateReportContext:
    @patch("fackel.agents.report.agent.build_llm")
    def test_graph_context_sent_first(self, mock_build: MagicMock) -> None:
        from fackel.agents.report.agent import generate_report

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content="R")
        mock_build.return_value = mock_llm

        out = generate_report(
            target="example.com",
            active_scan=False,
            findings=[],
            graph_context="DISCOVERED DATA (structured, authoritative)\n  - www.example.com",
        )
        assert out == "R"
        human = mock_llm.invoke.call_args[0][0][1].content
        assert "DISCOVERED DATA" in human
        assert "www.example.com" in human
        # structured block precedes the supplementary narrative
        assert human.index("DISCOVERED DATA") < human.index("supplementary")
