"""Tests for knowledge-graph export (JSON / Mermaid / query context)."""

from __future__ import annotations

from pathlib import Path

from fackel.domain import (
    EdgeCandidate,
    InformationCandidate,
    InformationType,
    RelationshipType,
    fingerprint,
)
from fackel.persistence.graph_export import build_query_context, to_json, to_mermaid
from fackel.persistence.store import InformationStore


def _rec(
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


def _edge(src: str, rel: RelationshipType, tgt: str) -> EdgeCandidate:
    return EdgeCandidate(source_fingerprint=src, target_fingerprint=tgt, type=rel, phase="osint")


def _populated(tmp_path: Path) -> InformationStore:
    store = InformationStore("s", tmp_path)
    store.ingest(
        [
            _rec(InformationType.DOMAIN, "example.com"),
            _rec(InformationType.SUBDOMAIN, "www.example.com"),
            _rec(InformationType.IP_ADDRESS, "1.2.3.4"),
        ],
        phase="osint",
    )
    dom = fingerprint(InformationType.DOMAIN, "example.com")
    www = fingerprint(InformationType.SUBDOMAIN, "www.example.com")
    ip = fingerprint(InformationType.IP_ADDRESS, "1.2.3.4")
    store.ingest_edges(
        [
            _edge(www, RelationshipType.SUBDOMAIN_OF, dom),
            _edge(www, RelationshipType.RESOLVES_TO, ip),
            _edge(www, RelationshipType.RESOLVES_TO, "deadbeefdeadbeef"),  # dangling target
        ],
        phase="osint",
    )
    return store


class TestToJson:
    def test_nodes_and_edges(self, tmp_path: Path) -> None:
        graph = to_json(_populated(tmp_path))
        assert graph["scan_id"] == "s"
        assert len(graph["nodes"]) == 3
        # dangling edge (unknown target) is dropped
        assert len(graph["edges"]) == 2
        types = {n["type"] for n in graph["nodes"]}
        assert types == {"DOMAIN", "SUBDOMAIN", "IP_ADDRESS"}


class TestToMermaid:
    def test_renders_diagram(self, tmp_path: Path) -> None:
        mermaid = to_mermaid(_populated(tmp_path))
        assert mermaid.startswith("graph LR")
        assert "DOMAIN: example.com" in mermaid
        assert "subdomain_of" in mermaid
        assert "resolves_to" in mermaid
        assert "deadbeefdeadbeef" not in mermaid  # dangling edge excluded


class TestQueryContext:
    def test_groups_entities_and_relationships(self, tmp_path: Path) -> None:
        ctx = build_query_context(_populated(tmp_path))
        assert "ENTITIES:" in ctx
        assert "RELATIONSHIPS:" in ctx
        assert "DOMAIN (1)" in ctx
        assert "www.example.com --subdomain_of--> example.com" in ctx
        assert "conf=" in ctx  # confidence surfaced
