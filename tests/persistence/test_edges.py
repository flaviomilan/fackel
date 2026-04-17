"""Tests for the knowledge-graph edge layer of InformationStore."""

from __future__ import annotations

from pathlib import Path

from fackel.domain import EdgeCandidate, RelationshipType
from fackel.persistence.store import InformationStore


def _edge(src: str, rel: RelationshipType, tgt: str, tool: str = "dns_resolve") -> EdgeCandidate:
    return EdgeCandidate(
        source_fingerprint=src,
        target_fingerprint=tgt,
        type=rel,
        source_tool=tool,
        phase="osint",
    )


class TestEdgeIngest:
    def test_creates_edges(self, tmp_path: Path) -> None:
        store = InformationStore("s1", tmp_path)
        edges = store.ingest_edges(
            [
                _edge("sub1", RelationshipType.RESOLVES_TO, "ip1"),
                _edge("sub2", RelationshipType.SUBDOMAIN_OF, "dom1"),
            ],
            phase="osint",
        )
        assert len(edges) == 2
        assert len(store.all_edges()) == 2

    def test_deduplicates_same_edge(self, tmp_path: Path) -> None:
        store = InformationStore("s1", tmp_path)
        store.ingest_edges(
            [_edge("a", RelationshipType.RESOLVES_TO, "b", tool="dns_resolve")], phase="osint"
        )
        store.ingest_edges(
            [_edge("a", RelationshipType.RESOLVES_TO, "b", tool="dnsx_resolve")], phase="osint"
        )
        all_edges = store.all_edges()
        assert len(all_edges) == 1
        # re-observation merges the contributing tools
        assert set(all_edges[0].source_tools) == {"dns_resolve", "dnsx_resolve"}
        assert all_edges[0].last_seen_at >= all_edges[0].first_seen_at

    def test_distinct_type_is_distinct_edge(self, tmp_path: Path) -> None:
        store = InformationStore("s1", tmp_path)
        store.ingest_edges(
            [
                _edge("a", RelationshipType.RESOLVES_TO, "b"),
                _edge("a", RelationshipType.SUBDOMAIN_OF, "b"),
            ],
            phase="osint",
        )
        assert len(store.all_edges()) == 2


class TestEdgeReaders:
    def test_edges_by_type(self, tmp_path: Path) -> None:
        store = InformationStore("s1", tmp_path)
        store.ingest_edges(
            [
                _edge("a", RelationshipType.RESOLVES_TO, "ip"),
                _edge("b", RelationshipType.RESOLVES_TO, "ip"),
                _edge("a", RelationshipType.SUBDOMAIN_OF, "dom"),
            ],
            phase="osint",
        )
        assert len(store.edges_by_type(RelationshipType.RESOLVES_TO)) == 2
        assert len(store.edges_by_type(RelationshipType.SUBDOMAIN_OF)) == 1

    def test_neighbors_matches_source_and_target(self, tmp_path: Path) -> None:
        store = InformationStore("s1", tmp_path)
        store.ingest_edges(
            [
                _edge("sub", RelationshipType.RESOLVES_TO, "ip"),
                _edge("other", RelationshipType.RESOLVES_TO, "ip"),
                _edge("sub", RelationshipType.SUBDOMAIN_OF, "dom"),
            ],
            phase="osint",
        )
        # "ip" is a target of two edges
        assert len(store.neighbors("ip")) == 2
        # "sub" is a source of two edges
        assert len(store.neighbors("sub")) == 2
        assert store.neighbors("nonexistent") == []


class TestEdgePersistence:
    def test_round_trip_via_jsonl(self, tmp_path: Path) -> None:
        store = InformationStore("s1", tmp_path)
        store.ingest_edges(
            [
                _edge("a", RelationshipType.RESOLVES_TO, "b"),
                _edge("c", RelationshipType.SUBDOMAIN_OF, "d"),
            ],
            phase="osint",
        )
        assert (tmp_path / "s1" / "edges.jsonl").exists()

        reloaded = InformationStore("s1", tmp_path)
        assert len(reloaded.all_edges()) == 2
        assert {e.type for e in reloaded.all_edges()} == {
            RelationshipType.RESOLVES_TO,
            RelationshipType.SUBDOMAIN_OF,
        }
