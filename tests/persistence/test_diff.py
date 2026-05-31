"""Tests for cross-scan diffing and the UPDATED timeline event."""

from __future__ import annotations

import json
from pathlib import Path

from fackel.domain import InformationCandidate, InformationType
from fackel.persistence import diff_scans, list_scans, load_scan
from fackel.persistence.store import InformationStore

SUB = InformationType.SUBDOMAIN


def _cand(tool: str, value: str) -> InformationCandidate:
    return InformationCandidate(
        type=SUB,
        normalized_value=value,
        original_value=value,
        source_execution_id="e",
        source_tool=tool,
        phase="osint",
    )


def _store(tmp_path: Path, scan_id: str, pairs: list[tuple[str, str]]) -> InformationStore:
    store = InformationStore(scan_id, tmp_path)
    store.ingest([_cand(tool, value) for tool, value in pairs], phase="osint")
    return store


def _timeline_event_types(tmp_path: Path, scan_id: str) -> list[str]:
    lines = (tmp_path / scan_id / "timeline.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line)["event_type"] for line in lines if line.strip()]


class TestDiffScans:
    def test_added_and_removed(self, tmp_path: Path) -> None:
        a = _store(tmp_path, "A", [("subfinder_enum", "a.x.com"), ("subfinder_enum", "b.x.com")])
        b = _store(tmp_path, "B", [("subfinder_enum", "b.x.com"), ("subfinder_enum", "c.x.com")])
        d = diff_scans(a, b)
        assert {r.normalized_value for r in d.added_records} == {"c.x.com"}
        assert {r.normalized_value for r in d.removed_records} == {"a.x.com"}
        assert d.changed_records == []
        assert d.has_changes

    def test_no_changes(self, tmp_path: Path) -> None:
        a = _store(tmp_path, "A", [("subfinder_enum", "a.x.com")])
        b = _store(tmp_path, "B", [("subfinder_enum", "a.x.com")])
        d = diff_scans(a, b)
        assert not d.has_changes

    def test_changed_confidence(self, tmp_path: Path) -> None:
        a = _store(tmp_path, "A", [("dnsdumpster_lookup", "a.x.com")])
        b = InformationStore("B", tmp_path)
        b.ingest([_cand("dnsdumpster_lookup", "a.x.com")], phase="osint")
        b.ingest([_cand("subfinder_enum", "a.x.com")], phase="osint")  # corroborated → higher conf
        d = diff_scans(a, b)
        assert len(d.changed_records) == 1
        old, new = d.changed_records[0]
        assert new.confidence > old.confidence


class TestScanRegistry:
    def test_list_and_load(self, tmp_path: Path) -> None:
        _store(tmp_path, "scan-A", [("subfinder_enum", "a.x.com")])
        assert "scan-A" in list_scans(tmp_path)
        loaded = load_scan("scan-A", tmp_path)
        assert len(loaded.all_records()) == 1

    def test_empty_dir(self, tmp_path: Path) -> None:
        assert list_scans(tmp_path / "nope") == []


class TestTimelineLifecycle:
    def test_updated_emitted_on_new_source(self, tmp_path: Path) -> None:
        store = InformationStore("A", tmp_path)
        store.ingest([_cand("dnsdumpster_lookup", "a.x.com")], phase="osint")
        store.ingest([_cand("subfinder_enum", "a.x.com")], phase="osint")
        types = _timeline_event_types(tmp_path, "A")
        assert "created" in types
        assert "updated" in types

    def test_reobserved_when_identical(self, tmp_path: Path) -> None:
        store = InformationStore("A", tmp_path)
        store.ingest([_cand("dnsdumpster_lookup", "a.x.com")], phase="osint")
        store.ingest([_cand("dnsdumpster_lookup", "a.x.com")], phase="osint")
        types = _timeline_event_types(tmp_path, "A")
        assert "reobserved" in types
