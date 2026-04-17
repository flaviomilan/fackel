"""Tests for /compact and /context against a real persisted store."""

from __future__ import annotations

import io
from pathlib import Path

from rich.console import Console

from cli.harness import Harness
from fackel.domain import InformationCandidate, InformationType
from fackel.persistence.store import InformationStore


def _cand(
    value: str, info_type: InformationType, tool: str = "dns_resolve"
) -> InformationCandidate:
    return InformationCandidate(
        type=info_type,
        normalized_value=value,
        original_value=value,
        source_execution_id=f"e:{value}",
        source_tool=tool,
        phase="osint",
    )


def _seed_scan(data_dir: Path, scan_id: str = "scanA") -> None:
    store = InformationStore(scan_id, data_dir)
    store.ingest(
        [
            _cand("a.example.com", InformationType.SUBDOMAIN),
            _cand("leaked-token", InformationType.CREDENTIAL_LEAK, tool="gau_urls"),
        ],
        phase="osint",
    )


def _harness(data_dir: Path) -> Harness:
    h = Harness(Console(file=io.StringIO(), force_terminal=False, width=100), verbose=False)
    h._session.data_dir = data_dir
    h._session.remember("scanA", "example.com")
    return h


def _out(h: Harness) -> str:
    return h._console.file.getvalue()  # type: ignore[attr-defined]


class TestCompact:
    def test_compact_builds_memory_and_resets_meter(self, tmp_path: Path) -> None:
        _seed_scan(tmp_path)
        h = _harness(tmp_path)
        h._tracker.add_event("osint", "token", {"content": "x " * 100})
        assert h._tracker.total > 0

        h._cmd_compact("")

        assert h._session.memory_note  # digest built from the store
        assert h._tracker.total == 0  # live meter reset
        assert "compacted" in _out(h)

    def test_compact_without_scan_warns(self, tmp_path: Path) -> None:
        h = Harness(Console(file=io.StringIO(), force_terminal=False), verbose=False)
        h._session.data_dir = tmp_path  # no remembered scans
        h._cmd_compact("")
        assert "nothing to compact" in _out(h)


class TestContext:
    def test_context_shows_phase_breakdown_and_session(self, tmp_path: Path) -> None:
        _seed_scan(tmp_path)
        h = _harness(tmp_path)
        h._tracker.add_event("osint", "token", {"content": "a " * 50})
        h._tracker.add_event("vuln_scan", "summary", {"content": "b " * 50})

        h._cmd_context("")
        out = _out(h)
        assert "Tokens by phase" in out
        assert "scanA" in out  # session summary lists the scan
        assert "ctx" in out  # meter rendered
