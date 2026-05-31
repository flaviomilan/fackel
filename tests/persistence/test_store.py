"""JSONL InformationStore tests."""

from __future__ import annotations

import json
from pathlib import Path

from fackel.domain import (
    InformationCandidate,
    InformationType,
    ToolExecution,
    ToolExecutionStatus,
)
from fackel.persistence import InformationStore, bind_store_for_scan, get_current_store


def _candidate(
    *,
    value: str = "example.com",
    info_type: InformationType = InformationType.DOMAIN,
    tool: str = "subfinder",
    execution_id: str = "exec-1",
    phase: str = "osint",
    attributes: dict | None = None,
) -> InformationCandidate:
    return InformationCandidate(
        type=info_type,
        normalized_value=value,
        original_value=value,
        attributes=attributes or {},
        source_execution_id=execution_id,
        source_tool=tool,
        phase=phase,
    )


def test_ingest_creates_record_and_timeline_event(tmp_path: Path) -> None:
    store = InformationStore("scan-1", tmp_path)
    records = store.ingest([_candidate()], phase="osint")
    assert len(records) == 1
    assert records[0].type == InformationType.DOMAIN
    assert records[0].normalized_value == "example.com"
    assert records[0].source_tools == ["subfinder"]

    timeline_lines = (tmp_path / "scan-1" / "timeline.jsonl").read_text().splitlines()
    assert len(timeline_lines) == 1
    event = json.loads(timeline_lines[0])
    assert event["event_type"] == "created"


def test_ingest_dedups_by_fingerprint(tmp_path: Path) -> None:
    store = InformationStore("scan-1", tmp_path)
    store.ingest([_candidate(tool="subfinder", execution_id="e1")], phase="osint")
    store.ingest(
        [
            _candidate(
                tool="amass",
                execution_id="e2",
                attributes={"source": "amass"},
            )
        ],
        phase="osint",
    )
    records = store.all_records()
    assert len(records) == 1
    record = records[0]
    assert set(record.source_tools) == {"subfinder", "amass"}
    assert set(record.source_executions) == {"e1", "e2"}
    assert record.attributes == {"source": "amass"}

    timeline_lines = (tmp_path / "scan-1" / "timeline.jsonl").read_text().splitlines()
    assert len(timeline_lines) == 2
    # A new source tool + changed attributes is a meaningful change → UPDATED.
    assert json.loads(timeline_lines[1])["event_type"] == "updated"


def test_records_by_phase_filters_correctly(tmp_path: Path) -> None:
    store = InformationStore("scan-1", tmp_path)
    store.ingest(
        [_candidate(value="a.example.com", info_type=InformationType.SUBDOMAIN)],
        phase="osint",
    )
    store.ingest(
        [
            _candidate(
                value="80",
                info_type=InformationType.OPEN_PORT,
                tool="naabu",
                execution_id="e2",
                phase="port_scan",
            )
        ],
        phase="port_scan",
    )

    osint = store.records_by_phase("osint")
    ports = store.records_by_phase("port_scan")
    assert len(osint) == 1
    assert len(ports) == 1
    assert osint[0].type == InformationType.SUBDOMAIN
    assert ports[0].type == InformationType.OPEN_PORT


def test_store_hydrates_from_jsonl_on_reopen(tmp_path: Path) -> None:
    first = InformationStore("scan-1", tmp_path)
    first.ingest([_candidate()], phase="osint")

    reopened = InformationStore("scan-1", tmp_path)
    records = reopened.all_records()
    assert len(records) == 1
    assert records[0].normalized_value == "example.com"


def test_record_execution_persists_to_executions_jsonl(tmp_path: Path) -> None:
    store = InformationStore("scan-1", tmp_path)
    execution = ToolExecution(
        execution_id="exec-xyz",
        scan_id="scan-1",
        phase="osint",
        tool_name="subfinder",
        params={"domain": "example.com"},
        status=ToolExecutionStatus.OK,
    )
    store.record_execution(execution)
    line = (tmp_path / "scan-1" / "executions.jsonl").read_text().strip()
    payload = json.loads(line)
    assert payload["execution_id"] == "exec-xyz"
    assert payload["tool_name"] == "subfinder"


def test_bind_store_for_scan_sets_and_resets_contextvar(tmp_path: Path) -> None:
    assert get_current_store() is None
    with bind_store_for_scan("scan-bind", tmp_path) as store:
        assert get_current_store() is store
    assert get_current_store() is None
