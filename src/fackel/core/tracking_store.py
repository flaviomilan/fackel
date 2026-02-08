from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from fackel.core.tracking import InfoRecord, InfoType, TimelineEvent


class InMemoryInfoStore:
    def __init__(self):
        self._data: dict[str, InfoRecord] = {}

    def get_by_fingerprint(self, fp: str) -> InfoRecord | None:
        return self._data.get(fp)

    def upsert(self, record: InfoRecord) -> None:
        self._data[record.fingerprint] = record

    def mark_resolved(self, fp: str, ts: datetime) -> None:
        rec = self._data.get(fp)
        if rec:
            self._data[fp] = InfoRecord(
                info_type=rec.info_type,
                value=rec.value,
                fingerprint=rec.fingerprint,
                source_tool=rec.source_tool,
                first_seen=rec.first_seen,
                last_seen=ts,
                state="resolved",
            )

    def iter_active(self):
        return [r for r in self._data.values() if r.state == "active"]

    def export(self) -> list[dict[str, Any]]:
        return [
            {
                "info_type": r.info_type.value,
                "value": r.value,
                "fingerprint": r.fingerprint,
                "source_tool": r.source_tool,
                "first_seen": r.first_seen.isoformat(),
                "last_seen": r.last_seen.isoformat(),
                "state": r.state,
            }
            for r in self._data.values()
        ]


class InMemoryTimelineStore:
    def __init__(self):
        self.events: list[TimelineEvent] = []

    def append(self, event: TimelineEvent) -> None:
        self.events.append(event)

    def export(self) -> list[dict[str, Any]]:
        return [
            {
                "fingerprint": e.fingerprint,
                "timestamp": e.timestamp.isoformat(),
                "action": e.action,
                "data": e.data,
            }
            for e in self.events
        ]


class FileInfoStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict[str, InfoRecord] = {}
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text())
                for item in raw:
                    self._data[item["fingerprint"]] = InfoRecord(
                        info_type=InfoType(item["info_type"]),
                        value=item["value"],
                        fingerprint=item["fingerprint"],
                        source_tool=item.get("source_tool", ""),
                        first_seen=datetime.fromisoformat(item["first_seen"]),
                        last_seen=datetime.fromisoformat(item["last_seen"]),
                        state=item.get("state", "active"),
                    )
            except Exception:
                self._data = {}

    def _flush(self) -> None:
        payload = [
            {
                "info_type": r.info_type.value,
                "value": r.value,
                "fingerprint": r.fingerprint,
                "source_tool": r.source_tool,
                "first_seen": r.first_seen.isoformat(),
                "last_seen": r.last_seen.isoformat(),
                "state": r.state,
            }
            for r in self._data.values()
        ]
        self.path.write_text(json.dumps(payload, indent=2))

    def get_by_fingerprint(self, fp: str) -> InfoRecord | None:
        return self._data.get(fp)

    def upsert(self, record: InfoRecord) -> None:
        self._data[record.fingerprint] = record
        self._flush()

    def mark_resolved(self, fp: str, ts: datetime) -> None:
        rec = self._data.get(fp)
        if rec:
            self._data[fp] = InfoRecord(
                info_type=rec.info_type,
                value=rec.value,
                fingerprint=rec.fingerprint,
                source_tool=rec.source_tool,
                first_seen=rec.first_seen,
                last_seen=ts,
                state="resolved",
            )
            self._flush()

    def iter_active(self):
        return [r for r in self._data.values() if r.state == "active"]

    def export(self) -> list[dict[str, Any]]:
        return [
            {
                "info_type": r.info_type.value,
                "value": r.value,
                "fingerprint": r.fingerprint,
                "source_tool": r.source_tool,
                "first_seen": r.first_seen.isoformat(),
                "last_seen": r.last_seen.isoformat(),
                "state": r.state,
            }
            for r in self._data.values()
        ]


class FileTimelineStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.events: list[TimelineEvent] = []
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text())
                for item in raw:
                    self.events.append(
                        TimelineEvent(
                            fingerprint=item["fingerprint"],
                            timestamp=datetime.fromisoformat(item["timestamp"]),
                            action=item["action"],
                            data=item.get("data", {}),
                        )
                    )
            except Exception:
                self.events = []

    def append(self, event: TimelineEvent) -> None:
        self.events.append(event)
        payload = [
            {
                "fingerprint": e.fingerprint,
                "timestamp": e.timestamp.isoformat(),
                "action": e.action,
                "data": e.data,
            }
            for e in self.events
        ]
        self.path.write_text(json.dumps(payload, indent=2))

    def export(self) -> list[dict[str, Any]]:
        return [
            {
                "fingerprint": e.fingerprint,
                "timestamp": e.timestamp.isoformat(),
                "action": e.action,
                "data": e.data,
            }
            for e in self.events
        ]
