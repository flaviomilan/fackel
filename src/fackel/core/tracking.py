from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Iterable, Protocol


class InfoType(str, Enum):
    EMAIL = "EMAIL"
    IP = "IP"
    HOSTNAME = "HOSTNAME"
    URL = "URL"
    SERVICE = "SERVICE"
    VULNERABILITY = "VULNERABILITY"
    LEAK = "LEAK"
    OTHER = "OTHER"


@dataclass(frozen=True)
class RawToolEvent:
    tool: str
    run_id: str
    observed_at: datetime
    payload: dict[str, Any]


@dataclass(frozen=True)
class InfoRecord:
    info_type: InfoType
    value: str
    fingerprint: str
    source_tool: str
    first_seen: datetime
    last_seen: datetime
    state: str = "active"  # active|resolved


@dataclass(frozen=True)
class TimelineEvent:
    fingerprint: str
    timestamp: datetime
    action: str  # created|seen|resolved|reopened
    data: dict[str, Any] = field(default_factory=dict)


class Translator(Protocol):
    def accepts(self, raw: RawToolEvent) -> bool: ...
    def translate(self, raw: RawToolEvent) -> Iterable[InfoRecord]: ...


class InfoStore(Protocol):
    def get_by_fingerprint(self, fp: str) -> InfoRecord | None: ...
    def upsert(self, record: InfoRecord) -> None: ...
    def mark_resolved(self, fp: str, ts: datetime) -> None: ...
    def iter_active(self) -> Iterable[InfoRecord]: ...


class TimelineStore(Protocol):
    def append(self, event: TimelineEvent) -> None: ...
    def export(self) -> list[dict[str, Any]]: ...


def normalize_value(info_type: InfoType, value: str) -> str:
    v = value.strip()
    if info_type == InfoType.EMAIL:
        return v.lower()
    if info_type in (InfoType.HOSTNAME, InfoType.URL):
        return v.lower().rstrip("/")
    if info_type == InfoType.IP:
        return v
    if info_type == InfoType.VULNERABILITY:
        return v.upper()
    return v


def fingerprint(info_type: InfoType, value: str) -> str:
    norm = normalize_value(info_type, value)
    h = hashlib.sha256()
    h.update(f"{info_type}:{norm}".encode("utf-8"))
    return h.hexdigest()


class TrackingService:
    """Core dedupe + lifecycle tracking; tool-agnostic."""

    def __init__(
        self,
        translators: list[Translator],
        info_store: InfoStore,
        timeline_store: TimelineStore,
        clock: Callable[[], datetime] = lambda: datetime.utcnow(),
    ):
        self.translators = translators
        self.info_store = info_store
        self.timeline_store = timeline_store
        self.clock = clock

    def process(self, raw: RawToolEvent) -> None:
        matched = [t for t in self.translators if t.accepts(raw)]
        if not matched:
            return
        now = self.clock()
        for translator in matched:
            for rec in translator.translate(raw):
                existing = self.info_store.get_by_fingerprint(rec.fingerprint)
                if existing:
                    if existing.state == "resolved":
                        reopened = InfoRecord(
                            info_type=existing.info_type,
                            value=existing.value,
                            fingerprint=existing.fingerprint,
                            source_tool=rec.source_tool,
                            first_seen=existing.first_seen,
                            last_seen=now,
                            state="active",
                        )
                        self.info_store.upsert(reopened)
                        self.timeline_store.append(
                            TimelineEvent(
                                fingerprint=rec.fingerprint,
                                timestamp=now,
                                action="reopened",
                                data={"tool": rec.source_tool},
                            )
                        )
                    else:
                        refreshed = InfoRecord(
                            info_type=existing.info_type,
                            value=existing.value,
                            fingerprint=existing.fingerprint,
                            source_tool=rec.source_tool,
                            first_seen=existing.first_seen,
                            last_seen=now,
                            state=existing.state,
                        )
                        self.info_store.upsert(refreshed)
                        self.timeline_store.append(
                            TimelineEvent(
                                fingerprint=rec.fingerprint,
                                timestamp=now,
                                action="seen",
                                data={"tool": rec.source_tool},
                            )
                        )
                else:
                    new_rec = InfoRecord(
                        info_type=rec.info_type,
                        value=rec.value,
                        fingerprint=rec.fingerprint,
                        source_tool=rec.source_tool,
                        first_seen=now,
                        last_seen=now,
                        state="active",
                    )
                    self.info_store.upsert(new_rec)
                    self.timeline_store.append(
                        TimelineEvent(
                            fingerprint=rec.fingerprint,
                            timestamp=now,
                            action="created",
                            data={"tool": rec.source_tool},
                        )
                    )

    def resolve_missing_since(self, cutoff: datetime) -> None:
        for rec in self.info_store.iter_active():
            if rec.last_seen < cutoff:
                self.info_store.mark_resolved(rec.fingerprint, self.clock())
                self.timeline_store.append(
                    TimelineEvent(
                        fingerprint=rec.fingerprint,
                        timestamp=self.clock(),
                        action="resolved",
                        data={"reason": "not_seen_since_cutoff"},
                    )
                )
