from __future__ import annotations

"""
MongoDB persistence for normalized information tracking.
- No ODM; explicit schemas and indexes.
- Uses UTC timestamps.
- Clean repository pattern; no tool-specific logic.
"""

from datetime import datetime
from typing import Literal

from pymongo import ASCENDING

from fackel.core.tracking import InfoRecord as NormalizedInfoRecord
from fackel.core.tracking import InfoType

Status = Literal["active", "resolved", "masked"]


def _coerce_info_type(value: str | InfoType | None) -> InfoType:
    """Map persisted info_type back to the InfoType enum with a safe fallback."""
    if isinstance(value, InfoType):
        return value
    try:
        return InfoType(value) if value is not None else InfoType.OTHER
    except ValueError:
        return InfoType.OTHER


class MongoPersistence:
    """Compatibility wrapper for bootstrap."""
    def __init__(self, uri: str, db_name: str = "fackel"):
        from pymongo import MongoClient
        self.client = MongoClient(uri)
        self.db = self.client[db_name]


# -------------------------
# Adapters to TrackingService (InfoStore / TimelineStore protocols)
# -------------------------
class MongoInfoStoreAdapter:
    """Implements InfoStore protocol on top of MongoDB."""

    def __init__(self, db):
        self.coll = db["information_records"]
        # Align field names with InformationRecordRepository to avoid divergent schemas
        self.coll.create_index(
            [("fingerprint", ASCENDING)], unique=True, name="fingerprint_unique"
        )
        self.coll.create_index([("info_type", ASCENDING)], name="info_type_idx")
        self.coll.create_index([("status", ASCENDING)], name="status_idx")
        self.coll.create_index([("first_seen_at", ASCENDING)], name="first_seen_idx")
        self.coll.create_index([("last_seen_at", ASCENDING)], name="last_seen_idx")

    def get_by_fingerprint(self, fp: str):
        doc = self.coll.find_one({"fingerprint": fp})
        if not doc:
            return None
        return NormalizedInfoRecord(
            info_type=_coerce_info_type(doc.get("info_type")),
            value=doc["value"],
            fingerprint=doc["fingerprint"],
            source_tool=doc.get("source_tool", ""),
            first_seen=doc.get("first_seen_at"),
            last_seen=doc.get("last_seen_at"),
            state=doc.get("status", "active"),
        )

    def upsert(self, record: NormalizedInfoRecord) -> None:
        info_type_val = (
            record.info_type.value
            if hasattr(record.info_type, "value")
            else record.info_type
        )
        self.coll.update_one(
            {"fingerprint": record.fingerprint},
            {
                "$set": {
                    "info_type": info_type_val,
                    "value": record.value,
                    "source_tool": record.source_tool,
                    "last_seen_at": record.last_seen,
                    "status": record.state,
                },
                "$setOnInsert": {
                    "first_seen_at": record.first_seen,
                    "version": 1,
                },
            },
            upsert=True,
        )

    def mark_resolved(self, fp: str, ts: datetime) -> None:
        self.coll.update_one(
            {"fingerprint": fp}, {"$set": {"status": "resolved", "last_seen_at": ts}}
        )

    def iter_active(self):
        cursor = self.coll.find({"status": "active"})
        for doc in cursor:
            yield NormalizedInfoRecord(
                info_type=_coerce_info_type(doc.get("info_type")),
                value=doc["value"],
                fingerprint=doc["fingerprint"],
                source_tool=doc.get("source_tool", ""),
                first_seen=doc.get("first_seen_at"),
                last_seen=doc.get("last_seen_at"),
                state=doc.get("status", "active"),
            )

    def export(self):
        return list(self.coll.find({}, {"_id": 0}))


class MongoTimelineStoreAdapter:
    """Implements TimelineStore protocol on top of MongoDB."""

    def __init__(self, db):
        self.coll = db["information_timeline"]
        self.coll.create_index(
            [("fingerprint", ASCENDING), ("at", ASCENDING)], name="timeline_fp_at"
        )

    def append(self, event) -> None:
        self.coll.insert_one(
            {
                "fingerprint": event.fingerprint,
                "at": event.timestamp,
                "action": event.action,
                "data": event.data,
            }
        )

    def export(self):
        return list(self.coll.find({}, {"_id": 0}))