import logging
import os

from fackel.core.mongo_tracking import (
    MongoInfoStoreAdapter,
    MongoPersistence,
    MongoTimelineStoreAdapter,
)
from fackel.core.tracking import TrackingService
from fackel.core.tracking_store import (
    FileInfoStore,
    FileTimelineStore,
    InMemoryInfoStore,
    InMemoryTimelineStore,
)
from fackel.core.translators import DEFAULT_TRANSLATORS

logger = logging.getLogger("fackel.bootstrap")


def setup_tracking(enable: bool = True) -> TrackingService | None:
    if not enable:
        return None

    tracking_base = os.getenv("FACKEL_TRACKING_PATH")
    mongo_uri = os.getenv("FACKEL_MONGO_URI")
    mongo_db = os.getenv("FACKEL_MONGO_DB", "fackel")

    if tracking_base:
        info_path = f"{tracking_base}.info.json"
        timeline_path = f"{tracking_base}.timeline.json"
        info_store = FileInfoStore(info_path)
        timeline_store = FileTimelineStore(timeline_path)
        logger.info(f"Using File tracking at {tracking_base}")
    elif mongo_uri:
        try:
            persistence = MongoPersistence(mongo_uri, mongo_db)
            info_store = MongoInfoStoreAdapter(persistence.db)
            timeline_store = MongoTimelineStoreAdapter(persistence.db)
            logger.info("Using MongoDB tracking")
        except Exception as exc:
            logger.warning(f"Mongo tracking unavailable; falling back to memory: {exc}")
            info_store = InMemoryInfoStore()
            timeline_store = InMemoryTimelineStore()
    else:
        logger.info("Using In-Memory tracking")
        info_store = InMemoryInfoStore()
        timeline_store = InMemoryTimelineStore()

    return TrackingService(
        translators=DEFAULT_TRANSLATORS,
        info_store=info_store,
        timeline_store=timeline_store,
    )
