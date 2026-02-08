"""
Scan Repository — Persistence layer for complete scan results.

Responsibilities:
- Store complete DomainReport with all findings, hosts, services
- Support query by domain, date range, scan_id
- Append-only: never delete or modify historical scans
- Index for efficient retrieval

Design principles:
- Single Responsibility: Only handles scan persistence
- Infrastructure layer: No business logic
- Protocol-based: Easy to mock/test
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol
from uuid import uuid4

from pymongo import ASCENDING, DESCENDING
from pymongo.database import Database

from fackel.core.models import DomainReport


class ScanRepository(Protocol):
    """Protocol for scan persistence."""

    def save_scan(self, domain: str, report: DomainReport, metadata: dict[str, Any]) -> str:
        """Save a complete scan with metadata. Returns scan_id."""
        ...

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieve a scan by ID."""
        ...

    def list_scans(
        self,
        domain: str | None = None,
        limit: int = 50,
        skip: int = 0
    ) -> list[dict[str, Any]]:
        """List scans with optional domain filter."""
        ...

    def get_latest_scan(self, domain: str) -> dict[str, Any] | None:
        """Get most recent scan for a domain."""
        ...


class MongoScanRepository:
    """MongoDB implementation of ScanRepository."""

    def __init__(self, db: Database):
        self.db = db
        self.collection = db["scan_results"]
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        """Create indexes for efficient queries."""
        # Index for scan_id lookups
        self.collection.create_index(
            [("scan_id", ASCENDING)],
            unique=True,
            name="scan_id_unique"
        )
        
        # Index for domain + timestamp queries
        self.collection.create_index(
            [("domain", ASCENDING), ("timestamp", DESCENDING)],
            name="domain_timestamp"
        )
        
        # Index for timestamp-only queries
        self.collection.create_index(
            [("timestamp", DESCENDING)],
            name="timestamp_desc"
        )

    def save_scan(
        self,
        domain: str,
        report: DomainReport,
        metadata: dict[str, Any] | None = None
    ) -> str:
        """
        Save a complete scan result.
        
        Args:
            domain: Target domain
            report: Complete DomainReport with all findings
            metadata: Optional metadata (tool versions, duration, etc.)
        
        Returns:
            scan_id: Unique identifier for this scan
        """
        scan_id = str(uuid4())
        timestamp = datetime.utcnow()
        
        doc = {
            "scan_id": scan_id,
            "domain": domain,
            "timestamp": timestamp,
            "report": report.to_dict(),
            "metadata": metadata or {},
            # Denormalize for easy querying
            "host_count": len(report.hosts),
            "finding_count": len(report.findings),
            "service_count": sum(len(h.services) for h in report.hosts.values()),
            "cve_count": sum(
                len(svc.cves)
                for host in report.hosts.values()
                for svc in host.services
            ),
        }
        
        self.collection.insert_one(doc)
        return scan_id

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieve a scan by ID."""
        result = self.collection.find_one(
            {"scan_id": scan_id},
            {"_id": 0}  # Exclude MongoDB internal ID
        )
        return result

    def list_scans(
        self,
        domain: str | None = None,
        limit: int = 50,
        skip: int = 0
    ) -> list[dict[str, Any]]:
        """
        List scans with optional domain filter.
        
        Args:
            domain: Filter by domain (None = all domains)
            limit: Maximum number of results
            skip: Number of results to skip (pagination)
        
        Returns:
            List of scan documents (without full report for performance)
        """
        query = {"domain": domain} if domain else {}
        
        cursor = self.collection.find(
            query,
            {
                "_id": 0,
                "scan_id": 1,
                "domain": 1,
                "timestamp": 1,
                "metadata": 1,
                "host_count": 1,
                "finding_count": 1,
                "service_count": 1,
                "cve_count": 1,
            }
        ).sort("timestamp", DESCENDING).skip(skip).limit(limit)
        
        return list(cursor)

    def get_latest_scan(self, domain: str) -> dict[str, Any] | None:
        """Get most recent scan for a domain."""
        result = self.collection.find_one(
            {"domain": domain},
            {"_id": 0},
            sort=[("timestamp", DESCENDING)]
        )
        return result

    def get_scans_in_range(
        self,
        start_date: datetime,
        end_date: datetime,
        domain: str | None = None
    ) -> list[dict[str, Any]]:
        """Get scans within a date range."""
        query: dict[str, Any] = {
            "timestamp": {
                "$gte": start_date,
                "$lte": end_date
            }
        }
        
        if domain:
            query["domain"] = domain
        
        cursor = self.collection.find(
            query,
            {"_id": 0}
        ).sort("timestamp", DESCENDING)
        
        return list(cursor)
