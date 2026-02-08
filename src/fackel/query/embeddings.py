"""
Scan Embeddings — Vector search for scan results.

Responsibilities:
- Generate embeddings for scan content
- Store embeddings in MongoDB for vector search
- Enable semantic search across scan history

Implementation:
- Uses OpenAI embeddings (text-embedding-3-small)
- Stores vectors alongside scan_id for efficient lookup
- Supports Redis cache to reduce API costs
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from langchain_openai import OpenAIEmbeddings
from pymongo import ASCENDING
from pymongo.database import Database

from fackel.core.models import DomainReport


class ScanEmbeddingService:
    """Service for embedding and indexing scan results."""

    def __init__(
        self,
        db: Database,
        embeddings_model: OpenAIEmbeddings | None = None,
        cache=None
    ):
        self.db = db
        self.collection = db["scan_embeddings"]
        self.embeddings = embeddings_model or OpenAIEmbeddings(
            model="text-embedding-3-small"
        )
        self.cache = cache
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        """Create indexes."""
        self.collection.create_index(
            [("scan_id", ASCENDING)],
            unique=True,
            name="scan_id_unique"
        )
        self.collection.create_index(
            [("domain", ASCENDING)],
            name="domain_idx"
        )

    def _prepare_scan_text(self, report: DomainReport) -> str:
        """
        Convert scan report to searchable text.
        
        Extracts:
        - Hostnames and IPs
        - Service names, products, versions
        - CVEs
        - Finding titles and descriptions
        """
        parts = []
        
        # Domain
        parts.append(f"Domain: {report.domain}")
        
        # Hosts and services
        for hostname, host in report.hosts.items():
            parts.append(f"Host: {hostname}")
            if host.ip:
                parts.append(f"IP: {host.ip}")
            
            for svc in host.services:
                svc_text = f"Service: {svc.name or 'unknown'} on port {svc.port}/{svc.protocol}"
                if svc.product:
                    svc_text += f" ({svc.product}"
                    if svc.version:
                        svc_text += f" {svc.version}"
                    svc_text += ")"
                parts.append(svc_text)
                
                # CVEs
                for cve in svc.cves:
                    cvss_str = f" CVSS {cve.cvss}" if cve.cvss else ""
                    parts.append(f"Vulnerability: {cve.cve_id}{cvss_str}")
        
        # Findings
        for finding in report.findings:
            parts.append(f"Finding: {finding.title}")
            if finding.severity:
                parts.append(f"Severity: {finding.severity}")
            if finding.description:
                parts.append(finding.description)
        
        # People
        for person in report.people:
            parts.append(f"Person: {person.name}")
            if person.role:
                parts.append(f"Role: {person.role}")
        
        return "\n".join(parts)

    def _get_cache_key(self, text: str) -> str:
        """Generate cache key for embedding."""
        h = hashlib.sha256()
        h.update(text.encode("utf-8"))
        return f"embed:scan:{h.hexdigest()}"

    async def embed_scan(
        self,
        scan_id: str,
        domain: str,
        report: DomainReport
    ) -> str:
        """
        Generate and store embedding for a scan.
        
        Returns:
            embedding_id
        """
        # Prepare text
        scan_text = self._prepare_scan_text(report)
        
        # Check cache
        cache_key = self._get_cache_key(scan_text)
        embedding_vector = None
        
        if self.cache:
            cached = self.cache.get(cache_key)
            if cached:
                embedding_vector = json.loads(cached)
        
        # Generate embedding if not cached
        if not embedding_vector:
            embedding_vector = await self.embeddings.aembed_query(scan_text)
            
            # Cache result
            if self.cache:
                self.cache.set(
                    cache_key,
                    json.dumps(embedding_vector),
                    ex=86400 * 7  # 7 days
                )
        
        # Store in MongoDB
        doc = {
            "scan_id": scan_id,
            "domain": domain,
            "embedding": embedding_vector,
            "text_preview": scan_text[:500],  # First 500 chars for debugging
        }
        
        self.collection.replace_one(
            {"scan_id": scan_id},
            doc,
            upsert=True
        )
        
        return scan_id

    async def search_similar(
        self,
        query: str,
        limit: int = 5,
        domain: str | None = None
    ) -> list[dict[str, Any]]:
        """
        Find scans similar to query.
        
        Args:
            query: Natural language query
            limit: Maximum number of results
            domain: Optional domain filter
        
        Returns:
            List of {scan_id, domain, similarity_score}
        """
        # Generate query embedding
        query_embedding = await self.embeddings.aembed_query(query)
        
        # MongoDB vector search aggregation
        # Note: Requires MongoDB Atlas or MongoDB 5.0+ with vector search
        pipeline: list[dict[str, Any]] = [
            {
                "$addFields": {
                    "similarity": {
                        "$let": {
                            "vars": {
                                "dotProduct": {
                                    "$reduce": {
                                        "input": {"$range": [0, {"$size": "$embedding"}]},
                                        "initialValue": 0,
                                        "in": {
                                            "$add": [
                                                "$$value",
                                                {
                                                    "$multiply": [
                                                        {"$arrayElemAt": ["$embedding", "$$this"]},
                                                        {"$arrayElemAt": [query_embedding, "$$this"]}
                                                    ]
                                                }
                                            ]
                                        }
                                    }
                                }
                            },
                            "in": "$$dotProduct"
                        }
                    }
                }
            },
            {"$sort": {"similarity": -1}},
            {"$limit": limit}
        ]
        
        # Add domain filter if specified
        if domain:
            pipeline.insert(0, {"$match": {"domain": domain}})
        
        # Execute search
        results = list(self.collection.aggregate(pipeline))
        
        # Format results
        return [
            {
                "scan_id": r["scan_id"],
                "domain": r["domain"],
                "similarity_score": r["similarity"],
                "text_preview": r.get("text_preview", "")
            }
            for r in results
        ]
