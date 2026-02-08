from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Generator, Iterable

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pymongo import MongoClient

from fackel.agents.graph_agent import LangGraphAgent
from fackel.core.scan_repository import MongoScanRepository
from fackel.query.embeddings import ScanEmbeddingService
from fackel.query import QueryService
from fackel.api_models import (
    QueryRequest,
    QueryResponse,
    ScanListResponse,
    ScanDetailResponse,
    ScanSummary,
    ScanSource,
    HealthResponse,
    ErrorResponse,
)

app = FastAPI(
    title="Fackel API",
    description="API for Autonomous OSINT Agent with RAG Query System",
    version="2.0.0"
)

logger = logging.getLogger("fackel.api")

# Enable CORS for frontend development (lock down in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB configuration from environment
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGO_DB_NAME", "fackel")

# Initialize query system (optional)
QUERY_SYSTEM_AVAILABLE = False
scan_repository = None
embedding_service = None
query_service = None

try:
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
    mongo_client.server_info()  # Test connection
    db = mongo_client[DB_NAME]
    
    scan_repository = MongoScanRepository(db)
    embedding_service = ScanEmbeddingService(db)
    query_service = QueryService(scan_repository, embedding_service)
    
    logger.info("✓ MongoDB connected, query system initialized")
    QUERY_SYSTEM_AVAILABLE = True
except Exception as e:
    logger.warning(f"Query system unavailable: {e}")
    scan_repository = None
    embedding_service = None
    query_service = None
    QUERY_SYSTEM_AVAILABLE = False

@app.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    """Health check endpoint with feature availability."""
    return HealthResponse(
        status="ok",
        service="fackel-agent",
        version="2.0.0",
        features={
            "scan_streaming": True,
            "query_system": QUERY_SYSTEM_AVAILABLE,
            "scan_persistence": QUERY_SYSTEM_AVAILABLE,
        }
    )


def _format_sse(events: Iterable[dict[str, object]]) -> Generator[str, None, None]:
    """Yield events encoded as SSE lines."""
    for event in events:
        yield f"data: {json.dumps(event, default=str)}\n\n"


@app.get("/scan/stream")
async def stream_scan(request: Request, domain: str, active: bool = False):
    """Starts a scan for the given domain and streams results via SSE."""
    if not domain:
        raise HTTPException(status_code=400, detail="Param 'domain' is required")

    agent = LangGraphAgent(active_scan=active)

    async def event_stream() -> Generator[str, None, None]:
        try:
            for event in agent.stream_run(domain):
                # Check if client disconnected
                if await request.is_disconnected():
                    logger.info(f"Client disconnected during scan of {domain}, stopping...")
                    break
                
                yield f"data: {json.dumps(event, default=str)}\n\n"
            
            yield "event: close\ndata: {}\n\n"
        except asyncio.CancelledError:
            logger.info(f"Scan cancelled for {domain}")
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("Streaming scan failed", exc_info=exc)
            error_event = {"type": "error", "message": str(exc)}
            yield f"event: error\ndata: {json.dumps(error_event)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ============================================================================
# Query System Endpoints
# ============================================================================

@app.post("/query", response_model=QueryResponse)
async def query_scans(request: Request, query_request: QueryRequest) -> QueryResponse:
    """
    Ask questions about scan results using natural language.
    
    Examples:
    - "Quais vulnerabilidades críticas foram encontradas?"
    - "Liste os CVEs do nginx"
    - "Quantos hosts foram escaneados?"
    """
    if not QUERY_SYSTEM_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Query system unavailable. Check MongoDB connection and OPENAI_API_KEY."
        )
    
    start_time = time.time()
    
    try:
        # Check if client already disconnected
        if await request.is_disconnected():
            logger.info("Client disconnected before query processing")
            raise HTTPException(status_code=499, detail="Client disconnected")
        
        result = await query_service.query(
            question=query_request.question,
            domain=query_request.domain,
            max_scans=query_request.max_scans,
            request=request  # Pass request for cancellation check
        )
        
        processing_time = (time.time() - start_time) * 1000
        
        return QueryResponse(
            answer=result["answer"],
            sources=[
                ScanSource(
                    scan_id=src["scan_id"],
                    domain=src["domain"],
                    timestamp=src["timestamp"],
                    similarity=src["similarity"]
                )
                for src in result["sources"]
            ],
            confidence=result["confidence"],
            question=query_request.question,
            processing_time_ms=processing_time
        )
    
    except Exception as e:
        logger.exception("Query failed", exc_info=e)
        raise HTTPException(
            status_code=500,
            detail=f"Query processing failed: {str(e)}"
        )


@app.get("/scans", response_model=ScanListResponse)
def list_scans(
    domain: str | None = Query(None, description="Filter by domain"),
    limit: int = Query(50, ge=1, le=100, description="Maximum results"),
    skip: int = Query(0, ge=0, description="Skip N results (pagination)")
) -> ScanListResponse:
    """
    List all scans with optional domain filter.
    
    Supports pagination via limit/skip parameters.
    """
    if not QUERY_SYSTEM_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Query system unavailable. Check MongoDB connection."
        )
    
    try:
        scans = scan_repository.list_scans(domain=domain, limit=limit, skip=skip)
        
        return ScanListResponse(
            scans=[
                ScanSummary(
                    scan_id=s["scan_id"],
                    domain=s["domain"],
                    timestamp=s["timestamp"],
                    host_count=s.get("host_count", 0),
                    service_count=s.get("service_count", 0),
                    finding_count=s.get("finding_count", 0),
                    cve_count=s.get("cve_count", 0),
                    metadata=s.get("metadata", {})
                )
                for s in scans
            ],
            total=len(scans),
            limit=limit,
            skip=skip
        )
    
    except Exception as e:
        logger.exception("Failed to list scans", exc_info=e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list scans: {str(e)}"
        )


@app.get("/scans/{scan_id}", response_model=ScanDetailResponse)
def get_scan_details(scan_id: str) -> ScanDetailResponse:
    """
    Get complete details of a specific scan.
    
    Returns full DomainReport with all hosts, services, findings, CVEs.
    """
    if not QUERY_SYSTEM_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Query system unavailable. Check MongoDB connection."
        )
    
    try:
        scan = scan_repository.get_scan(scan_id)
        
        if not scan:
            raise HTTPException(
                status_code=404,
                detail=f"Scan not found: {scan_id}"
            )
        
        return ScanDetailResponse(
            scan_id=scan["scan_id"],
            domain=scan["domain"],
            timestamp=scan["timestamp"],
            host_count=scan.get("host_count", 0),
            service_count=scan.get("service_count", 0),
            finding_count=scan.get("finding_count", 0),
            cve_count=scan.get("cve_count", 0),
            metadata=scan.get("metadata", {}),
            report=scan["report"]
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to get scan", exc_info=e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve scan: {str(e)}"
        )


@app.get("/scans/domain/{domain}/latest", response_model=ScanDetailResponse)
def get_latest_scan(domain: str) -> ScanDetailResponse:
    """
    Get the most recent scan for a specific domain.
    """
    if not QUERY_SYSTEM_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Query system unavailable. Check MongoDB connection."
        )
    
    try:
        scan = scan_repository.get_latest_scan(domain)
        
        if not scan:
            raise HTTPException(
                status_code=404,
                detail=f"No scans found for domain: {domain}"
            )
        
        return ScanDetailResponse(
            scan_id=scan["scan_id"],
            domain=scan["domain"],
            timestamp=scan["timestamp"],
            host_count=scan.get("host_count", 0),
            service_count=scan.get("service_count", 0),
            finding_count=scan.get("finding_count", 0),
            cve_count=scan.get("cve_count", 0),
            metadata=scan.get("metadata", {}),
            report=scan["report"]
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to get latest scan", exc_info=e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve latest scan: {str(e)}"
        )
