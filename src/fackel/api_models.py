"""
API Models for Query System

Pydantic models for request/response validation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class QueryRequest(BaseModel):
    """Request model for Q&A queries."""
    
    question: str = Field(
        ...,
        description="Natural language question about scan results",
        min_length=5,
        max_length=500,
        examples=["Quais vulnerabilidades críticas foram encontradas?"]
    )
    domain: str | None = Field(
        None,
        description="Optional domain filter to search only specific domain scans",
        examples=["example.com"]
    )
    max_scans: int = Field(
        3,
        description="Maximum number of scans to include in LLM context",
        ge=1,
        le=10
    )


class ScanSource(BaseModel):
    """Source information for query results."""
    
    scan_id: str = Field(..., description="Unique scan identifier")
    domain: str = Field(..., description="Target domain")
    timestamp: str = Field(..., description="Scan execution timestamp (ISO format)")
    similarity: float = Field(
        ...,
        description="Semantic similarity score (0.0 to 1.0)",
        ge=0.0,
        le=1.0
    )


class QueryResponse(BaseModel):
    """Response model for Q&A queries."""
    
    answer: str = Field(..., description="LLM-generated answer to the question")
    sources: list[ScanSource] = Field(
        default_factory=list,
        description="Scans used to generate the answer"
    )
    confidence: float = Field(
        ...,
        description="Confidence score based on similarity (0.0 to 1.0)",
        ge=0.0,
        le=1.0
    )
    question: str = Field(..., description="Original question")
    processing_time_ms: float | None = Field(
        None,
        description="Query processing time in milliseconds"
    )


class ScanSummary(BaseModel):
    """Summary of a scan result."""
    
    scan_id: str = Field(..., description="Unique scan identifier")
    domain: str = Field(..., description="Target domain")
    timestamp: datetime = Field(..., description="Scan execution timestamp")
    host_count: int = Field(0, description="Number of hosts discovered")
    service_count: int = Field(0, description="Number of services discovered")
    finding_count: int = Field(0, description="Number of findings/issues")
    cve_count: int = Field(0, description="Number of CVEs identified")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional scan metadata"
    )


class ScanListResponse(BaseModel):
    """Response for listing scans."""
    
    scans: list[ScanSummary] = Field(..., description="List of scan summaries")
    total: int = Field(..., description="Total number of scans")
    limit: int = Field(..., description="Limit applied to query")
    skip: int = Field(..., description="Number of scans skipped (pagination)")


class ScanDetailResponse(BaseModel):
    """Response with full scan details."""
    
    scan_id: str
    domain: str
    timestamp: datetime
    host_count: int
    service_count: int
    finding_count: int
    cve_count: int
    metadata: dict[str, Any] = Field(default_factory=dict)
    report: dict[str, Any] = Field(..., description="Complete DomainReport")


class HealthResponse(BaseModel):
    """Health check response."""
    
    status: str = Field(..., description="Service status")
    service: str = Field(..., description="Service name")
    version: str = Field(..., description="API version")
    features: dict[str, bool] = Field(
        default_factory=dict,
        description="Feature availability"
    )


class ErrorResponse(BaseModel):
    """Error response model."""
    
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    details: dict[str, Any] | None = Field(
        None,
        description="Additional error details"
    )
