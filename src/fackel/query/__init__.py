"""
Query subsystem for Q&A over scan results.

Enables natural language queries over persisted scan data using:
- Semantic search with embeddings
- RAG (Retrieval-Augmented Generation) with LLM
- Observability with Langfuse
"""

from .query_service import QueryService

__all__ = ["QueryService"]
