from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import numpy as np
import yaml

from fackel.config import PLAYBOOKS_PATH
from fackel.core.embedding_cache import EmbeddingCache
from fackel.core.observability import get_observability

logger = logging.getLogger("fackel.vector_store")


@dataclass
class PlaybookTool:
    name: str
    reason: str


@dataclass
class PlaybookEntry:
    name: str
    description: str
    signals: list[str]
    tools: list[PlaybookTool]
    embedding: np.ndarray | None = None


class VectorPlaybookStore:
    """Vector-based playbook store using embeddings for semantic matching.
    
    Uses OpenAI embeddings for semantic similarity. Falls back to keyword
    matching if embeddings fail.
    """

    def __init__(self, path: str | None = None, use_embeddings: bool = True, use_cache: bool = True):
        self.path = path or str(PLAYBOOKS_PATH)
        self.use_embeddings = use_embeddings
        self.entries: list[PlaybookEntry] = []
        self._embedder = None
        self._cache = EmbeddingCache(enabled=use_cache) if use_cache else None
        self.observability = get_observability()
        
        if self.use_embeddings:
            self._init_embedder()
        
        self._load_playbooks()

    def _init_embedder(self):
        """Initialize OpenAI embeddings client."""
        try:
            from langchain_openai import OpenAIEmbeddings
            self._embedder = OpenAIEmbeddings(model="text-embedding-3-small")
            logger.info("Vector store: OpenAI embeddings initialized")
        except Exception as e:
            logger.warning(f"Vector store: embeddings disabled ({e})")
            self.use_embeddings = False
            self._embedder = None

    def _load_playbooks(self):
        """Load playbooks from YAML and compute embeddings."""
        p = Path(self.path)
        if not p.exists():
            logger.warning(f"Playbook file not found: {self.path}")
            return
        
        data = yaml.safe_load(p.read_text()) or []
        
        for item in data:
            tools = [
                PlaybookTool(name=t.get("name"), reason=t.get("reason", ""))
                for t in item.get("tools", [])
                if t.get("name")
            ]
            
            # Ensure all signals are strings (defensive conversion)
            raw_signals = item.get("signals", {}).get("any", [])
            signals = [str(s) for s in raw_signals if s is not None]
            
            entry = PlaybookEntry(
                name=item.get("name", "unnamed"),
                description=item.get("description", ""),
                signals=signals,
                tools=tools,
            )
            
            # Compute embedding for the rule (signals + description)
            if self.use_embeddings and self._embedder:
                try:
                    text = f"{entry.description} " + " ".join(entry.signals)
                    
                    # Try cache first
                    cached = self._cache.get(text) if self._cache else None
                    if cached is not None:
                        entry.embedding = cached
                        # Track cache hit
                        self.observability.track_embedding(
                            text=text,
                            model="text-embedding-3-small",
                            cached=True,
                            metadata={"context": "playbook_load", "playbook": entry.name},
                        )
                    else:
                        # Generate and cache
                        embedding = self._embedder.embed_query(text)
                        entry.embedding = np.array(embedding)
                        if self._cache:
                            self._cache.set(text, entry.embedding)
                        
                        # Track cache miss
                        self.observability.track_embedding(
                            text=text,
                            model="text-embedding-3-small",
                            cached=False,
                            metadata={"context": "playbook_load", "playbook": entry.name},
                        )
                            
                except Exception as e:
                    logger.warning(f"Failed to embed playbook {entry.name}: {e}")
            
            self.entries.append(entry)
        
        logger.info(f"Loaded {len(self.entries)} playbooks from {self.path}")

    def match(self, signals: Sequence[str], threshold: float = 0.6, top_k: int = 5) -> list[PlaybookTool]:
        """Find matching tools using semantic similarity.
        
        Args:
            signals: List of text signals from state
            threshold: Minimum cosine similarity (0-1)
            top_k: Maximum number of rules to match
            
        Returns:
            List of tool proposals
        """
        if not signals:
            return []
        
        # Combine signals into query text
        query = " ".join(signals)
        
        if self.use_embeddings and self._embedder:
            return self._vector_match(query, threshold, top_k)
        else:
            return self._keyword_match(signals)

    def _vector_match(self, query: str, threshold: float, top_k: int) -> list[PlaybookTool]:
        """Semantic matching using embeddings."""
        try:
            # Try cache first for query embedding
            query_emb = self._cache.get(query) if self._cache else None
            
            if query_emb is None:
                # Compute query embedding
                query_emb = np.array(self._embedder.embed_query(query))
                if self._cache:
                    self._cache.set(query, query_emb, ttl=3600)  # 1h TTL for queries
                
                # Track cache miss
                self.observability.track_embedding(
                    text=query,
                    model="text-embedding-3-small",
                    cached=False,
                    metadata={"context": "playbook_query"},
                )
            else:
                # Track cache hit
                self.observability.track_embedding(
                    text=query,
                    model="text-embedding-3-small",
                    cached=True,
                    metadata={"context": "playbook_query"},
                )
            
            # Compute similarities
            scores = []
            for entry in self.entries:
                if entry.embedding is not None:
                    sim = self._cosine_similarity(query_emb, entry.embedding)
                    scores.append((sim, entry))
            
            # Sort by similarity and filter by threshold
            scores.sort(key=lambda x: x[0], reverse=True)
            matches = [(sim, entry) for sim, entry in scores[:top_k] if sim >= threshold]
            
            # Return tools
            tools = []
            for sim, entry in matches:
                logger.debug(f"Playbook match: {entry.name} (sim={sim:.3f})")
                tools.extend(entry.tools)
            
            return tools
            
        except Exception as e:
            logger.warning(f"Vector match failed, falling back to keyword: {e}")
            return self._keyword_match(query.split())

    def _keyword_match(self, signals: Sequence[str]) -> list[PlaybookTool]:
        """Fallback keyword matching (case-insensitive substring)."""
        tools = []
        signals_lower = [s.lower() for s in signals]
        
        for entry in self.entries:
            for pattern in entry.signals:
                pattern_lower = pattern.lower()
                if any(pattern_lower in sig for sig in signals_lower):
                    logger.debug(f"Playbook match (keyword): {entry.name}")
                    tools.extend(entry.tools)
                    break
        
        return tools

    @staticmethod
    def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
        """Compute cosine similarity between two vectors."""
        return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))
