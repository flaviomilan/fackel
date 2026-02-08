from __future__ import annotations

import hashlib
import logging
import os
import pickle
from typing import Optional

import numpy as np

logger = logging.getLogger("fackel.embedding_cache")


class EmbeddingCache:
    """Redis-backed cache for embedding vectors.
    
    Stores embeddings with content-based keys (SHA256 hash of text).
    Falls back to no-cache if Redis is unavailable.
    """

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._client = None
        self._available = False
        
        if self.enabled:
            self._connect()

    def _connect(self) -> None:
        """Establish Redis connection from environment config."""
        try:
            import redis
            
            host = os.getenv("REDIS_HOST", "localhost")
            port = int(os.getenv("REDIS_PORT", "6379"))
            db = int(os.getenv("REDIS_DB", "0"))
            password = os.getenv("REDIS_PASSWORD")
            
            # Don't pass empty password to avoid auth errors
            if password and password.strip():
                redis_kwargs = {"password": password}
            else:
                redis_kwargs = {}
            
            self._client = redis.Redis(
                host=host,
                port=port,
                db=db,
                decode_responses=False,
                socket_timeout=2,
                socket_connect_timeout=2,
                **redis_kwargs
            )
            
            # Verify connection
            self._client.ping()
            self._available = True
            logger.info(f"Embedding cache: Redis connected ({host}:{port}/{db})")
            
        except ImportError:
            logger.warning("Embedding cache: redis package not installed")
        except Exception as e:
            logger.warning(f"Embedding cache: Redis unavailable ({e})")
            self._available = False

    def get(self, text: str) -> Optional[np.ndarray]:
        """Retrieve cached embedding for text."""
        if not self._available:
            return None
        
        try:
            key = self._key(text)
            data = self._client.get(key)
            
            if data:
                embedding = pickle.loads(data)
                logger.debug(f"Embedding cache: HIT ({key[:16]}...)")
                return np.array(embedding)
            
            logger.debug(f"Embedding cache: MISS ({key[:16]}...)")
            return None
            
        except Exception as e:
            logger.warning(f"Embedding cache: get failed ({e})")
            return None

    def set(self, text: str, embedding: np.ndarray, ttl: Optional[int] = None) -> None:
        """Store embedding in cache.
        
        Args:
            text: Source text
            embedding: Vector to cache
            ttl: Time-to-live in seconds (None = no expiration)
        """
        if not self._available:
            return
        
        try:
            key = self._key(text)
            data = pickle.dumps(embedding.tolist())
            
            if ttl:
                self._client.setex(key, ttl, data)
            else:
                self._client.set(key, data)
            
            logger.debug(f"Embedding cache: SET ({key[:16]}...)")
            
        except Exception as e:
            logger.warning(f"Embedding cache: set failed ({e})")

    def invalidate(self, text: str) -> None:
        """Remove embedding from cache."""
        if not self._available:
            return
        
        try:
            key = self._key(text)
            self._client.delete(key)
            logger.debug(f"Embedding cache: DELETED ({key[:16]}...)")
        except Exception as e:
            logger.warning(f"Embedding cache: invalidate failed ({e})")

    def clear_all(self) -> None:
        """Clear all embeddings (use with caution in production)."""
        if not self._available:
            return
        
        try:
            pattern = "fackel:embedding:*"
            for key in self._client.scan_iter(match=pattern):
                self._client.delete(key)
            logger.info("Embedding cache: cleared all entries")
        except Exception as e:
            logger.warning(f"Embedding cache: clear failed ({e})")

    @staticmethod
    def _key(text: str) -> str:
        """Generate cache key from text content."""
        hash_digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return f"fackel:embedding:{hash_digest}"

    @property
    def available(self) -> bool:
        """Check if cache is operational."""
        return self._available
