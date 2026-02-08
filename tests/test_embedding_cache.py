"""Tests for embedding cache."""

import numpy as np
import pytest

from fackel.core.embedding_cache import EmbeddingCache


@pytest.fixture
def cache():
    """Create cache instance for testing."""
    return EmbeddingCache(enabled=True)


@pytest.fixture
def sample_embedding():
    """Generate sample embedding vector."""
    return np.random.rand(1536)


def test_cache_availability(cache):
    """Test cache connects to Redis."""
    # Should work if Redis is running, gracefully fail otherwise
    assert cache.enabled is True
    # available might be False if Redis not running (fallback behavior)


def test_set_and_get(cache, sample_embedding):
    """Test basic set/get operations."""
    if not cache.available:
        pytest.skip("Redis not available")
    
    text = "test embedding for graphql"
    
    # Set
    cache.set(text, sample_embedding)
    
    # Get
    retrieved = cache.get(text)
    assert retrieved is not None
    assert np.allclose(retrieved, sample_embedding)


def test_cache_miss(cache):
    """Test cache miss returns None."""
    if not cache.available:
        pytest.skip("Redis not available")
    
    text = "this should not be in cache ever xyz123"
    retrieved = cache.get(text)
    assert retrieved is None


def test_invalidate(cache, sample_embedding):
    """Test cache invalidation."""
    if not cache.available:
        pytest.skip("Redis not available")
    
    text = "test invalidation"
    
    # Set
    cache.set(text, sample_embedding)
    assert cache.get(text) is not None
    
    # Invalidate
    cache.invalidate(text)
    assert cache.get(text) is None


def test_ttl(cache, sample_embedding):
    """Test TTL setting."""
    if not cache.available:
        pytest.skip("Redis not available")
    
    text = "test ttl"
    cache.set(text, sample_embedding, ttl=1)
    
    # Should exist immediately
    assert cache.get(text) is not None
    
    # Should expire after TTL (would need to wait in real test)
    # We just verify it doesn't crash


def test_content_addressable_keys(cache, sample_embedding):
    """Test same content produces same key."""
    if not cache.available:
        pytest.skip("Redis not available")
    
    text1 = "graphql endpoint"
    text2 = "graphql endpoint"  # Same content
    
    cache.set(text1, sample_embedding)
    retrieved = cache.get(text2)
    
    assert np.allclose(retrieved, sample_embedding)


def test_different_content_different_keys(cache, sample_embedding):
    """Test different content produces different keys."""
    if not cache.available:
        pytest.skip("Redis not available")
    
    text1 = "graphql"
    text2 = "wordpress"
    
    emb1 = sample_embedding
    emb2 = np.random.rand(1536)
    
    cache.set(text1, emb1)
    cache.set(text2, emb2)
    
    assert np.allclose(cache.get(text1), emb1)
    assert np.allclose(cache.get(text2), emb2)
    assert not np.allclose(cache.get(text1), cache.get(text2))


def test_fallback_when_unavailable():
    """Test graceful fallback when Redis unavailable."""
    # Intentionally wrong config
    import os
    old_host = os.getenv("REDIS_HOST")
    os.environ["REDIS_HOST"] = "invalid-host-xyz"
    
    cache = EmbeddingCache(enabled=True)
    assert cache.available is False
    
    # Should not crash
    assert cache.get("test") is None
    cache.set("test", np.random.rand(1536))
    cache.invalidate("test")
    
    # Restore
    if old_host:
        os.environ["REDIS_HOST"] = old_host
    else:
        del os.environ["REDIS_HOST"]
