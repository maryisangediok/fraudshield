"""
Simple caching layer for analysis results.
Uses in-memory LRU cache by default, can be extended to Redis.
"""

import hashlib
import json
import logging
from functools import lru_cache
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

from fraudshield.config import settings

logger = logging.getLogger(__name__)


class AnalysisCache:
    """
    In-memory cache for analysis results.
    Keys are hashes of the input content.
    """

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._timestamps: Dict[str, datetime] = {}
        self._max_size = max_size
        self._ttl = timedelta(seconds=ttl_seconds)

    def _make_key(self, modality: str, content: str) -> str:
        """Create a unique cache key from modality and content."""
        combined = f"{modality}:{content}"
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    def _make_key_for_bytes(self, modality: str, content: bytes) -> str:
        """Create a unique cache key from modality and binary content."""
        content_hash = hashlib.sha256(content).hexdigest()[:32]
        return f"{modality}:{content_hash}"

    def _evict_expired(self):
        """Remove expired entries."""
        now = datetime.now()
        expired = [k for k, ts in self._timestamps.items() if now - ts > self._ttl]
        for k in expired:
            self._cache.pop(k, None)
            self._timestamps.pop(k, None)

    def _evict_oldest(self):
        """Remove oldest entry if cache is full."""
        if len(self._cache) >= self._max_size:
            oldest_key = min(self._timestamps, key=self._timestamps.get)
            self._cache.pop(oldest_key, None)
            self._timestamps.pop(oldest_key, None)

    def get(self, modality: str, content: str) -> Optional[Dict[str, Any]]:
        """Get cached result for text-based content."""
        self._evict_expired()
        key = self._make_key(modality, content)
        result = self._cache.get(key)
        if result:
            logger.debug(f"Cache hit for {modality}")
        return result

    def get_bytes(self, modality: str, content: bytes) -> Optional[Dict[str, Any]]:
        """Get cached result for binary content."""
        self._evict_expired()
        key = self._make_key_for_bytes(modality, content)
        result = self._cache.get(key)
        if result:
            logger.debug(f"Cache hit for {modality} (bytes)")
        return result

    def set(self, modality: str, content: str, result: Dict[str, Any]):
        """Cache result for text-based content."""
        self._evict_expired()
        self._evict_oldest()
        key = self._make_key(modality, content)
        self._cache[key] = result
        self._timestamps[key] = datetime.now()
        logger.debug(f"Cached result for {modality}")

    def set_bytes(self, modality: str, content: bytes, result: Dict[str, Any]):
        """Cache result for binary content."""
        self._evict_expired()
        self._evict_oldest()
        key = self._make_key_for_bytes(modality, content)
        self._cache[key] = result
        self._timestamps[key] = datetime.now()
        logger.debug(f"Cached result for {modality} (bytes)")

    def clear(self):
        """Clear all cached entries."""
        self._cache.clear()
        self._timestamps.clear()
        logger.info("Cache cleared")

    @property
    def size(self) -> int:
        """Current number of cached entries."""
        return len(self._cache)


# Global cache instance (uses config values)
analysis_cache = AnalysisCache(
    max_size=settings.cache_capacity,
    ttl_seconds=settings.cache_ttl,
)


def get_cached_or_analyze(
    modality: str,
    content: str,
    analyze_fn,
    use_cache: bool = True,
) -> Dict[str, Any]:
    """
    Helper to get cached result or run analysis.

    Args:
        modality: Type of analysis (text, url, etc.)
        content: The content to analyze
        analyze_fn: Function to call if not cached
        use_cache: Whether to use caching

    Returns:
        Analysis result (cached or fresh)
    """
    if use_cache:
        cached = analysis_cache.get(modality, content)
        if cached:
            # Add indicator that this was cached
            cached_result = cached.copy()
            if "indicators" in cached_result:
                if "cached_result" not in cached_result["indicators"]:
                    cached_result["indicators"] = ["cached_result"] + cached_result["indicators"]
            return cached_result

    # Run analysis
    result = analyze_fn(content)

    # Cache the result
    if use_cache:
        analysis_cache.set(modality, content, result)

    return result


async def get_cached_or_analyze_async(
    modality: str,
    content: str,
    analyze_fn,
    use_cache: bool = True,
) -> Dict[str, Any]:
    """
    Async helper to get cached result or run analysis.
    """
    if use_cache:
        cached = analysis_cache.get(modality, content)
        if cached:
            cached_result = cached.copy()
            if "indicators" in cached_result:
                if "cached_result" not in cached_result["indicators"]:
                    cached_result["indicators"] = ["cached_result"] + cached_result["indicators"]
            return cached_result

    # Run analysis
    result = await analyze_fn(content)

    if use_cache:
        analysis_cache.set(modality, content, result)

    return result

