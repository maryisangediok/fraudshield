"""
Security middleware and dependencies for the API.
"""

import time
import logging
from collections import defaultdict
from typing import Optional

from fastapi import Header, HTTPException, Request, status
from fastapi.security import APIKeyHeader

from fraudshield.config import settings

logger = logging.getLogger(__name__)

# API Key header scheme
api_key_header = APIKeyHeader(name=settings.api_token_header, auto_error=False)


async def verify_api_token(
    request: Request,
    api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    """
    Verify the API token from the X-API-Key header.
    
    In development mode (no token configured), this is bypassed.
    In production, a valid token is required.
    """
    # If no token is configured, allow all requests (dev mode)
    if not settings.api_token:
        if settings.is_production:
            logger.warning("API token not configured in production mode!")
        return None

    # Token is configured, so require it
    if not api_key:
        logger.warning(f"Missing API key from {request.client.host}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if api_key != settings.api_token:
        logger.warning(f"Invalid API key attempt from {request.client.host}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return api_key


# Simple in-memory rate limiter
class RateLimiter:
    """
    Simple in-memory rate limiter.
    For production, use Redis or a proper rate limiting service.
    """

    def __init__(self):
        self._requests: dict = defaultdict(list)

    def _clean_old_requests(self, key: str, window: int):
        """Remove requests outside the current window."""
        now = time.time()
        self._requests[key] = [
            ts for ts in self._requests[key]
            if now - ts < window
        ]

    def is_allowed(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        """
        Check if a request is allowed.
        
        Returns:
            (allowed: bool, remaining: int)
        """
        self._clean_old_requests(key, window)
        
        current_count = len(self._requests[key])
        
        if current_count >= limit:
            return False, 0
        
        self._requests[key].append(time.time())
        return True, limit - current_count - 1

    def get_retry_after(self, key: str, window: int) -> int:
        """Get seconds until the oldest request expires."""
        if not self._requests[key]:
            return 0
        oldest = min(self._requests[key])
        return max(0, int(window - (time.time() - oldest)))


# Global rate limiter instance
rate_limiter = RateLimiter()


async def check_rate_limit(request: Request):
    """
    Rate limiting dependency.
    Limits requests per IP address.
    """
    if not settings.rate_limit_requests:
        return  # Rate limiting disabled

    # Use client IP as the key
    client_ip = request.client.host if request.client else "unknown"
    
    allowed, remaining = rate_limiter.is_allowed(
        key=client_ip,
        limit=settings.rate_limit_requests,
        window=settings.rate_limit_window,
    )

    # Add rate limit headers to response
    request.state.rate_limit_remaining = remaining
    request.state.rate_limit_limit = settings.rate_limit_requests

    if not allowed:
        retry_after = rate_limiter.get_retry_after(client_ip, settings.rate_limit_window)
        logger.warning(f"Rate limit exceeded for {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": str(settings.rate_limit_requests),
                "X-RateLimit-Remaining": "0",
            },
        )


async def verify_api_token_optional(
    api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    """
    Optional API token verification for public endpoints.
    Doesn't fail if token is missing, but validates if provided.
    """
    if not api_key:
        return None
    
    if settings.api_token and api_key != settings.api_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )
    
    return api_key


