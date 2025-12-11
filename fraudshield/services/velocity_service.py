"""
Velocity checking service.
Detects suspicious patterns like rapid repeated requests.
"""

import time
import hashlib
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

from fraudshield.config import settings


@dataclass
class VelocityCheck:
    """Result of a velocity check."""
    allowed: bool
    risk_boost: float  # Additional risk score to add
    indicators: List[str]
    message: str


class VelocityTracker:
    """
    Tracks request velocity for suspicious pattern detection.
    
    Checks:
    - Same content submitted multiple times rapidly
    - Same IP making many requests
    - Same client hitting different content rapidly
    """
    
    def __init__(
        self,
        content_window_seconds: Optional[int] = None,
        content_max_duplicates: Optional[int] = None,
        ip_window_seconds: Optional[int] = None,
        ip_max_requests: Optional[int] = None,
    ):
        # Use config values as defaults
        self.content_window = content_window_seconds or settings.velocity_content_window
        self.content_max_duplicates = content_max_duplicates or settings.velocity_content_max_duplicates
        self.ip_window = ip_window_seconds or settings.velocity_ip_window
        self.ip_max_requests = ip_max_requests or settings.velocity_ip_max_requests
        
        # Tracking stores: {key: [timestamps]}
        self._content_requests: Dict[str, List[float]] = defaultdict(list)
        self._ip_requests: Dict[str, List[float]] = defaultdict(list)
        self._client_requests: Dict[str, List[float]] = defaultdict(list)
    
    def _clean_old_entries(self, store: Dict[str, List[float]], window: int):
        """Remove entries older than the window."""
        now = time.time()
        for key in list(store.keys()):
            store[key] = [ts for ts in store[key] if now - ts < window]
            if not store[key]:
                del store[key]
    
    def _hash_content(self, content: str) -> str:
        """Create a hash of content for tracking."""
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def check_velocity(
        self,
        content: str,
        ip_address: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> VelocityCheck:
        """
        Check if the request shows suspicious velocity patterns.
        
        Returns:
            VelocityCheck with risk boost and indicators
        """
        now = time.time()
        indicators = []
        risk_boost = 0.0
        messages = []
        
        # Clean old entries
        self._clean_old_entries(self._content_requests, self.content_window)
        self._clean_old_entries(self._ip_requests, self.ip_window)
        
        # Check content velocity (same content submitted repeatedly)
        content_hash = self._hash_content(content)
        content_count = len(self._content_requests[content_hash])
        
        if content_count >= self.content_max_duplicates:
            indicators.append("velocity_duplicate_content")
            risk_boost += 1.5
            messages.append(f"Same content submitted {content_count + 1} times in {self.content_window}s")
        
        self._content_requests[content_hash].append(now)
        
        # Check IP velocity
        if ip_address:
            ip_count = len(self._ip_requests[ip_address])
            
            if ip_count >= self.ip_max_requests * 0.8:  # 80% of limit
                indicators.append("velocity_high_ip_rate")
                risk_boost += 0.5
                messages.append(f"High request rate from IP: {ip_count + 1} in {self.ip_window}s")
            
            if ip_count >= self.ip_max_requests:
                indicators.append("velocity_ip_limit_exceeded")
                risk_boost += 2.0
                messages.append(f"IP rate limit exceeded: {ip_count + 1} requests")
            
            self._ip_requests[ip_address].append(now)
        
        # Check client velocity
        if client_id:
            client_count = len(self._client_requests[client_id])
            self._client_requests[client_id].append(now)
        
        allowed = "velocity_ip_limit_exceeded" not in indicators
        
        return VelocityCheck(
            allowed=allowed,
            risk_boost=risk_boost,
            indicators=indicators,
            message="; ".join(messages) if messages else "Normal velocity",
        )
    
    def get_stats(self) -> Dict[str, int]:
        """Get current tracking stats."""
        return {
            "tracked_content_hashes": len(self._content_requests),
            "tracked_ips": len(self._ip_requests),
            "tracked_clients": len(self._client_requests),
        }


# Global velocity tracker instance
velocity_tracker = VelocityTracker()

