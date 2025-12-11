"""Tests for velocity checking service."""

import pytest
import time

from fraudshield.services.velocity_service import VelocityTracker, velocity_tracker


class TestVelocityTracker:
    """Tests for velocity tracking functionality."""

    @pytest.fixture
    def fresh_tracker(self):
        """Create a fresh velocity tracker for each test."""
        return VelocityTracker(
            content_window_seconds=10,
            content_max_duplicates=3,
            ip_window_seconds=10,
            ip_max_requests=5,
        )

    def test_first_request_allowed(self, fresh_tracker):
        """First request should always be allowed."""
        result = fresh_tracker.check_velocity("test content", "127.0.0.1")
        assert result.allowed is True
        assert result.risk_boost == 0.0
        assert len(result.indicators) == 0

    def test_duplicate_content_detected(self, fresh_tracker):
        """Duplicate content should be detected after threshold."""
        content = "same scam message"
        
        # First 3 requests OK
        for _ in range(3):
            result = fresh_tracker.check_velocity(content, "127.0.0.1")
        
        # 4th request should trigger duplicate detection
        result = fresh_tracker.check_velocity(content, "127.0.0.1")
        assert "velocity_duplicate_content" in result.indicators
        assert result.risk_boost > 0

    def test_high_ip_rate_detected(self, fresh_tracker):
        """High request rate from same IP should be detected."""
        # Make requests up to 80% of limit
        for i in range(4):
            result = fresh_tracker.check_velocity(f"content_{i}", "192.168.1.1")
        
        # Next request should trigger high rate warning
        result = fresh_tracker.check_velocity("content_5", "192.168.1.1")
        assert "velocity_high_ip_rate" in result.indicators

    def test_ip_limit_exceeded(self, fresh_tracker):
        """Exceeding IP limit should block requests."""
        # Exceed the limit
        for i in range(6):
            result = fresh_tracker.check_velocity(f"content_{i}", "10.0.0.1")
        
        # Should be blocked
        assert result.allowed is False
        assert "velocity_ip_limit_exceeded" in result.indicators

    def test_different_ips_independent(self, fresh_tracker):
        """Different IPs should be tracked independently."""
        # Many requests from IP 1
        for i in range(5):
            fresh_tracker.check_velocity(f"content_{i}", "1.1.1.1")
        
        # First request from IP 2 should be fine
        result = fresh_tracker.check_velocity("content", "2.2.2.2")
        assert result.allowed is True
        assert "velocity_high_ip_rate" not in result.indicators

    def test_different_content_independent(self, fresh_tracker):
        """Different content should be tracked independently."""
        # Many requests with content A
        for _ in range(4):
            fresh_tracker.check_velocity("content A", "127.0.0.1")
        
        # First request with content B should be fine (no duplicate warning)
        result = fresh_tracker.check_velocity("content B", "127.0.0.1")
        assert "velocity_duplicate_content" not in result.indicators

    def test_stats_tracking(self, fresh_tracker):
        """Stats should track current state."""
        fresh_tracker.check_velocity("content1", "1.1.1.1")
        fresh_tracker.check_velocity("content2", "2.2.2.2")
        
        stats = fresh_tracker.get_stats()
        assert stats["tracked_content_hashes"] == 2
        assert stats["tracked_ips"] == 2

    def test_global_tracker_exists(self):
        """Global velocity_tracker should be available."""
        assert velocity_tracker is not None
        result = velocity_tracker.check_velocity("test", "127.0.0.1")
        assert hasattr(result, "allowed")
        assert hasattr(result, "risk_boost")
        assert hasattr(result, "indicators")


