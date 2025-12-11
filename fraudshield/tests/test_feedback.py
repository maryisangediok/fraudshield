"""Tests for feedback service."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from fraudshield.database import Base
from fraudshield.models.feedback import Feedback
from fraudshield.services.feedback_service import (
    submit_feedback,
    get_feedback_stats,
    get_common_false_positives,
    should_whitelist,
    hash_content,
)


class TestFeedbackService:
    """Tests for feedback functionality."""

    @pytest.fixture
    def test_db(self):
        """Create a test database session."""
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)
        session = SessionLocal()
        yield session
        session.close()

    def test_submit_feedback_creates_record(self, test_db):
        """Submitting feedback should create a database record."""
        result = submit_feedback(
            db=test_db,
            content="Test scam message",
            modality="text",
            predicted_risk_level="HIGH",
            predicted_score=8.5,
            feedback_type="false_positive",
            actual_risk_level="LOW",
            user_comment="This was actually a legitimate email",
        )
        
        assert result.id is not None
        assert result.feedback_type == "false_positive"
        assert result.predicted_risk_level == "HIGH"
        assert result.actual_risk_level == "LOW"

    def test_feedback_types_accepted(self, test_db):
        """All valid feedback types should be accepted."""
        for feedback_type in ["false_positive", "false_negative", "correct"]:
            result = submit_feedback(
                db=test_db,
                content=f"Test {feedback_type}",
                modality="text",
                predicted_risk_level="MEDIUM",
                predicted_score=5.0,
                feedback_type=feedback_type,
            )
            assert result.feedback_type == feedback_type

    def test_content_hashing(self):
        """Content should be hashed consistently."""
        content = "Test message"
        hash1 = hash_content(content)
        hash2 = hash_content(content)
        
        assert hash1 == hash2
        assert len(hash1) == 64

    def test_different_content_different_hash(self):
        """Different content should produce different hashes."""
        hash1 = hash_content("Message 1")
        hash2 = hash_content("Message 2")
        
        assert hash1 != hash2

    def test_get_feedback_stats_empty(self, test_db):
        """Stats should handle empty feedback."""
        stats = get_feedback_stats(test_db, days=30)
        
        assert stats["total_feedback"] == 0
        assert stats["false_positive_rate"] == 0.0
        assert stats["accuracy"] == 0.0

    def test_get_feedback_stats_with_data(self, test_db):
        """Stats should calculate rates correctly."""
        # Submit some feedback
        submit_feedback(test_db, "msg1", "text", "HIGH", 8.0, "false_positive")
        submit_feedback(test_db, "msg2", "text", "LOW", 2.0, "false_negative")
        submit_feedback(test_db, "msg3", "text", "MEDIUM", 5.0, "correct")
        submit_feedback(test_db, "msg4", "text", "HIGH", 9.0, "correct")
        
        stats = get_feedback_stats(test_db, days=30)
        
        assert stats["total_feedback"] == 4
        assert stats["false_positives"] == 1
        assert stats["false_negatives"] == 1
        assert stats["correct"] == 2
        assert stats["false_positive_rate"] == 0.25
        assert stats["false_negative_rate"] == 0.25
        assert stats["accuracy"] == 0.5

    def test_common_false_positives(self, test_db):
        """Should identify commonly reported false positives."""
        # Same content reported multiple times as false positive
        for _ in range(5):
            submit_feedback(
                test_db,
                "common-false-positive-content",
                "text",
                "HIGH",
                8.0,
                "false_positive",
            )
        
        # Different content
        submit_feedback(test_db, "other-content", "text", "HIGH", 8.0, "false_positive")
        
        common = get_common_false_positives(test_db, limit=5)
        
        assert len(common) >= 1
        assert common[0]["count"] == 5

    def test_should_whitelist_threshold(self, test_db):
        """Content should be suggested for whitelisting after threshold."""
        content = "frequently-reported-safe-content"
        content_hash = hash_content(content)
        
        # Below threshold
        for _ in range(2):
            submit_feedback(test_db, content, "text", "HIGH", 8.0, "false_positive")
        
        assert should_whitelist(test_db, content_hash, threshold=3) is False
        
        # At threshold
        submit_feedback(test_db, content, "text", "HIGH", 8.0, "false_positive")
        
        assert should_whitelist(test_db, content_hash, threshold=3) is True


class TestFeedbackEndpoints:
    """Tests for feedback API endpoints."""

    def test_submit_feedback_endpoint(self, client):
        """POST /feedback should accept feedback."""
        response = client.post(
            "/feedback",
            json={
                "content": "Test scam message",
                "modality": "text",
                "predicted_risk_level": "HIGH",
                "predicted_score": 8.5,
                "feedback_type": "false_positive",
                "actual_risk_level": "LOW",
                "comment": "This was legitimate",
            },
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
        assert data["feedback_type"] == "false_positive"
        assert "Thank you" in data["message"]

    def test_submit_feedback_invalid_type(self, client):
        """Invalid feedback type should return 400."""
        response = client.post(
            "/feedback",
            json={
                "content": "Test",
                "modality": "text",
                "predicted_risk_level": "HIGH",
                "predicted_score": 8.0,
                "feedback_type": "invalid_type",
            },
        )
        
        assert response.status_code == 400

    def test_feedback_stats_endpoint(self, client):
        """GET /feedback/stats should return statistics."""
        response = client.get("/feedback/stats")
        
        assert response.status_code == 200
        data = response.json()
        assert "total_feedback" in data
        assert "false_positive_rate" in data
        assert "accuracy" in data


