"""Smoke tests to verify basic functionality."""

from fraudshield.services.risk_service import RiskService


def test_risk_service_basic():
    """Test RiskService.compute returns expected structure."""
    level, score, explanation = RiskService.compute({"text": 0.8, "url": 0.2}, ["x"])
    assert level in {"LOW", "MEDIUM", "HIGH"}
    assert 0.0 <= score <= 1.0
    assert isinstance(explanation, str)


def test_risk_service_empty():
    """Test RiskService.compute handles empty input."""
    level, score, explanation = RiskService.compute({}, [])
    assert level == "LOW"
    assert score == 0.0
    assert "No signals" in explanation


def test_risk_service_high_score():
    """Test RiskService.compute returns HIGH for high scores."""
    level, score, explanation = RiskService.compute({"text": 0.9}, ["urgent"])
    assert level == "HIGH"
    assert score >= 0.75
