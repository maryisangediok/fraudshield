"""Tests for confidence calibration."""

import pytest

from fraudshield.utils.confidence import (
    calculate_agreement_score,
    calibrate_confidence,
    get_final_confidence,
)


class TestAgreementScore:
    """Tests for agreement score calculation."""

    def test_perfect_agreement_same_level(self):
        """Test perfect agreement when both say HIGH."""
        score, label = calculate_agreement_score("HIGH", "HIGH", 8.0, 8.0)
        assert score >= 0.9
        assert label == "strong"

    def test_perfect_agreement_low(self):
        """Test agreement when both say LOW."""
        score, label = calculate_agreement_score("LOW", "LOW", 1.0, 0.1)
        assert score >= 0.7
        assert label in ("strong", "moderate")

    def test_one_level_difference(self):
        """Test moderate agreement with one level difference."""
        score, label = calculate_agreement_score("HIGH", "MEDIUM", 7.0, 5.0)
        assert 0.4 <= score <= 0.7
        assert label in ("moderate", "weak")

    def test_two_level_difference(self):
        """Test weak/conflict when HIGH vs LOW."""
        score, label = calculate_agreement_score("HIGH", "LOW", 9.0, 1.0)
        assert score < 0.4
        assert label in ("weak", "conflict")

    def test_conflict_opposite_extremes(self):
        """Test conflict detection."""
        score, label = calculate_agreement_score("HIGH", "LOW", 10.0, 0.0)
        assert label == "conflict"


class TestCalibrateConfidence:
    """Tests for confidence calibration."""

    def test_boost_on_strong_agreement(self):
        """Test confidence is boosted when agreement is strong."""
        result = calibrate_confidence(
            llm_confidence=0.7,
            llm_risk="HIGH",
            heuristic_risk="HIGH",
            llm_score=8.0,
            heuristic_score=7.5,
        )
        assert result["calibrated_confidence"] > 0.7
        assert result["agreement_label"] == "strong"
        assert result["adjustment"] == "boosted"

    def test_reduce_on_conflict(self):
        """Test confidence is reduced when there's conflict."""
        result = calibrate_confidence(
            llm_confidence=0.9,
            llm_risk="HIGH",
            heuristic_risk="LOW",
            llm_score=9.0,
            heuristic_score=1.0,
        )
        assert result["calibrated_confidence"] < 0.9
        assert result["agreement_label"] == "conflict"
        assert result["adjustment"] == "reduced"

    def test_raw_confidence_preserved(self):
        """Test that raw LLM confidence is preserved in result."""
        result = calibrate_confidence(
            llm_confidence=0.75,
            llm_risk="MEDIUM",
            heuristic_risk="MEDIUM",
            llm_score=5.0,
            heuristic_score=5.0,
        )
        assert result["raw_llm_confidence"] == 0.75

    def test_confidence_bounded(self):
        """Test that calibrated confidence stays in valid range."""
        # Even with perfect agreement, shouldn't exceed 0.95
        result = calibrate_confidence(
            llm_confidence=0.99,
            llm_risk="HIGH",
            heuristic_risk="HIGH",
            llm_score=10.0,
            heuristic_score=10.0,
        )
        assert result["calibrated_confidence"] <= 0.95

        # Even with conflict, shouldn't go below 0.1
        result = calibrate_confidence(
            llm_confidence=0.2,
            llm_risk="HIGH",
            heuristic_risk="LOW",
            llm_score=10.0,
            heuristic_score=0.0,
        )
        assert result["calibrated_confidence"] >= 0.1


class TestGetFinalConfidence:
    """Tests for the convenience wrapper function."""

    def test_extracts_values_correctly(self):
        """Test that values are extracted from result dicts."""
        llm_result = {
            "risk_level": "MEDIUM",
            "overall_score": 5.0,
            "confidence": 0.6,
        }
        heuristic_result = {
            "risk_level": "MEDIUM",
            "overall_score": 4.5,
        }
        result = get_final_confidence(llm_result, heuristic_result)
        
        assert "calibrated_confidence" in result
        assert "agreement_score" in result
        assert "agreement_label" in result

    def test_handles_missing_confidence(self):
        """Test fallback when LLM doesn't provide confidence."""
        llm_result = {
            "risk_level": "HIGH",
            "overall_score": 8.0,
            # No confidence field
        }
        heuristic_result = {
            "risk_level": "HIGH",
            "overall_score": 7.0,
        }
        result = get_final_confidence(llm_result, heuristic_result)
        
        # Should use default 0.5
        assert result["raw_llm_confidence"] == 0.5


