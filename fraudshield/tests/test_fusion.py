"""Tests for the multi-modal fusion engine."""

import pytest

from fraudshield.pipelines.fusion_engine import fuse_modalities, _max_risk_level, _risk_from_score


class TestFusionHelpers:
    """Tests for fusion helper functions."""

    def test_max_risk_level_returns_highest(self):
        """Test _max_risk_level returns the highest risk."""
        assert _max_risk_level("LOW", "MEDIUM", "HIGH") == "HIGH"
        assert _max_risk_level("LOW", "MEDIUM") == "MEDIUM"
        assert _max_risk_level("LOW", "LOW") == "LOW"

    def test_max_risk_level_handles_empty(self):
        """Test _max_risk_level handles empty input."""
        assert _max_risk_level() == "LOW"

    def test_risk_from_score_thresholds(self):
        """Test _risk_from_score returns correct levels."""
        assert _risk_from_score(0) == "LOW"
        assert _risk_from_score(3.9) == "LOW"
        assert _risk_from_score(4) == "MEDIUM"
        assert _risk_from_score(6.9) == "MEDIUM"
        assert _risk_from_score(7) == "HIGH"
        assert _risk_from_score(10) == "HIGH"


class TestFuseModalities:
    """Tests for the main fusion function."""

    def test_empty_input_returns_low(self):
        """Test empty modality results return LOW risk."""
        result = fuse_modalities({})
        assert result["risk_level"] == "LOW"
        assert result["overall_score"] == 0.0
        assert result["modality_scores"] == {}
        assert result["indicators"] == []

    def test_single_modality(self):
        """Test fusion with a single modality."""
        modality_results = {
            "text": {
                "risk_level": "MEDIUM",
                "overall_score": 5.0,
                "indicators": ["urgency"],
                "explanation": "Found urgency language",
            }
        }
        result = fuse_modalities(modality_results)
        assert result["risk_level"] == "MEDIUM"
        assert result["overall_score"] == 5.0
        assert result["modality_scores"]["text"] == 5.0
        assert "text:urgency" in result["indicators"]

    def test_multiple_modalities_weighted_average(self):
        """Test fusion computes weighted average."""
        modality_results = {
            "text": {
                "risk_level": "LOW",
                "overall_score": 2.0,
                "indicators": [],
                "explanation": "",
            },
            "url": {
                "risk_level": "HIGH",
                "overall_score": 8.0,
                "indicators": ["phishing"],
                "explanation": "",
            },
        }
        result = fuse_modalities(modality_results)
        # Weighted: (2.0*1.0 + 8.0*1.1) / (1.0 + 1.1) = 10.8 / 2.1 ≈ 5.14
        assert 5.0 <= result["overall_score"] <= 5.3
        assert result["risk_level"] == "HIGH"  # Max of modality levels
        assert "text" in result["modality_scores"]
        assert "url" in result["modality_scores"]

    def test_high_modality_overrides_low_score(self):
        """Test that HIGH modality level overrides low fused score."""
        modality_results = {
            "text": {
                "risk_level": "HIGH",  # HIGH level but low score
                "overall_score": 2.0,
                "indicators": ["critical_threat"],
                "explanation": "",
            },
        }
        result = fuse_modalities(modality_results)
        # Even though score is low, risk_level should be HIGH
        assert result["risk_level"] == "HIGH"

    def test_indicators_prefixed_with_modality(self):
        """Test indicators are prefixed with modality name."""
        modality_results = {
            "text": {
                "risk_level": "LOW",
                "overall_score": 1.0,
                "indicators": ["keyword_a", "keyword_b"],
                "explanation": "",
            },
            "url": {
                "risk_level": "LOW",
                "overall_score": 1.0,
                "indicators": ["shortener"],
                "explanation": "",
            },
        }
        result = fuse_modalities(modality_results)
        assert "text:keyword_a" in result["indicators"]
        assert "text:keyword_b" in result["indicators"]
        assert "url:shortener" in result["indicators"]

    def test_raw_contains_original_results(self):
        """Test raw field contains original modality results."""
        modality_results = {
            "text": {
                "risk_level": "LOW",
                "overall_score": 1.0,
                "indicators": [],
                "explanation": "test",
            },
        }
        result = fuse_modalities(modality_results)
        assert result["raw"] == modality_results


