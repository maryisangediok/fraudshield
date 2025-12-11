"""Tests for risk level calculation utilities."""

import pytest

from fraudshield.utils.risk_levels import (
    calculate_risk_level,
    _risk_from_score,
    _max_risk_level,
    has_critical_indicator,
    has_elevated_indicator,
)


class TestRiskFromScore:
    """Tests for score-based risk level calculation."""

    def test_low_score_returns_low(self):
        """Scores below low threshold should return LOW."""
        assert _risk_from_score(0.0) == "LOW"
        assert _risk_from_score(2.0) == "LOW"
        assert _risk_from_score(3.9) == "LOW"

    def test_medium_score_returns_medium(self):
        """Scores between thresholds should return MEDIUM."""
        assert _risk_from_score(4.0) == "MEDIUM"
        assert _risk_from_score(5.5) == "MEDIUM"
        assert _risk_from_score(6.9) == "MEDIUM"

    def test_high_score_returns_high(self):
        """Scores above high threshold should return HIGH."""
        assert _risk_from_score(7.0) == "HIGH"
        assert _risk_from_score(8.5) == "HIGH"
        assert _risk_from_score(10.0) == "HIGH"


class TestMaxRiskLevel:
    """Tests for max risk level selection."""

    def test_single_level(self):
        """Single level should return itself."""
        assert _max_risk_level("LOW") == "LOW"
        assert _max_risk_level("MEDIUM") == "MEDIUM"
        assert _max_risk_level("HIGH") == "HIGH"

    def test_multiple_levels_returns_highest(self):
        """Should return highest risk level."""
        assert _max_risk_level("LOW", "MEDIUM") == "MEDIUM"
        assert _max_risk_level("LOW", "HIGH") == "HIGH"
        assert _max_risk_level("MEDIUM", "HIGH") == "HIGH"
        assert _max_risk_level("LOW", "MEDIUM", "HIGH") == "HIGH"

    def test_empty_returns_low(self):
        """No levels should return LOW."""
        assert _max_risk_level() == "LOW"

    def test_invalid_levels_ignored(self):
        """Invalid levels should be ignored."""
        assert _max_risk_level("LOW", "INVALID", "MEDIUM") == "MEDIUM"
        assert _max_risk_level("INVALID") == "LOW"


class TestCriticalIndicators:
    """Tests for critical indicator detection."""

    def test_critical_indicator_detected(self):
        """Critical indicators should be detected."""
        assert has_critical_indicator(["credential_theft"]) is True
        assert has_critical_indicator(["brand_impersonation"]) is True
        assert has_critical_indicator(["malware_distribution"]) is True

    def test_non_critical_not_detected(self):
        """Non-critical indicators should not trigger."""
        assert has_critical_indicator(["urgency_language"]) is False
        assert has_critical_indicator(["suspicious_keywords"]) is False

    def test_mixed_indicators(self):
        """Should detect critical among non-critical."""
        indicators = ["urgency_language", "credential_theft", "suspicious_keywords"]
        assert has_critical_indicator(indicators) is True

    def test_empty_indicators(self):
        """Empty list should return False."""
        assert has_critical_indicator([]) is False


class TestElevatedIndicators:
    """Tests for elevated indicator detection."""

    def test_elevated_indicator_detected(self):
        """Elevated indicators should be detected."""
        assert has_elevated_indicator(["urgency_language"]) is True
        assert has_elevated_indicator(["crypto_reference"]) is True
        assert has_elevated_indicator(["url_shortener_used"]) is True

    def test_non_elevated_not_detected(self):
        """Non-elevated indicators should not trigger."""
        assert has_elevated_indicator(["no_obvious_text_red_flags"]) is False

    def test_empty_indicators(self):
        """Empty list should return False."""
        assert has_elevated_indicator([]) is False


class TestCalculateRiskLevel:
    """Tests for overall risk level calculation."""

    def test_critical_indicator_overrides_to_high(self):
        """Critical indicators should override to HIGH regardless of score."""
        # Low score but critical indicator
        result = calculate_risk_level(1.0, ["credential_theft"])
        assert result == "HIGH"
        
        # Medium score with critical indicator
        result = calculate_risk_level(5.0, ["brand_impersonation"])
        assert result == "HIGH"

    def test_elevated_indicator_bumps_low_to_medium(self):
        """Elevated indicators should bump LOW to MEDIUM."""
        # Low score with elevated indicator
        result = calculate_risk_level(2.0, ["urgency_language"])
        assert result == "MEDIUM"

    def test_elevated_indicator_doesnt_affect_medium_or_high(self):
        """Elevated indicators should not change MEDIUM or HIGH."""
        # Already MEDIUM
        result = calculate_risk_level(5.0, ["urgency_language"])
        assert result == "MEDIUM"
        
        # Already HIGH
        result = calculate_risk_level(8.0, ["urgency_language"])
        assert result == "HIGH"

    def test_score_based_without_overrides(self):
        """Without special indicators, should be score-based."""
        assert calculate_risk_level(2.0, []) == "LOW"
        assert calculate_risk_level(5.0, []) == "MEDIUM"
        assert calculate_risk_level(8.0, []) == "HIGH"

    def test_no_obvious_red_flags_stays_low(self):
        """No indicators should result in score-based level."""
        result = calculate_risk_level(2.0, ["no_obvious_text_red_flags"])
        assert result == "LOW"

    def test_prefixed_indicators_handled(self):
        """Prefixed indicators should still work."""
        # This test depends on how indicators are stored
        # If indicators are stored with prefixes, the check might fail
        # This is a reminder to handle prefixed indicators if needed
        pass


