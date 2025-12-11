"""Tests for explainability utilities."""

import pytest

from fraudshield.utils.explainability import (
    calculate_feature_contributions,
    generate_explainability_report,
    report_to_dict,
    FEATURE_WEIGHTS,
    FEATURE_CATEGORIES,
)


class TestFeatureContributions:
    """Tests for feature contribution calculations."""

    def test_empty_indicators_returns_empty(self):
        """Empty indicators should return empty list."""
        result = calculate_feature_contributions([], 5.0, 5.0)
        assert len(result) == 0

    def test_single_indicator_contribution(self):
        """Single indicator should have full contribution."""
        indicators = ["urgency_language"]
        result = calculate_feature_contributions(indicators, 5.0, 5.0)
        
        assert len(result) == 1
        assert result[0].feature == "urgency_language"
        assert result[0].contribution > 0

    def test_multiple_indicators_distributed(self):
        """Multiple indicators should distribute contribution."""
        indicators = ["urgency_language", "url_shortener_used", "crypto_reference"]
        result = calculate_feature_contributions(indicators, 6.0, 6.0)
        
        assert len(result) == 3
        total_contribution = sum(f.contribution for f in result)
        assert total_contribution > 0

    def test_sorted_by_contribution(self):
        """Results should be sorted by contribution (descending)."""
        indicators = ["no_obvious_text_red_flags", "brand_impersonation_paypal"]
        result = calculate_feature_contributions(indicators, 5.0, 5.0)
        
        # brand_impersonation_paypal has higher weight, should be first
        assert result[0].feature == "brand_impersonation_paypal"
        assert result[0].contribution >= result[1].contribution

    def test_prefixed_indicators_handled(self):
        """Prefixed indicators (e.g., 'text:keyword') should be handled."""
        indicators = ["text:urgency_language", "url:url_shortener_used"]
        result = calculate_feature_contributions(indicators, 5.0, 5.0)
        
        assert len(result) == 2
        # Should extract base indicator for weight lookup
        assert all(f.weight > 0 for f in result)

    def test_unknown_indicator_gets_default_weight(self):
        """Unknown indicators should get default weight."""
        indicators = ["unknown_indicator_xyz"]
        result = calculate_feature_contributions(indicators, 5.0, 5.0)
        
        assert len(result) == 1
        assert result[0].weight == 0.5  # Default weight


class TestExplainabilityReport:
    """Tests for explainability report generation."""

    @pytest.fixture
    def sample_heuristic(self):
        return {
            "overall_score": 4.0,
            "risk_level": "MEDIUM",
            "indicators": ["urgency_language"],
            "explanation": "Urgency detected",
        }

    @pytest.fixture
    def sample_llm(self):
        return {
            "overall_score": 5.0,
            "risk_level": "MEDIUM",
            "confidence": 0.7,
            "indicators": ["suspicious_keywords"],
            "explanation": "LLM detected scam patterns",
        }

    def test_report_contains_all_fields(self, sample_heuristic, sample_llm):
        """Report should contain all required fields."""
        indicators = ["urgency_language", "suspicious_keywords"]
        report = generate_explainability_report(
            score=4.5,
            risk_level="MEDIUM",
            confidence=0.7,
            indicators=indicators,
            heuristic_result=sample_heuristic,
            llm_result=sample_llm,
        )
        
        assert report.total_score == 4.5
        assert report.risk_level == "MEDIUM"
        assert report.confidence == 0.7
        assert len(report.top_features) > 0
        assert len(report.summary) > 0
        assert len(report.recommendations) > 0

    def test_high_risk_recommendations(self, sample_heuristic, sample_llm):
        """HIGH risk should include warning recommendations."""
        report = generate_explainability_report(
            score=8.0,
            risk_level="HIGH",
            confidence=0.9,
            indicators=["credential_theft"],
            heuristic_result=sample_heuristic,
            llm_result=sample_llm,
        )
        
        # Should have warning recommendation
        assert any("HIGH RISK" in rec or "⚠️" in rec for rec in report.recommendations)

    def test_url_indicators_get_url_recommendation(self, sample_heuristic, sample_llm):
        """URL indicators should trigger URL verification recommendation."""
        report = generate_explainability_report(
            score=5.0,
            risk_level="MEDIUM",
            confidence=0.7,
            indicators=["url_shortener_used"],
            heuristic_result=sample_heuristic,
            llm_result=sample_llm,
        )
        
        # Should have URL verification recommendation
        assert any("URL" in rec or "🔗" in rec for rec in report.recommendations)

    def test_category_aggregation(self, sample_heuristic, sample_llm):
        """Feature categories should be aggregated."""
        indicators = ["urgency_language", "suspicious_keywords", "url_shortener_used"]
        report = generate_explainability_report(
            score=5.0,
            risk_level="MEDIUM",
            confidence=0.7,
            indicators=indicators,
            heuristic_result=sample_heuristic,
            llm_result=sample_llm,
        )
        
        # Should have both text and url categories
        assert "text" in report.feature_categories
        assert "url" in report.feature_categories


class TestReportToDict:
    """Tests for report serialization."""

    def test_serializable_output(self):
        """report_to_dict should return JSON-serializable dict."""
        from fraudshield.utils.explainability import ExplainabilityReport, FeatureContribution
        
        report = ExplainabilityReport(
            total_score=5.0,
            risk_level="MEDIUM",
            confidence=0.7,
            top_features=[
                FeatureContribution(
                    feature="test",
                    contribution=2.0,
                    weight=0.5,
                    description="Test feature",
                    category="test",
                )
            ],
            feature_categories={"test": 2.0},
            summary="Test summary",
            recommendations=["Test recommendation"],
        )
        
        result = report_to_dict(report)
        
        assert isinstance(result, dict)
        assert result["total_score"] == 5.0
        assert result["risk_level"] == "MEDIUM"
        assert len(result["feature_breakdown"]) == 1
        assert result["summary"] == "Test summary"

    def test_feature_weights_defined(self):
        """Feature weights should be defined for common indicators."""
        assert "urgency_language" in FEATURE_WEIGHTS
        assert "brand_impersonation_paypal" in FEATURE_WEIGHTS
        assert "url_shortener_used" in FEATURE_WEIGHTS

    def test_feature_categories_defined(self):
        """Feature categories should be defined."""
        assert "urgency_language" in FEATURE_CATEGORIES
        assert FEATURE_CATEGORIES["urgency_language"] == "text"
        assert FEATURE_CATEGORIES["url_shortener_used"] == "url"


