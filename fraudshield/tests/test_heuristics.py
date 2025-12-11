"""Tests for heuristic scoring functions."""

import pytest

from fraudshield.services.risk_service import score_text_heuristics, score_url_heuristics
from fraudshield.services.text_service import TextAnalysisService


class TestTextHeuristics:
    """Tests for text heuristic analysis."""

    def test_scam_keywords_detected(self, sample_scam_text):
        """Test that scam keywords are detected."""
        result = score_text_heuristics(sample_scam_text)
        assert result["risk_level"] in {"MEDIUM", "HIGH"}
        assert result["overall_score"] > 0.5
        assert len(result["indicators"]) > 0

    def test_safe_text_low_risk(self, sample_safe_text):
        """Test that safe text returns low risk."""
        result = score_text_heuristics(sample_safe_text)
        assert result["risk_level"] == "LOW"
        assert result["overall_score"] < 0.5

    def test_urgency_language_flagged(self):
        """Test urgency language is flagged."""
        text = "Act now! This offer expires immediately!"
        result = score_text_heuristics(text)
        assert "urgency_language" in result["indicators"]

    def test_crypto_reference_flagged(self):
        """Test crypto references are flagged."""
        text = "Send bitcoin to this wallet address for your prize"
        result = score_text_heuristics(text)
        assert "crypto_reference" in result["indicators"]


class TestURLHeuristics:
    """Tests for URL heuristic analysis."""

    def test_shortener_detected(self):
        """Test URL shorteners are detected."""
        result = score_url_heuristics("http://bit.ly/something")
        assert "url_shortener_used" in result["indicators"]
        assert result["overall_score"] >= 2

    def test_ip_address_url_detected(self):
        """Test IP-based URLs are detected."""
        result = score_url_heuristics("http://192.168.1.1/login")
        assert "url_uses_ip_address" in result["indicators"]
        assert result["overall_score"] >= 3

    def test_high_risk_tld_detected(self):
        """Test high-risk TLDs are detected."""
        result = score_url_heuristics("http://example.xyz/verify")
        indicators = result["indicators"]
        assert any("high_risk_tld" in ind for ind in indicators)

    def test_brand_impersonation_detected(self):
        """Test PayPal impersonation is detected."""
        result = score_url_heuristics("http://paypal-secure.fake.com/login")
        assert "brand_impersonation_paypal" in result["indicators"]
        assert result["risk_level"] in {"MEDIUM", "HIGH"}

    def test_phishing_keywords_detected(self):
        """Test phishing path keywords are detected."""
        result = score_url_heuristics("http://example.com/login/verify/account")
        assert "phishing_path_keywords" in result["indicators"]

    def test_safe_url_low_risk(self, sample_safe_url):
        """Test safe URLs return low risk."""
        result = score_url_heuristics(sample_safe_url)
        assert result["risk_level"] == "LOW"
        assert result["overall_score"] < 3

    def test_combined_indicators_high_risk(self):
        """Test multiple indicators result in high risk."""
        # URL with shortener + phishing keywords
        result = score_url_heuristics("http://bit.ly/verify-password-login")
        assert result["risk_level"] in {"MEDIUM", "HIGH"}
        assert len(result["indicators"]) >= 2


