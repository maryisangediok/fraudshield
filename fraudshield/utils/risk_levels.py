"""
Risk level utilities.
Industry-standard: score-derived risk with critical indicator overrides.
Supports configurable thresholds via environment variables.
"""

from typing import List, Set, Optional

from fraudshield.config import settings


def _get_critical_indicators() -> Set[str]:
    """Get critical indicators from config (with fallback defaults)."""
    config_indicators = set(settings.critical_indicators_list)
    
    # Always include these core critical indicators
    core_critical = {
        "credential_theft",
        "identity_theft",
        "brand_impersonation_paypal",
        "brand_impersonation",
        "wire_transfer_request",
        "gift_card_scam",
        "malware_distribution",
        "known_phishing_url",
    }
    
    return config_indicators | core_critical


def _get_elevated_indicators() -> Set[str]:
    """Get elevated indicators from config (with fallback defaults)."""
    config_indicators = set(settings.elevated_indicators_list)
    
    # Always include these core elevated indicators
    core_elevated = {
        "urgency_language",
        "suspicious_keywords",
        "crypto_reference",
        "url_shortener_used",
    }
    
    return config_indicators | core_elevated


def derive_risk_from_score(
    score: float,
    high_threshold: Optional[float] = None,
    medium_threshold: Optional[float] = None,
) -> str:
    """
    Derive risk level purely from score (0-10 scale).
    
    Args:
        score: The risk score (0-10)
        high_threshold: Score >= this = HIGH (default from config)
        medium_threshold: Score >= this = MEDIUM (default from config)
    
    Returns:
        "LOW", "MEDIUM", or "HIGH"
    """
    # Use config values if not provided
    high = high_threshold if high_threshold is not None else settings.high_risk_threshold
    medium = medium_threshold if medium_threshold is not None else settings.medium_risk_threshold
    
    if score >= high:
        return "HIGH"
    elif score >= medium:
        return "MEDIUM"
    else:
        return "LOW"


def has_critical_indicator(indicators: List[str]) -> bool:
    """Check if any indicator is critical (forces HIGH risk)."""
    critical_set = _get_critical_indicators()
    
    for indicator in indicators:
        # Direct match
        if indicator.lower() in critical_set:
            return True
        # Check for prefixed indicators (e.g., "text:credential_theft")
        if ":" in indicator:
            base = indicator.split(":", 1)[-1].lower()
            if base in critical_set:
                return True
    return False


def has_elevated_indicator(indicators: List[str]) -> bool:
    """Check if any indicator suggests elevated risk."""
    elevated_set = _get_elevated_indicators()
    
    for indicator in indicators:
        if indicator.lower() in elevated_set:
            return True
        if ":" in indicator:
            base = indicator.split(":", 1)[-1].lower()
            if base in elevated_set:
                return True
    return False


def calculate_risk_level(
    score: float,
    indicators: List[str],
    high_threshold: Optional[float] = None,
    medium_threshold: Optional[float] = None,
) -> str:
    """
    Calculate risk level using industry-standard approach:
    1. Derive base risk from score (with configurable thresholds)
    2. Override to HIGH if critical indicators present
    3. Bump to at least MEDIUM if elevated indicators present
    
    Args:
        score: Combined score (0-10 scale)
        indicators: List of detected indicators
        high_threshold: Score >= this = HIGH (default from config)
        medium_threshold: Score >= this = MEDIUM (default from config)
        
    Returns:
        "LOW", "MEDIUM", or "HIGH"
    """
    # Check for critical indicators first (force HIGH)
    if has_critical_indicator(indicators):
        return "HIGH"
    
    # Derive base risk from score with thresholds
    base_risk = derive_risk_from_score(score, high_threshold, medium_threshold)
    
    # If we have elevated indicators and score says LOW, bump to MEDIUM
    if base_risk == "LOW" and has_elevated_indicator(indicators):
        return "MEDIUM"
    
    return base_risk

