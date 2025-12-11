"""
Explainability utilities.
Provides feature importance and detailed breakdowns for fraud scores.
"""

from typing import Dict, Any, List
from dataclasses import dataclass


@dataclass
class FeatureContribution:
    """A single feature's contribution to the risk score."""
    feature: str
    contribution: float  # How much this feature added/subtracted from score
    weight: float  # Relative importance (0-1)
    description: str
    category: str  # "text", "url", "behavior", "context"


@dataclass 
class ExplainabilityReport:
    """Full explainability breakdown."""
    total_score: float
    risk_level: str
    confidence: float
    
    # Feature breakdown
    top_features: List[FeatureContribution]
    feature_categories: Dict[str, float]  # Category -> total contribution
    
    # Human-readable
    summary: str
    recommendations: List[str]


# Feature weights for explainability (relative importance)
FEATURE_WEIGHTS = {
    # Text features
    "suspicious_keywords": 0.7,
    "urgency_language": 0.8,
    "crypto_reference": 0.6,
    "no_obvious_text_red_flags": 0.1,
    
    # URL features
    "url_uses_ip_address": 0.9,
    "url_shortener_used": 0.6,
    "phishing_path_keywords": 0.8,
    "sensitive_query_parameters": 0.7,
    "brand_impersonation_paypal": 1.0,
    "high_risk_tld": 0.7,
    
    # Behavior features
    "velocity_duplicate_content": 0.8,
    "velocity_high_ip_rate": 0.6,
    
    # LLM features
    "llm_unavailable": 0.0,
    "heuristic_llm_conflict": 0.4,
}

# Category mappings
FEATURE_CATEGORIES = {
    "suspicious_keywords": "text",
    "urgency_language": "text",
    "crypto_reference": "text",
    "no_obvious_text_red_flags": "text",
    
    "url_uses_ip_address": "url",
    "url_shortener_used": "url",
    "phishing_path_keywords": "url",
    "sensitive_query_parameters": "url",
    "brand_impersonation_paypal": "url",
    "high_risk_tld": "url",
    
    "velocity_duplicate_content": "behavior",
    "velocity_high_ip_rate": "behavior",
    
    "llm_unavailable": "system",
    "heuristic_llm_conflict": "system",
}

# Feature descriptions
FEATURE_DESCRIPTIONS = {
    "suspicious_keywords": "Contains keywords commonly used in scams (e.g., 'gift card', 'wire transfer')",
    "urgency_language": "Uses urgent language to pressure quick action",
    "crypto_reference": "References cryptocurrency, often used in scams",
    "no_obvious_text_red_flags": "No obvious textual red flags detected",
    
    "url_uses_ip_address": "URL uses IP address instead of domain name",
    "url_shortener_used": "URL uses a link shortener service",
    "phishing_path_keywords": "URL path contains phishing-related keywords (login, verify, etc.)",
    "sensitive_query_parameters": "URL contains sensitive parameters (otp, password, etc.)",
    "brand_impersonation_paypal": "URL appears to impersonate PayPal",
    "high_risk_tld": "URL uses a high-risk top-level domain",
    
    "velocity_duplicate_content": "Same content submitted multiple times rapidly",
    "velocity_high_ip_rate": "High request rate from this IP address",
    
    "llm_unavailable": "LLM analysis was unavailable",
    "heuristic_llm_conflict": "Heuristic and LLM assessments conflicted",
}


def calculate_feature_contributions(
    indicators: List[str],
    heuristic_score: float,
    llm_score: float,
) -> List[FeatureContribution]:
    """
    Calculate how much each feature contributed to the final score.
    """
    contributions = []
    
    # Base contribution from scores
    total_indicator_weight = sum(
        FEATURE_WEIGHTS.get(ind.split(":")[-1], 0.5)
        for ind in indicators
    )
    
    if total_indicator_weight == 0:
        total_indicator_weight = 1
    
    for indicator in indicators:
        # Handle prefixed indicators (e.g., "text:suspicious_keywords")
        base_indicator = indicator.split(":")[-1] if ":" in indicator else indicator
        
        weight = FEATURE_WEIGHTS.get(base_indicator, 0.5)
        category = FEATURE_CATEGORIES.get(base_indicator, "other")
        description = FEATURE_DESCRIPTIONS.get(
            base_indicator,
            f"Indicator: {base_indicator}"
        )
        
        # Estimate contribution based on weight proportion
        contribution = (weight / total_indicator_weight) * heuristic_score
        
        contributions.append(FeatureContribution(
            feature=indicator,
            contribution=round(contribution, 2),
            weight=weight,
            description=description,
            category=category,
        ))
    
    # Sort by contribution (highest first)
    contributions.sort(key=lambda x: x.contribution, reverse=True)
    
    return contributions


def generate_explainability_report(
    score: float,
    risk_level: str,
    confidence: float,
    indicators: List[str],
    heuristic_result: Dict[str, Any],
    llm_result: Dict[str, Any],
) -> ExplainabilityReport:
    """
    Generate a full explainability report for an analysis.
    """
    heuristic_score = heuristic_result.get("overall_score", 0)
    llm_score = llm_result.get("overall_score", 0)
    
    # Calculate feature contributions
    contributions = calculate_feature_contributions(
        indicators, heuristic_score, llm_score
    )
    
    # Aggregate by category
    category_totals: Dict[str, float] = {}
    for contrib in contributions:
        cat = contrib.category
        category_totals[cat] = category_totals.get(cat, 0) + contrib.contribution
    
    # Generate summary
    top_3 = contributions[:3]
    if top_3:
        top_features_text = ", ".join([f.feature for f in top_3])
        summary = f"Risk assessment based primarily on: {top_features_text}. "
    else:
        summary = "No significant risk indicators detected. "
    
    summary += f"Combined score: {score:.1f}/10 ({risk_level}). "
    summary += f"Confidence: {confidence:.0%}."
    
    # Generate recommendations
    recommendations = []
    
    if risk_level == "HIGH":
        recommendations.append("⚠️ HIGH RISK: Do not proceed without verification")
        recommendations.append("Contact the supposed sender through official channels")
        
    if any("url" in c.category for c in contributions):
        recommendations.append("🔗 Verify the URL by typing it directly in your browser")
        
    if any("urgency" in c.feature.lower() for c in contributions):
        recommendations.append("⏰ Be wary of urgency tactics - legitimate organizations don't pressure you")
        
    if any("credential" in c.feature.lower() or "password" in c.feature.lower() for c in contributions):
        recommendations.append("🔐 Never share passwords or OTPs via email, text, or phone")
    
    if not recommendations:
        recommendations.append("✅ No immediate concerns, but always verify unexpected messages")
    
    return ExplainabilityReport(
        total_score=score,
        risk_level=risk_level,
        confidence=confidence,
        top_features=contributions[:5],  # Top 5 features
        feature_categories=category_totals,
        summary=summary,
        recommendations=recommendations,
    )


def report_to_dict(report: ExplainabilityReport) -> Dict[str, Any]:
    """Convert report to dictionary for JSON serialization."""
    return {
        "total_score": report.total_score,
        "risk_level": report.risk_level,
        "confidence": report.confidence,
        "summary": report.summary,
        "recommendations": report.recommendations,
        "feature_breakdown": [
            {
                "feature": f.feature,
                "contribution": f.contribution,
                "weight": f.weight,
                "description": f.description,
                "category": f.category,
            }
            for f in report.top_features
        ],
        "category_scores": report.feature_categories,
    }


