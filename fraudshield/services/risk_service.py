import re
from typing import Any, Dict, List, Tuple

from fraudshield.services.text_service import TextAnalysisService

SUSPICIOUS_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "rb.gy",
    "t.co",
    "is.gd",
]

HIGH_RISK_TLDS = [
    ".ru", ".cn", ".tk", ".xyz", ".top", ".click", ".link", ".info",
]


def score_text_heuristics(text: str) -> Dict[str, Any]:
    """Wrapper around TextAnalysisService for pipeline compatibility."""
    raw_score, indicators = TextAnalysisService.analyze(text)
    
    # Convert 0-1 scale to 0-10 scale for consistency
    score = raw_score * 10

    if score >= 7:
        risk_level = "HIGH"
    elif score >= 4:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_level": risk_level,
        "overall_score": score,
        "indicators": indicators,
        "explanation": f"Text heuristics detected: {', '.join(indicators)}",
    }


def score_url_heuristics(url: str) -> Dict[str, Any]:
    """
    URL-only heuristic scoring.
    Scale: 0–10.
    """
    score = 0.0
    indicators: List[str] = []
    url_lower = url.lower()

    # 1) IP-based URLs
    if re.match(r"^https?://(\d{1,3}\.){3}\d{1,3}", url_lower):
        score += 3
        indicators.append("url_uses_ip_address")

    # 2) Suspicious shorteners
    if any(short in url_lower for short in SUSPICIOUS_SHORTENERS):
        score += 2
        indicators.append("url_shortener_used")

    # 3) High-risk TLDs
    for tld in HIGH_RISK_TLDS:
        if tld in url_lower:
            score += 2
            indicators.append(f"high_risk_tld:{tld}")
            break

    # 4) Impersonation: looks like PayPal but is not paypal.com
    if "paypal" in url_lower and "paypal.com" not in url_lower:
        score += 4
        indicators.append("brand_impersonation_paypal")

    # 5) Phishy path keywords (strong signal)
    path_keywords = ["login", "signin", "verify", "secure", "account", "reset", "password"]
    if any(k in url_lower for k in path_keywords):
        score += 3
        indicators.append("phishing_path_keywords")

    # 6) Sensitive query params (strong signal)
    query_keywords = ["otp", "code", "token", "password", "ssn"]
    if any(k in url_lower for k in query_keywords):
        score += 3
        indicators.append("sensitive_query_parameters")

    # Cap
    if score > 10:
        score = 10.0

    # Tighter thresholds
    if score >= 6:
        risk_level = "HIGH"
    elif score >= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    explanation = (
        "URL heuristics detected: " + ", ".join(indicators)
        if indicators
        else "No strong heuristic risk indicators found in the URL."
    )

    return {
        "risk_level": risk_level,
        "overall_score": score,
        "indicators": indicators,
        "explanation": explanation,
    }


class RiskService:
    @staticmethod
    def compute(modality_scores: Dict[str, float], indicators: List[str]) -> Tuple[str, float, str]:
        if not modality_scores:
            return "LOW", 0.0, "No signals detected."

        avg = sum(modality_scores.values()) / len(modality_scores)

        if avg >= 0.75:
            level = "HIGH"
        elif avg >= 0.4:
            level = "MEDIUM"
        else:
            level = "LOW"

        explanation = f"Overall risk is {level} based on modalities: {', '.join(modality_scores.keys())}."
        return level, avg, explanation
