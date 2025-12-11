"""
Confidence calibration utilities.
Adjusts LLM confidence based on heuristic agreement.
"""

from typing import Dict, Any, Tuple

# Risk level ordering for comparison
_RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "UNKNOWN": -1}


def calculate_agreement_score(
    llm_risk: str,
    heuristic_risk: str,
    llm_score: float,
    heuristic_score: float,
) -> Tuple[float, str]:
    """
    Calculate how much the LLM and heuristics agree.
    
    Returns:
        (agreement_score, agreement_label)
        - agreement_score: 0.0 to 1.0 (1.0 = perfect agreement)
        - agreement_label: "strong", "moderate", "weak", "conflict"
    """
    llm_level = _RISK_ORDER.get(llm_risk.upper(), 0)
    heuristic_level = _RISK_ORDER.get(heuristic_risk.upper(), 0)
    
    # Level difference (0, 1, or 2)
    level_diff = abs(llm_level - heuristic_level)
    
    # Normalize scores to same scale (0-10)
    # Heuristic text scores are 0-1, URL scores are 0-10
    llm_normalized = llm_score if llm_score <= 10 else llm_score / 10
    heuristic_normalized = heuristic_score if heuristic_score <= 1 else heuristic_score / 10
    
    # Score difference (0 to 1 scale)
    score_diff = abs(llm_normalized - heuristic_normalized)
    if llm_normalized > 1:  # 0-10 scale
        score_diff = score_diff / 10
    
    # Calculate agreement
    # Level agreement: 0 diff = 1.0, 1 diff = 0.5, 2 diff = 0.0
    level_agreement = max(0, 1.0 - (level_diff * 0.5))
    
    # Score agreement: closer scores = higher agreement
    score_agreement = max(0, 1.0 - score_diff)
    
    # Combined agreement (weight level more heavily)
    agreement = (level_agreement * 0.7) + (score_agreement * 0.3)
    
    # Label
    if agreement >= 0.8:
        label = "strong"
    elif agreement >= 0.5:
        label = "moderate"
    elif agreement >= 0.3:
        label = "weak"
    else:
        label = "conflict"
    
    return round(agreement, 3), label


def calibrate_confidence(
    llm_confidence: float,
    llm_risk: str,
    heuristic_risk: str,
    llm_score: float,
    heuristic_score: float,
) -> Dict[str, Any]:
    """
    Calibrate LLM confidence based on heuristic agreement.
    
    Returns:
        {
            "calibrated_confidence": float (0-1),
            "raw_llm_confidence": float (0-1),
            "agreement_score": float (0-1),
            "agreement_label": str,
            "adjustment": str ("boosted", "reduced", "unchanged")
        }
    """
    agreement_score, agreement_label = calculate_agreement_score(
        llm_risk, heuristic_risk, llm_score, heuristic_score
    )
    
    # Adjust confidence based on agreement
    # Strong agreement: boost confidence up to +0.2
    # Weak agreement: reduce confidence up to -0.3
    # Conflict: significantly reduce confidence
    
    if agreement_label == "strong":
        # Boost confidence (max 0.95)
        adjustment = min(0.2, (1.0 - llm_confidence) * 0.5)
        calibrated = min(0.95, llm_confidence + adjustment)
        adjustment_type = "boosted" if adjustment > 0.01 else "unchanged"
        
    elif agreement_label == "moderate":
        # Slight adjustment toward agreement
        adjustment = (agreement_score - 0.5) * 0.1
        calibrated = max(0.1, min(0.9, llm_confidence + adjustment))
        adjustment_type = "boosted" if adjustment > 0.01 else "reduced" if adjustment < -0.01 else "unchanged"
        
    elif agreement_label == "weak":
        # Reduce confidence
        adjustment = -0.15
        calibrated = max(0.15, llm_confidence + adjustment)
        adjustment_type = "reduced"
        
    else:  # conflict
        # Significant reduction - signals are contradicting
        adjustment = -0.3
        calibrated = max(0.1, llm_confidence + adjustment)
        adjustment_type = "reduced"
    
    return {
        "calibrated_confidence": round(calibrated, 3),
        "raw_llm_confidence": round(llm_confidence, 3),
        "agreement_score": agreement_score,
        "agreement_label": agreement_label,
        "adjustment": adjustment_type,
    }


def get_final_confidence(
    llm_result: Dict[str, Any],
    heuristic_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Convenience function to get calibrated confidence from pipeline results.
    
    Args:
        llm_result: Result from LLM (must have risk_level, overall_score, confidence)
        heuristic_result: Result from heuristics (must have risk_level, overall_score)
    
    Returns:
        Confidence calibration result dict
    """
    llm_confidence = float(llm_result.get("confidence", 0.5))
    llm_risk = llm_result.get("risk_level", "LOW")
    llm_score = float(llm_result.get("overall_score", 0))
    
    heuristic_risk = heuristic_result.get("risk_level", "LOW")
    heuristic_score = float(heuristic_result.get("overall_score", 0))
    
    return calibrate_confidence(
        llm_confidence=llm_confidence,
        llm_risk=llm_risk,
        heuristic_risk=heuristic_risk,
        llm_score=llm_score,
        heuristic_score=heuristic_score,
    )


