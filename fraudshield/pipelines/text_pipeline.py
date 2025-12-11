from typing import Dict, Any, Optional

from fraudshield.services.llm_client import LLMClient
from fraudshield.services.risk_service import score_text_heuristics
from fraudshield.services.velocity_service import velocity_tracker
from fraudshield.services.lists_service import pattern_lists
from fraudshield.utils.confidence import get_final_confidence
from fraudshield.utils.risk_levels import calculate_risk_level
from fraudshield.utils.explainability import generate_explainability_report, report_to_dict


def analyze_text_with_llm(
    text: str,
    ip_address: Optional[str] = None,
    client_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Main text pipeline for /analyze when type == 'text'.
    Combines heuristics + LLM + velocity checks + blacklist/whitelist.
    """

    # 0) Check blacklist/whitelist first (instant override)
    list_check = pattern_lists.check_content_hash(text)
    if list_check.matched:
        if list_check.risk_override == "LOW":
            return {
                "risk_level": "LOW",
                "overall_score": 0.0,
                "confidence": 0.95,
                "modality_scores": {"text": 0.0},
                "indicators": ["whitelisted_content"],
                "explanation": "Content matched whitelist. Marked as safe.",
                "raw": {"whitelist_match": list_check.pattern},
            }
        elif list_check.risk_override == "HIGH":
            return {
                "risk_level": "HIGH",
                "overall_score": 10.0,
                "confidence": 0.95,
                "modality_scores": {"text": 10.0},
                "indicators": ["blacklisted_content"],
                "explanation": f"Content matched blacklist ({list_check.category}). Marked as high risk.",
                "raw": {"blacklist_match": list_check.pattern},
            }

    # 1) Check velocity
    velocity = velocity_tracker.check_velocity(text, ip_address, client_id)
    
    # 2) Heuristic scoring
    heuristic = score_text_heuristics(text)

    # 3) LLM scoring
    llm = LLMClient()
    llm_result = llm.score_text(text)

    # 4) Combine scores (average + velocity boost)
    base_score = (heuristic["overall_score"] + llm_result["overall_score"]) / 2.0
    combined_score = min(10.0, base_score + velocity.risk_boost)

    # 5) Collect all indicators
    combined_indicators = list({
        *(heuristic.get("indicators") or []),
        *(llm_result.get("indicators") or []),
        *velocity.indicators,
    })

    # 6) Calculate risk level (score-based with critical overrides)
    combined_risk = calculate_risk_level(combined_score, combined_indicators)

    # 7) Calibrate confidence based on heuristic agreement
    confidence_info = get_final_confidence(llm_result, heuristic)
    calibrated_confidence = confidence_info["calibrated_confidence"]

    if confidence_info["agreement_label"] == "conflict":
        combined_indicators.append("heuristic_llm_conflict")

    # 8) Generate explainability report
    explainability = generate_explainability_report(
        score=combined_score,
        risk_level=combined_risk,
        confidence=calibrated_confidence,
        indicators=combined_indicators,
        heuristic_result=heuristic,
        llm_result=llm_result,
    )

    explanation = (
        f"{explainability.summary}\n\n"
        "Heuristic signals: "
        f"{heuristic.get('explanation', '')}\n\n"
        "LLM assessment: "
        f"{llm_result.get('explanation', '')}\n\n"
        f"Confidence: {confidence_info['agreement_label']} agreement "
        f"(heuristic vs LLM) → {confidence_info['adjustment']}"
    ).strip()

    return {
        "risk_level": combined_risk,
        "overall_score": combined_score,
        "confidence": calibrated_confidence,
        "modality_scores": {"text": combined_score},
        "indicators": combined_indicators,
        "explanation": explanation,
        "explainability": report_to_dict(explainability),
        "recommendations": explainability.recommendations,
        "raw": {
            "heuristic": heuristic,
            "llm": llm_result,
            "confidence_calibration": confidence_info,
            "velocity": {
                "risk_boost": velocity.risk_boost,
                "indicators": velocity.indicators,
            },
        },
    }
