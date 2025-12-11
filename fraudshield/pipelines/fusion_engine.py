from typing import Dict, Any, List

from fraudshield.utils.risk_levels import calculate_risk_level


def fuse_modalities(modality_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Fuse multiple modality results into a single overall decision.

    Expected per-modality structure:
    {
        "risk_level": "LOW" | "MEDIUM" | "HIGH",
        "overall_score": float (0–10),
        "indicators": [str, ...],
        "explanation": str,
        ...
    }
    """

    if not modality_results:
        return {
            "risk_level": "LOW",
            "overall_score": 0.0,
            "confidence": 0.0,
            "modality_scores": {},
            "explanation": "No modalities were provided for analysis.",
            "indicators": [],
            "raw": {},
        }

    # 1) Collect per-modality scores
    modality_scores: Dict[str, float] = {}
    modality_confidences: List[float] = []
    all_indicators: List[str] = []

    # You can tune these weights later
    weights = {
        "text": 1.0,
        "url": 1.1,
        "audio": 1.3,
        "image": 1.2,
    }

    weighted_sum = 0.0
    weight_total = 0.0

    explanations_sections: List[str] = []

    for modality, result in modality_results.items():
        score = float(result.get("overall_score", 0.0))
        confidence = float(result.get("confidence", 0.5))
        indicators = result.get("indicators") or []
        expl = result.get("explanation", "")

        modality_scores[modality] = score
        modality_confidences.append(confidence)
        all_indicators.extend([f"{modality}:{ind}" for ind in indicators])

        w = weights.get(modality, 1.0)
        weighted_sum += score * w
        weight_total += w

        if expl:
            explanations_sections.append(f"[{modality.upper()}] {expl}")

    # 2) Weighted average overall score
    overall_score = weighted_sum / weight_total if weight_total > 0 else 0.0

    # 3) Average confidence across modalities
    avg_confidence = sum(modality_confidences) / len(modality_confidences) if modality_confidences else 0.0

    # 4) Calculate risk level (score-based with critical indicator overrides)
    fused_level = calculate_risk_level(overall_score, all_indicators)

    # 5) Combined explanation
    explanation = (
        "Multi-modal analysis combining: "
        + ", ".join(modality_results.keys())
        + ".\n\n"
        + "\n\n".join(explanations_sections)
    )

    return {
        "risk_level": fused_level,
        "overall_score": overall_score,
        "confidence": avg_confidence,
        "modality_scores": modality_scores,
        "explanation": explanation,
        "indicators": all_indicators,
        "raw": modality_results,
    }

