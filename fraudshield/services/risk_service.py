from typing import Dict, List, Tuple


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
