from pydantic import BaseModel
from typing import Dict, List


class AnalyzeResponse(BaseModel):
    risk_level: str
    overall_score: float
    modality_scores: Dict[str, float]
    explanation: str
    indicators: List[str]
