from pydantic import BaseModel
from typing import Dict, List, Optional, Any


class FeatureBreakdown(BaseModel):
    """Single feature contribution to risk score."""
    feature: str
    contribution: float
    weight: float
    description: str
    category: str


class ExplainabilityData(BaseModel):
    """Detailed explainability breakdown."""
    summary: str
    recommendations: List[str]
    feature_breakdown: List[FeatureBreakdown]
    category_scores: Dict[str, float]


class AnalyzeResponse(BaseModel):
    risk_level: str
    overall_score: float
    confidence: Optional[float] = None  # 0.0-1.0 confidence in the assessment
    modality_scores: Dict[str, float]
    explanation: str
    indicators: List[str]
    explainability: Optional[ExplainabilityData] = None  # Detailed breakdown


class FeedbackRequest(BaseModel):
    """Request to submit feedback on an analysis."""
    content: str  # The original analyzed content
    modality: str  # text, url, image, etc.
    predicted_risk_level: str  # What the system predicted
    predicted_score: float
    feedback_type: str  # "false_positive", "false_negative", "correct"
    actual_risk_level: Optional[str] = None  # What it should have been
    analysis_id: Optional[int] = None
    comment: Optional[str] = None


class FeedbackResponse(BaseModel):
    """Response after submitting feedback."""
    id: int
    message: str
    feedback_type: str


class FeedbackStats(BaseModel):
    """Feedback statistics."""
    period_days: int
    total_feedback: int
    false_positives: int
    false_negatives: int
    correct: int
    false_positive_rate: float
    false_negative_rate: float
    accuracy: float
