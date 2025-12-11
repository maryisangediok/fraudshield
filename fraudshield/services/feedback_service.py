"""
Feedback service for tracking and analyzing user feedback.
"""

import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from fraudshield.config import settings
from fraudshield.models.feedback import Feedback


def hash_content(content: str) -> str:
    """Create a hash of content for deduplication."""
    return hashlib.sha256(content.encode()).hexdigest()[:64]


def submit_feedback(
    db: Session,
    content: str,
    modality: str,
    predicted_risk_level: str,
    predicted_score: float,
    feedback_type: str,
    actual_risk_level: Optional[str] = None,
    analysis_id: Optional[int] = None,
    client_id: Optional[str] = None,
    user_comment: Optional[str] = None,
) -> Feedback:
    """
    Submit feedback for an analysis result.
    
    Args:
        db: Database session
        content: The analyzed content (text, URL, etc.)
        modality: Type of analysis (text, url, image, etc.)
        predicted_risk_level: What the system predicted
        predicted_score: The score the system gave
        feedback_type: "false_positive", "false_negative", or "correct"
        actual_risk_level: What the risk level should have been
        analysis_id: Optional link to Analysis record
        client_id: Optional client identifier
        user_comment: Optional user explanation
    """
    feedback = Feedback(
        content_hash=hash_content(content),
        modality=modality,
        predicted_risk_level=predicted_risk_level,
        predicted_score=predicted_score,
        feedback_type=feedback_type,
        actual_risk_level=actual_risk_level,
        analysis_id=analysis_id,
        client_id=client_id,
        user_comment=user_comment,
    )
    
    db.add(feedback)
    db.commit()
    db.refresh(feedback)
    
    return feedback


def get_feedback_stats(
    db: Session,
    days: int = 30,
    client_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Get feedback statistics for monitoring model performance.
    """
    since = datetime.utcnow() - timedelta(days=days)
    
    query = db.query(Feedback).filter(Feedback.created_at >= since)
    if client_id:
        query = query.filter(Feedback.client_id == client_id)
    
    total = query.count()
    
    if total == 0:
        return {
            "period_days": days,
            "total_feedback": 0,
            "false_positive_rate": 0.0,
            "false_negative_rate": 0.0,
            "accuracy": 0.0,
        }
    
    false_positives = query.filter(Feedback.feedback_type == "false_positive").count()
    false_negatives = query.filter(Feedback.feedback_type == "false_negative").count()
    correct = query.filter(Feedback.feedback_type == "correct").count()
    
    return {
        "period_days": days,
        "total_feedback": total,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "correct": correct,
        "false_positive_rate": round(false_positives / total, 4) if total > 0 else 0.0,
        "false_negative_rate": round(false_negatives / total, 4) if total > 0 else 0.0,
        "accuracy": round(correct / total, 4) if total > 0 else 0.0,
    }


def get_common_false_positives(
    db: Session,
    limit: int = 10,
) -> List[Dict[str, Any]]:
    """Get most common content hashes that were false positives."""
    results = (
        db.query(
            Feedback.content_hash,
            Feedback.modality,
            func.count(Feedback.id).label("count"),
        )
        .filter(Feedback.feedback_type == "false_positive")
        .group_by(Feedback.content_hash, Feedback.modality)
        .order_by(func.count(Feedback.id).desc())
        .limit(limit)
        .all()
    )
    
    return [
        {"content_hash": r.content_hash, "modality": r.modality, "count": r.count}
        for r in results
    ]


def should_whitelist(
    db: Session,
    content_hash: str,
    threshold: Optional[int] = None,
) -> bool:
    """
    Check if content has enough false positive reports to suggest whitelisting.
    Uses config value if threshold not provided.
    """
    threshold = threshold if threshold is not None else settings.whitelist_suggestion_threshold
    
    count = (
        db.query(Feedback)
        .filter(
            Feedback.content_hash == content_hash,
            Feedback.feedback_type == "false_positive",
        )
        .count()
    )
    return count >= threshold

