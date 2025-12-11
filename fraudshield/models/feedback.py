"""
Feedback model for tracking false positives/negatives.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Enum
from fraudshield.database import Base
import enum


class FeedbackType(str, enum.Enum):
    FALSE_POSITIVE = "false_positive"  # Flagged as fraud but wasn't
    FALSE_NEGATIVE = "false_negative"  # Missed fraud
    CORRECT = "correct"  # Correct classification
    

class Feedback(Base):
    """User feedback on analysis results."""
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, index=True)
    
    # Reference to original analysis
    analysis_id = Column(Integer, nullable=True)  # Link to Analysis table
    content_hash = Column(String(64), index=True)  # Hash of analyzed content
    
    # What the system predicted
    predicted_risk_level = Column(String(10))
    predicted_score = Column(Float)
    
    # User feedback
    feedback_type = Column(String(20))  # false_positive, false_negative, correct
    actual_risk_level = Column(String(10), nullable=True)  # What it should have been
    
    # Context
    modality = Column(String(20))
    client_id = Column(String(100), nullable=True)
    user_comment = Column(Text, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    reviewed = Column(Integer, default=0)  # 0 = pending, 1 = reviewed
    reviewer_notes = Column(Text, nullable=True)


