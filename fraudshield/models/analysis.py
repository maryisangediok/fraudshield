from sqlalchemy import Column, Integer, String, DateTime, JSON, func
from fraudshield.database import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    user_hash = Column(String, nullable=True)

    modality = Column(String, nullable=False)        # text | link | audio | video
    risk_level = Column(String, nullable=False)      # LOW / MEDIUM / HIGH
    overall_score = Column(String, nullable=False)   # stored as string for simplicity

    modality_scores = Column(JSON, nullable=True)    # {"text": 0.83, "url": 0.12}
    indicators = Column(JSON, nullable=True)         # ["urgent_language", "synthetic_voice"]

    source_hint = Column(String, nullable=True)      # e.g. "sms", "whatsapp", "email"
    created_at = Column(DateTime(timezone=True), server_default=func.now())
