from fastapi import FastAPI, Depends, Form, File, UploadFile, HTTPException, status
from sqlalchemy.orm import Session
from typing import Dict, List, Optional

from fraudshield.database import SessionLocal, Base, engine
from fraudshield.schemas.analyze_schemas import AnalyzeResponse
from fraudshield.services.text_service import TextAnalysisService
from fraudshield.services.link_service import LinkAnalysisService
from fraudshield.services.audio_service import AudioAnalysisService
from fraudshield.services.video_service import VideoAnalysisService
from fraudshield.services.risk_service import RiskService
from fraudshield.models.analysis import Analysis

Base.metadata.create_all(bind=engine)

app = FastAPI(title="FraudShield API", version="0.1.0")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


SUPPORTED_TYPES = {"text", "link", "url", "audio", "video"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    type: str = Form(..., description="One of: text, link, url, audio, video"),
    text: Optional[str] = Form(None),
    url: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    source_hint: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    t = type.lower()
    if t not in SUPPORTED_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported type '{type}'. Must be one of {SUPPORTED_TYPES}.",
        )

    modality_scores: Dict[str, float] = {}
    indicators: List[str] = []

    if t == "text":
        if not text:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Field 'text' is required for type='text'.",
            )
        score, mods = TextAnalysisService.analyze(text)
        modality_scores["text"] = score
        indicators.extend(mods)

    elif t in {"link", "url"}:
        if not url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Field 'url' is required for type='link' or 'url'.",
            )
        score, mods = LinkAnalysisService.analyze(url)
        modality_scores["url"] = score
        indicators.extend(mods)

    elif t == "audio":
        if not file:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File is required for type='audio'.",
            )
        score, mods = await AudioAnalysisService.analyze(file)
        modality_scores["audio"] = score
        indicators.extend(mods)

    elif t == "video":
        if not file:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File is required for type='video'.",
            )
        score, mods = await VideoAnalysisService.analyze(file)
        modality_scores["video"] = score
        indicators.extend(mods)

    risk_level, overall_score, explanation = RiskService.compute(modality_scores, indicators)

    analysis = Analysis(
        user_hash=None,
        modality=t,
        risk_level=risk_level,
        overall_score=str(overall_score),
        modality_scores=modality_scores,
        indicators=indicators,
        source_hint=source_hint,
    )
    db.add(analysis)
    db.commit()

    return AnalyzeResponse(
        risk_level=risk_level,
        overall_score=overall_score,
        modality_scores=modality_scores,
        explanation=explanation,
        indicators=indicators,
    )
