from fastapi import FastAPI, Depends, Form, File, UploadFile, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import Dict, List, Optional
import logging

from fraudshield.config import settings
from fraudshield.database import SessionLocal, Base, engine
from fraudshield.schemas.analyze_schemas import (
    AnalyzeResponse,
    FeedbackRequest,
    FeedbackResponse,
    FeedbackStats,
)
from fraudshield.models.feedback import Feedback
from fraudshield.services.feedback_service import submit_feedback, get_feedback_stats
from fraudshield.services.text_service import TextAnalysisService
from fraudshield.pipelines.text_pipeline import analyze_text_with_llm
from fraudshield.pipelines.url_pipeline import analyze_url_with_llm
from fraudshield.pipelines.audio_pipeline import analyze_audio_with_llm
from fraudshield.pipelines.vision_pipeline import analyze_image_with_llm
from fraudshield.pipelines.fusion_engine import fuse_modalities
from fraudshield.pipelines.email_pipeline import analyze_email_with_llm
from fraudshield.pipelines.pdf_pipeline import analyze_pdf_with_llm
from fraudshield.pipelines.video_pipeline import analyze_video_with_llm
from fraudshield.services.link_service import LinkAnalysisService
from fraudshield.services.audio_service import AudioAnalysisService
from fraudshield.services.risk_service import RiskService
from fraudshield.models.analysis import Analysis
from fraudshield.api.security import verify_api_token, check_rate_limit
from fraudshield.api.admin import router as admin_router
from fraudshield.utils.logging_config import metrics, StructuredLogger, init_logging

# Initialize structured logging
init_logging()

logger = StructuredLogger(__name__)

Base.metadata.create_all(bind=engine)

# Create app with metadata
app = FastAPI(
    title="FraudShield API",
    version="0.1.0",
    description="Multimodal AI-powered fraud detection API",
    docs_url="/docs" if settings.debug else None,  # Disable docs in production
    redoc_url="/redoc" if settings.debug else None,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# Rate limit headers middleware
@app.middleware("http")
async def add_rate_limit_headers(request: Request, call_next):
    response = await call_next(request)
    if hasattr(request.state, "rate_limit_remaining"):
        response.headers["X-RateLimit-Limit"] = str(request.state.rate_limit_limit)
        response.headers["X-RateLimit-Remaining"] = str(request.state.rate_limit_remaining)
    return response


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


SUPPORTED_TYPES = {"text", "link", "url", "audio", "image", "video", "email", "pdf", "document", "multi"}

# Include admin router
app.include_router(admin_router)


@app.get("/health")
def health():
    """Health check endpoint - no auth required."""
    return {"status": "ok"}


@app.get("/status")
def status_info():
    """
    API status and configuration info.
    Useful for debugging and monitoring.
    """
    return {
        "status": "ok",
        "version": "0.1.0",
        "environment": settings.environment,
        "auth_enabled": bool(settings.api_token),
        "rate_limit": {
            "requests": settings.rate_limit_requests,
            "window_seconds": settings.rate_limit_window,
        },
        "supported_types": list(SUPPORTED_TYPES),
    }


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    dependencies=[Depends(verify_api_token), Depends(check_rate_limit)],
)
async def analyze(
    request: Request,
    type: str = Form(..., description="One of: text, url, audio, image, video, email, pdf, multi"),
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
        result = analyze_text_with_llm(text)

        analysis = Analysis(
            user_hash=None,
            modality=t,
            risk_level=result["risk_level"],
            overall_score=str(result["overall_score"]),
            modality_scores=result["modality_scores"],
            indicators=result["indicators"],
            source_hint=source_hint,
        )
        db.add(analysis)
        db.commit()

        return AnalyzeResponse(
            risk_level=result["risk_level"],
            overall_score=result["overall_score"],
            confidence=result.get("confidence"),
            modality_scores=result["modality_scores"],
            explanation=result["explanation"],
            indicators=result["indicators"],
        )

    elif t in {"link", "url"}:
        if not url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Field 'url' is required for type='link' or 'url'.",
            )
        result = analyze_url_with_llm(url)

        analysis = Analysis(
            user_hash=None,
            modality=t,
            risk_level=result["risk_level"],
            overall_score=str(result["overall_score"]),
            modality_scores=result["modality_scores"],
            indicators=result["indicators"],
            source_hint=source_hint,
        )
        db.add(analysis)
        db.commit()

        return AnalyzeResponse(
            risk_level=result["risk_level"],
            overall_score=result["overall_score"],
            confidence=result.get("confidence"),
            modality_scores=result["modality_scores"],
            explanation=result["explanation"],
            indicators=result["indicators"],
        )

    elif t == "audio":
        if not file:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File is required for type='audio'.",
            )
        result = await analyze_audio_with_llm(file)

        analysis = Analysis(
            user_hash=None,
            modality=t,
            risk_level=result["risk_level"],
            overall_score=str(result["overall_score"]),
            modality_scores=result["modality_scores"],
            indicators=result["indicators"],
            source_hint=source_hint,
        )
        db.add(analysis)
        db.commit()

        return AnalyzeResponse(
            risk_level=result["risk_level"],
            overall_score=result["overall_score"],
            confidence=result.get("confidence"),
            modality_scores=result["modality_scores"],
            explanation=result["explanation"],
            indicators=result["indicators"],
        )

    elif t == "image":
        if not file:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File is required for type='image'.",
            )
        result = await analyze_image_with_llm(file)

        analysis = Analysis(
            user_hash=None,
            modality=t,
            risk_level=result["risk_level"],
            overall_score=str(result["overall_score"]),
            modality_scores=result["modality_scores"],
            indicators=result["indicators"],
            source_hint=source_hint,
        )
        db.add(analysis)
        db.commit()

        return AnalyzeResponse(
            risk_level=result["risk_level"],
            overall_score=result["overall_score"],
            confidence=result.get("confidence"),
            modality_scores=result["modality_scores"],
            explanation=result["explanation"],
            indicators=result["indicators"],
        )

    elif t == "multi":
        # Multi-modal fusion: analyze all provided inputs
        modality_results: Dict[str, dict] = {}

        # TEXT if present
        if text:
            modality_results["text"] = analyze_text_with_llm(text)

        # URL if present
        if url:
            modality_results["url"] = analyze_url_with_llm(url)

        # FILE if present: use source_hint to decide how to treat it
        if file:
            hint = (source_hint or "").lower()
            if "audio" in hint:
                modality_results["audio"] = await analyze_audio_with_llm(file)
            elif "image" in hint or "screenshot" in hint:
                modality_results["image"] = await analyze_image_with_llm(file)
            else:
                # default to image
                modality_results["image"] = await analyze_image_with_llm(file)

        if not modality_results:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="For type='multi', provide at least one of: text, url, file.",
            )

        result = fuse_modalities(modality_results)

        analysis = Analysis(
            user_hash=None,
            modality=t,
            risk_level=result["risk_level"],
            overall_score=str(result["overall_score"]),
            modality_scores=result["modality_scores"],
            indicators=result["indicators"],
            source_hint=source_hint,
        )
        db.add(analysis)
        db.commit()

        return AnalyzeResponse(
            risk_level=result["risk_level"],
            overall_score=result["overall_score"],
            confidence=result.get("confidence"),
            modality_scores=result["modality_scores"],
            explanation=result["explanation"],
            indicators=result["indicators"],
        )

    elif t == "video":
        if not file:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File is required for type='video'.",
            )
        result = await analyze_video_with_llm(file)

        analysis = Analysis(
            user_hash=None,
            modality=t,
            risk_level=result["risk_level"],
            overall_score=str(result["overall_score"]),
            modality_scores=result["modality_scores"],
            indicators=result["indicators"],
            source_hint=source_hint,
        )
        db.add(analysis)
        db.commit()

        return AnalyzeResponse(
            risk_level=result["risk_level"],
            overall_score=result["overall_score"],
            confidence=result.get("confidence"),
            modality_scores=result["modality_scores"],
            explanation=result["explanation"],
            indicators=result["indicators"],
        )

    elif t == "email":
        if not file:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File (.eml) is required for type='email'.",
            )
        result = await analyze_email_with_llm(file)

        analysis = Analysis(
            user_hash=None,
            modality=t,
            risk_level=result["risk_level"],
            overall_score=str(result["overall_score"]),
            modality_scores=result["modality_scores"],
            indicators=result["indicators"],
            source_hint=source_hint,
        )
        db.add(analysis)
        db.commit()

        return AnalyzeResponse(
            risk_level=result["risk_level"],
            overall_score=result["overall_score"],
            confidence=result.get("confidence"),
            modality_scores=result["modality_scores"],
            explanation=result["explanation"],
            indicators=result["indicators"],
        )

    elif t in {"pdf", "document"}:
        if not file:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File is required for type='pdf' or 'document'.",
            )
        result = await analyze_pdf_with_llm(file)

        analysis = Analysis(
            user_hash=None,
            modality=t,
            risk_level=result["risk_level"],
            overall_score=str(result["overall_score"]),
            modality_scores=result["modality_scores"],
            indicators=result["indicators"],
            source_hint=source_hint,
        )
        db.add(analysis)
        db.commit()

        return AnalyzeResponse(
            risk_level=result["risk_level"],
            overall_score=result["overall_score"],
            confidence=result.get("confidence"),
            modality_scores=result["modality_scores"],
            explanation=result["explanation"],
            indicators=result["indicators"],
        )

    # Fallback (shouldn't reach here due to validation)
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Unsupported type: {type}",
    )


# ============== FEEDBACK ENDPOINTS ==============


@app.post(
    "/feedback",
    response_model=FeedbackResponse,
    dependencies=[Depends(verify_api_token)],
)
async def submit_analysis_feedback(
    feedback: FeedbackRequest,
    db: Session = Depends(get_db),
):
    """
    Submit feedback on an analysis result.
    
    Use this to report false positives or false negatives,
    which helps improve the system over time.
    """
    if feedback.feedback_type not in ["false_positive", "false_negative", "correct"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="feedback_type must be 'false_positive', 'false_negative', or 'correct'",
        )
    
    result = submit_feedback(
        db=db,
        content=feedback.content,
        modality=feedback.modality,
        predicted_risk_level=feedback.predicted_risk_level,
        predicted_score=feedback.predicted_score,
        feedback_type=feedback.feedback_type,
        actual_risk_level=feedback.actual_risk_level,
        analysis_id=feedback.analysis_id,
        user_comment=feedback.comment,
    )
    
    return FeedbackResponse(
        id=result.id,
        message="Feedback submitted successfully. Thank you!",
        feedback_type=feedback.feedback_type,
    )


@app.get(
    "/feedback/stats",
    response_model=FeedbackStats,
    dependencies=[Depends(verify_api_token)],
)
async def get_feedback_statistics(
    days: int = 30,
    db: Session = Depends(get_db),
):
    """
    Get feedback statistics for monitoring model performance.
    
    Shows false positive/negative rates and overall accuracy
    based on user feedback.
    """
    stats = get_feedback_stats(db=db, days=days)
    return FeedbackStats(**stats)
