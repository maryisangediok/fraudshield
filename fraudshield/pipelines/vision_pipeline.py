from typing import Dict, Any

from fastapi import UploadFile, HTTPException

from fraudshield.services.vision_service import analyze_image_bytes


async def analyze_image_with_llm(upload_file: UploadFile) -> Dict[str, Any]:
    """
    Main vision pipeline for /analyze when type == 'image'.

    1) Read the uploaded file bytes.
    2) Send to OpenAI's vision-enabled model.
    3) Adapt the response into the common FraudShield schema.
    """

    if upload_file is None:
        raise HTTPException(status_code=400, detail="file is required when type='image'.")

    data = await upload_file.read()
    if not data:
        raise HTTPException(status_code=400, detail="uploaded file is empty.")

    try:
        llm_result = analyze_image_bytes(data)
    except Exception as e:
        # Fallback if the vision model fails (quota or other issues)
        return {
            "risk_level": "UNKNOWN",
            "overall_score": 0.0,
            "modality_scores": {"image": 0.0},
            "explanation": (
                "Vision analysis unavailable; an error occurred while calling the vision model. "
                f"Internal error: {type(e).__name__}"
            ),
            "indicators": ["vision_unavailable"],
            "raw": {"error": str(e)},
        }

    # Expected llm_result:
    # {
    #   "risk_level": "LOW" | "MEDIUM" | "HIGH",
    #   "overall_score": float (0–10),
    #   "indicators": [...],
    #   "explanation": "..."
    # }

    score = float(llm_result.get("overall_score", 0.0))
    risk_level = llm_result.get("risk_level", "LOW")
    confidence = llm_result.get("confidence", 0.5)
    indicators = llm_result.get("indicators") or []
    explanation = llm_result.get("explanation", "")

    return {
        "risk_level": risk_level,
        "overall_score": score,
        "confidence": confidence,
        "modality_scores": {"image": score},
        "explanation": explanation,
        "indicators": indicators,
        "raw": {
            "vision": llm_result,
        },
    }

