from typing import Dict, Any

from fastapi import UploadFile

from fraudshield.services.audio_service import transcribe_audio_file
from fraudshield.pipelines.text_pipeline import analyze_text_with_llm


async def analyze_audio_with_llm(upload_file: UploadFile) -> Dict[str, Any]:
    """
    Main audio pipeline for /analyze when type == 'audio'.

    1) Transcribe the audio to text.
    2) Run the existing text pipeline on the transcript.
    3) Adapt the response to mark modality as 'audio'.
    """
    transcript = await transcribe_audio_file(upload_file)

    text_result = analyze_text_with_llm(transcript)

    # Re-label modality_scores to 'audio' while keeping everything else
    modality_scores = {"audio": text_result.get("overall_score", 0.0)}

    return {
        "risk_level": text_result["risk_level"],
        "overall_score": text_result["overall_score"],
        "confidence": text_result.get("confidence", 0.5),
        "modality_scores": modality_scores,
        "explanation": (
            "Audio transcript analyzed as text.\n\n"
            f"Transcript:\n{transcript}\n\n"
            f"Analysis:\n{text_result.get('explanation', '')}"
        ),
        "indicators": text_result.get("indicators", []),
        "raw": {
            "transcript": transcript,
            "text_analysis": text_result,
        },
    }
