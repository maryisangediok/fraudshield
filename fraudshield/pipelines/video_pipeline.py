"""
Video analysis pipeline.
Extracts frames and audio from videos, analyzes both for fraud.
"""

import os
from typing import Dict, Any, List

from fastapi import UploadFile

from fraudshield.services.video_service import extract_video_components, cleanup_audio_file
from fraudshield.services.vision_service import analyze_image_bytes
from fraudshield.services.audio_service import transcribe_audio_file
from fraudshield.pipelines.text_pipeline import analyze_text_with_llm
from fraudshield.pipelines.fusion_engine import fuse_modalities


async def analyze_video_with_llm(upload_file: UploadFile) -> Dict[str, Any]:
    """
    Main video pipeline for /analyze when type == 'video'.

    1) Extract frames and audio from video
    2) Analyze key frames with vision model
    3) Transcribe and analyze audio
    4) Fuse all results together
    """
    # Extract video components
    components = await extract_video_components(upload_file)

    if components.get("error"):
        return {
            "risk_level": "UNKNOWN",
            "overall_score": 0.0,
            "confidence": 0.0,
            "modality_scores": {"video": 0.0},
            "explanation": f"Failed to process video: {components.get('error')}",
            "indicators": ["video_processing_error"],
            "raw": {"error": components.get("error")},
        }

    frames = components.get("frames", [])
    audio_path = components.get("audio_path")
    duration = components.get("duration", 0)

    modality_results: Dict[str, Dict[str, Any]] = {}
    video_indicators: List[str] = []

    try:
        # Analyze frames with vision model
        if frames:
            frame_scores = []
            frame_indicators = []
            frame_confidences = []

            # Analyze up to 3 frames to save API costs
            for i, frame_bytes in enumerate(frames[:3]):
                try:
                    vision_result = analyze_image_bytes(frame_bytes)
                    frame_scores.append(float(vision_result.get("overall_score", 0)))
                    frame_indicators.extend(vision_result.get("indicators", []))
                    frame_confidences.append(float(vision_result.get("confidence", 0.5)))
                except Exception as e:
                    video_indicators.append(f"frame_{i}_analysis_failed")

            if frame_scores:
                avg_confidence = sum(frame_confidences) / len(frame_confidences)
                modality_results["image"] = {
                    "risk_level": "HIGH" if max(frame_scores) >= 7 else "MEDIUM" if max(frame_scores) >= 4 else "LOW",
                    "overall_score": max(frame_scores),  # Use highest risk frame
                    "confidence": avg_confidence,
                    "indicators": list(set(frame_indicators)),
                    "explanation": f"Analyzed {len(frame_scores)} video frame(s). Highest risk score: {max(frame_scores):.1f}",
                }

        # Analyze audio if present
        if audio_path and os.path.exists(audio_path):
            try:
                # Read audio file and transcribe
                with open(audio_path, "rb") as f:
                    audio_bytes = f.read()

                # Create a mock UploadFile for the audio service
                from io import BytesIO
                from fastapi import UploadFile as FastAPIUploadFile

                audio_buffer = BytesIO(audio_bytes)
                audio_file = FastAPIUploadFile(
                    file=audio_buffer,
                    filename="extracted_audio.mp3",
                )

                # Transcribe audio
                from fraudshield.services.audio_service import transcribe_audio_file
                transcript = await transcribe_audio_file(audio_file)

                if transcript and transcript.strip():
                    # Analyze the transcript
                    text_result = analyze_text_with_llm(transcript)
                    # Label it as audio modality
                    modality_results["audio"] = {
                        "risk_level": text_result["risk_level"],
                        "overall_score": text_result["overall_score"],
                        "confidence": text_result.get("confidence", 0.5),
                        "indicators": text_result.get("indicators", []),
                        "explanation": f"Audio transcript: {transcript[:200]}..." if len(transcript) > 200 else f"Audio transcript: {transcript}",
                    }

            except Exception as e:
                video_indicators.append("audio_analysis_failed")

    finally:
        # Clean up temp audio file
        cleanup_audio_file(audio_path)

    # If no modalities were analyzed
    if not modality_results:
        return {
            "risk_level": "LOW",
            "overall_score": 0.0,
            "confidence": 0.3,
            "modality_scores": {"video": 0.0},
            "explanation": f"Video processed ({duration:.1f}s) but no analyzable content found.",
            "indicators": video_indicators or ["no_analyzable_content"],
            "raw": {"duration": duration, "frames_extracted": len(frames), "has_audio": audio_path is not None},
        }

    # Fuse results
    fused = fuse_modalities(modality_results)

    # Add video-specific indicators
    all_indicators = fused.get("indicators", []) + [f"video:{ind}" for ind in video_indicators]

    # Build explanation
    explanation = (
        f"Video Analysis:\n"
        f"Duration: {duration:.1f} seconds\n"
        f"Frames analyzed: {min(len(frames), 3)}\n"
        f"Audio: {'Yes' if 'audio' in modality_results else 'No/Failed'}\n\n"
        f"{fused.get('explanation', '')}"
    )

    return {
        "risk_level": fused["risk_level"],
        "overall_score": fused["overall_score"],
        "confidence": fused.get("confidence", 0.5),
        "modality_scores": {"video": fused["overall_score"], **fused.get("modality_scores", {})},
        "explanation": explanation,
        "indicators": all_indicators,
        "raw": {
            "duration": duration,
            "frames_analyzed": min(len(frames), 3),
            "has_audio": "audio" in modality_results,
            "modality_results": {k: {kk: vv for kk, vv in v.items() if kk != "raw"} for k, v in modality_results.items()},
        },
    }
