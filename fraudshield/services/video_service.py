"""
Video processing service.
Extracts frames and audio from video files for analysis.
"""

import logging
import tempfile
import os
from typing import Dict, Any, List, Tuple
from io import BytesIO

from fastapi import UploadFile

logger = logging.getLogger(__name__)


async def extract_video_components(upload_file: UploadFile) -> Dict[str, Any]:
    """
    Extract frames and audio from a video file.

    Returns:
        {
            "frames": [bytes, ...],  # Key frame images as bytes
            "audio_path": str | None,  # Path to extracted audio file
            "duration": float,
            "fps": float,
            "error": str | None,
        }
    """
    try:
        from moviepy.editor import VideoFileClip
        from PIL import Image
    except ImportError as e:
        logger.error(f"Required library not installed: {e}")
        return {
            "frames": [],
            "audio_path": None,
            "duration": 0,
            "fps": 0,
            "error": f"Required library not installed: {e}",
        }

    # Save uploaded file to temp location
    data = await upload_file.read()
    temp_video = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
    temp_video.write(data)
    temp_video.close()

    try:
        clip = VideoFileClip(temp_video.name)

        duration = clip.duration
        fps = clip.fps

        # Extract key frames (1 per 5 seconds, max 10 frames)
        frames = []
        frame_interval = max(5, duration / 10)  # At least 5 seconds apart
        frame_times = []
        t = 0
        while t < duration and len(frame_times) < 10:
            frame_times.append(t)
            t += frame_interval

        for t in frame_times:
            try:
                frame = clip.get_frame(t)
                # Convert numpy array to PIL Image then to bytes
                img = Image.fromarray(frame)
                img_buffer = BytesIO()
                img.save(img_buffer, format="PNG")
                frames.append(img_buffer.getvalue())
            except Exception as e:
                logger.warning(f"Failed to extract frame at {t}s: {e}")

        # Extract audio if present
        audio_path = None
        if clip.audio is not None:
            temp_audio = tempfile.NamedTemporaryFile(delete=False, suffix=".mp3")
            temp_audio.close()
            try:
                clip.audio.write_audiofile(temp_audio.name, logger=None)
                audio_path = temp_audio.name
            except Exception as e:
                logger.warning(f"Failed to extract audio: {e}")
                if os.path.exists(temp_audio.name):
                    os.unlink(temp_audio.name)

        clip.close()

        return {
            "frames": frames,
            "audio_path": audio_path,
            "duration": duration,
            "fps": fps,
            "error": None,
        }

    except Exception as e:
        logger.error(f"Error processing video: {e}")
        return {
            "frames": [],
            "audio_path": None,
            "duration": 0,
            "fps": 0,
            "error": str(e),
        }
    finally:
        # Clean up temp video file
        if os.path.exists(temp_video.name):
            os.unlink(temp_video.name)


def cleanup_audio_file(audio_path: str):
    """Clean up temporary audio file."""
    if audio_path and os.path.exists(audio_path):
        try:
            os.unlink(audio_path)
        except Exception as e:
            logger.warning(f"Failed to cleanup audio file: {e}")


class VideoAnalysisService:
    """Legacy placeholder - use video pipeline instead."""

    @staticmethod
    async def analyze(file) -> Tuple[float, List[str]]:
        """Placeholder video analysis: returns neutral-medium risk."""
        indicators = ["video_not_yet_analyzed_ml"]
        score = 0.5
        return score, indicators
