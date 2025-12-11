from io import BytesIO

from fastapi import UploadFile
from openai import OpenAI

from fraudshield.config import settings


client = OpenAI(api_key=settings.openai_api_key)


async def transcribe_audio_file(upload_file: UploadFile) -> str:
    """
    Transcribe an uploaded audio file to text using OpenAI's audio API.
    Returns the transcript as plain text.
    """
    # Read file bytes from the uploaded file
    data = await upload_file.read()

    # Wrap in a file-like object for the OpenAI client
    audio_file = BytesIO(data)
    audio_file.name = upload_file.filename or "audio.wav"

    # Use transcription model from config
    response = client.audio.transcriptions.create(
        model=settings.openai_transcription_model,
        file=audio_file,
        response_format="text",
    )

    # response is just the transcript text in this mode
    return response


class AudioAnalysisService:
    """Legacy placeholder - use transcribe_audio_file + text pipeline instead."""

    @staticmethod
    async def analyze(file):
        """Placeholder audio analysis: returns neutral-medium risk."""
        indicators = ["audio_not_yet_analyzed_ml"]
        score = 0.5
        return score, indicators
