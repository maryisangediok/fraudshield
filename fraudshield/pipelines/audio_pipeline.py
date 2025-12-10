from fraudshield.services.audio_service import AudioAnalysisService


async def run_audio_pipeline(file):
    return await AudioAnalysisService.analyze(file)
