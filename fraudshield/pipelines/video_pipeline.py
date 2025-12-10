from fraudshield.services.video_service import VideoAnalysisService


async def run_video_pipeline(file):
    return await VideoAnalysisService.analyze(file)
