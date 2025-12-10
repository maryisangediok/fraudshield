from typing import Dict, List, Optional, Tuple
from fraudshield.services.risk_service import RiskService
from fraudshield.services.text_service import TextAnalysisService
from fraudshield.services.link_service import LinkAnalysisService
from fraudshield.services.audio_service import AudioAnalysisService
from fraudshield.services.video_service import VideoAnalysisService


class MultimodalPipeline:
    """Orchestrator for multimodal analysis without HTTP."""

    @staticmethod
    async def analyze(
        type: str,
        text: Optional[str] = None,
        url: Optional[str] = None,
        file=None,
    ) -> Tuple[str, float, Dict[str, float], str, List[str]]:
        modality_scores: Dict[str, float] = {}
        indicators: List[str] = []

        t = type.lower()

        if t == "text" and text:
            score, mods = TextAnalysisService.analyze(text)
            modality_scores["text"] = score
            indicators.extend(mods)

        if t in ("link", "url") and url:
            score, mods = LinkAnalysisService.analyze(url)
            modality_scores["url"] = score
            indicators.extend(mods)

        if t == "audio" and file is not None:
            score, mods = await AudioAnalysisService.analyze(file)
            modality_scores["audio"] = score
            indicators.extend(mods)

        if t == "video" and file is not None:
            score, mods = await VideoAnalysisService.analyze(file)
            modality_scores["video"] = score
            indicators.extend(mods)

        risk_level, overall_score, explanation = RiskService.compute(modality_scores, indicators)
        return risk_level, overall_score, modality_scores, explanation, indicators
