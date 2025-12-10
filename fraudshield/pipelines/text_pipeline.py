from fraudshield.services.text_service import TextAnalysisService


def run_text_pipeline(text: str):
    return TextAnalysisService.analyze(text)
