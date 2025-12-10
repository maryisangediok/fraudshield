from fraudshield.services.link_service import LinkAnalysisService


def run_url_pipeline(url: str):
    return LinkAnalysisService.analyze(url)
