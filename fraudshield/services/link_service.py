from urllib.parse import urlparse
from fraudshield.utils.preprocessing import normalize_url


SUSPICIOUS_TLDS = {".xyz", ".ru", ".top", ".click", ".info"}


class LinkAnalysisService:
    @staticmethod
    def analyze(url: str):
        """Simple URL heuristic analysis placeholder."""
        url = normalize_url(url)
        indicators = []
        score = 0.1

        parsed = urlparse(url if (url.startswith("http://") or url.startswith("https://")) else "http://" + url)

        host = parsed.netloc.lower()
        path = parsed.path.lower()

        if any(tld for tld in SUSPICIOUS_TLDS if host.endswith(tld)):
            indicators.append("suspicious_tld")
            score = 0.7

        if len(path) > 40:
            indicators.append("long_path")
            score = max(score, 0.6)

        if any(x in host for x in ["login", "secure", "verify", "update"]):
            indicators.append("impersonation_like_host")
            score = max(score, 0.75)

        if not indicators:
            indicators.append("no_obvious_url_red_flags")

        score = min(score, 0.98)
        return score, indicators
