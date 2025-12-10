from fraudshield.utils.preprocessing import normalize_text


class TextAnalysisService:
    @staticmethod
    def analyze(text: str):
        """Naive heuristic placeholder for text fraud analysis."""
        text = normalize_text(text)
        indicators = []
        score = 0.1

        red_flags = ["gift card", "urgent", "wire", "transfer", "verify your account", "password", "bank", "otp"]
        lower = text.lower()
        matches = [w for w in red_flags if w in lower]

        if matches:
            indicators.append("suspicious_keywords")
            score = 0.7 + 0.05 * min(len(matches), 3)

        if any(word in lower for word in ["now", "immediately", "right away"]):
            indicators.append("urgency_language")
            score = max(score, 0.8)

        if "bitcoin" in lower or "crypto" in lower:
            indicators.append("crypto_reference")
            score = max(score, 0.75)

        if not indicators:
            indicators.append("no_obvious_text_red_flags")

        score = min(score, 0.99)
        return score, indicators
