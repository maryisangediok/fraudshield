import json
import logging
from typing import Dict, Any

from openai import OpenAI, OpenAIError
from fraudshield.config import settings

logger = logging.getLogger(__name__)


class LLMClient:
    """
    Wrapper around the OpenAI client for fraud risk scoring.
    """

    def __init__(self, model: str | None = None):
        self.client = OpenAI(api_key=settings.openai_api_key)
        self.model = model or settings.openai_model

    def score_text(self, text: str) -> Dict[str, Any]:
        system_msg = (
            "You are a fraud risk classifier for AI-enabled scams. "
            "Return ONLY valid JSON (no markdown). Schema:\n"
            "{\n"
            '  "risk_level": "LOW" | "MEDIUM" | "HIGH",\n'
            '  "overall_score": float (0-10),\n'
            '  "confidence": float (0-1, how confident you are in this assessment),\n'
            '  "indicators": [string, ...],\n'
            '  "explanation": string\n'
            "}\n"
            "Set confidence lower if the text is ambiguous or lacks clear signals."
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system_msg},
                    {
                        "role": "user",
                        "content": f"Classify this message:\n\n{text}"
                    },
                ],
            )

            content = response.choices[0].message.content
            return json.loads(content)

        except OpenAIError as e:
            logger.warning(f"OpenAI API error, falling back to neutral score: {e}")
            return {
                "risk_level": "LOW",
                "overall_score": 0.0,
                "confidence": 0.0,
                "indicators": ["llm_unavailable"],
                "explanation": "LLM scoring unavailable; using heuristics only.",
            }

    def score_url(self, url: str) -> Dict[str, Any]:
        """
        LLM-based scoring for URLs only (no page fetch).
        The model must judge based on the URL structure, domain, and path.
        """
        system_msg = (
            "You are a fraud/phishing URL risk classifier. "
            "You do NOT have network access; you must judge only from the URL string. "
            "Look for signs of phishing, impersonation, suspicious domains, shorteners, "
            "and high-risk patterns. "
            "Return ONLY valid JSON (no markdown). Schema:\n"
            "{\n"
            '  "risk_level": "LOW" | "MEDIUM" | "HIGH",\n'
            '  "overall_score": float (0-10),\n'
            '  "confidence": float (0-1, how confident you are in this assessment),\n'
            '  "indicators": [string, ...],\n'
            '  "explanation": string\n'
            "}\n"
            "Set confidence lower if the URL is ambiguous or could be legitimate."
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system_msg},
                    {
                        "role": "user",
                        "content": f"Classify the fraud risk of this URL:\n\n{url}",
                    },
                ],
            )

            content = response.choices[0].message.content
            return json.loads(content)

        except OpenAIError as e:
            logger.warning(f"OpenAI API error, falling back to neutral score: {e}")
            return {
                "risk_level": "LOW",
                "overall_score": 0.0,
                "confidence": 0.0,
                "indicators": ["llm_unavailable"],
                "explanation": "LLM scoring unavailable; using heuristics only.",
            }
