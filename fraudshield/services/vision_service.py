import base64
import json
import logging
from typing import Dict, Any

from openai import OpenAI, OpenAIError

from fraudshield.config import settings


logger = logging.getLogger(__name__)
client = OpenAI(api_key=settings.openai_api_key)


def analyze_image_bytes(image_bytes: bytes) -> Dict[str, Any]:
    """
    Call the OpenAI vision model on a screenshot / image and return a structured
    fraud-risk assessment as JSON.
    """

    # Base64-encode the image for the API
    b64_image = base64.b64encode(image_bytes).decode("utf-8")

    system_msg = (
        "You are a security and fraud analysis engine. "
        "You look at screenshots of emails, login pages, OTP prompts, invoices, "
        "chat conversations, and websites, and decide if they are likely part of "
        "a fraud, scam, phishing, or social-engineering attempt.\n\n"
        "You must return ONLY valid JSON (no markdown). Schema:\n"
        "{\n"
        '  "risk_level": "LOW" | "MEDIUM" | "HIGH",\n'
        '  "overall_score": float (0-10),\n'
        '  "confidence": float (0-1, how confident you are in this assessment),\n'
        '  "indicators": [string, ...],\n'
        '  "explanation": string\n'
        "}\n"
        "overall_score should be between 0 and 10, where 0 is no risk and 10 is extreme risk.\n"
        "Set confidence lower if the image is unclear, ambiguous, or lacks obvious fraud signals."
    )

    user_content = [
        {
            "type": "text",
            "text": (
                "Analyze this image for fraud / phishing / scam risk. "
                "This may be a screenshot of an email, login page, payment page, OTP request, "
                "invoice, or chat. Focus on:\n"
                "- Brand impersonation\n"
                "- Fake login / account verification\n"
                "- Requests for credentials / OTP / payment\n"
                "- Urgency and pressure\n"
                "- Suspicious URLs or layout\n"
            ),
        },
        {
            "type": "image_url",
            "image_url": {
                "url": f"data:image/png;base64,{b64_image}",
                "detail": "high",
            },
        },
    ]

    try:
        response = client.chat.completions.create(
            model=settings.openai_vision_model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_content},
            ],
            max_tokens=settings.openai_max_tokens,
        )

        content = response.choices[0].message.content
        return json.loads(content)

    except OpenAIError as e:
        logger.warning(f"OpenAI Vision API error: {e}")
        raise

