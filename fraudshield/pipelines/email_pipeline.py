"""
Email analysis pipeline.
Parses .eml files and analyzes text content + URLs for fraud.
"""

from typing import Dict, Any, List

from fastapi import UploadFile

from fraudshield.services.email_service import parse_email_file, get_email_analysis_text
from fraudshield.pipelines.text_pipeline import analyze_text_with_llm
from fraudshield.pipelines.url_pipeline import analyze_url_with_llm
from fraudshield.pipelines.fusion_engine import fuse_modalities


async def analyze_email_with_llm(upload_file: UploadFile) -> Dict[str, Any]:
    """
    Main email pipeline for /analyze when type == 'email'.

    1) Parse the .eml file
    2) Analyze the text content
    3) Analyze any URLs found
    4) Fuse results together
    """
    # Parse the email
    parsed = await parse_email_file(upload_file)

    modality_results: Dict[str, Dict[str, Any]] = {}
    email_indicators: List[str] = []

    # Analyze combined text content
    analysis_text = get_email_analysis_text(parsed)
    if analysis_text.strip():
        text_result = analyze_text_with_llm(analysis_text)
        modality_results["text"] = text_result

    # Analyze each URL found
    urls = parsed.get("urls", [])
    if urls:
        # Analyze up to 5 URLs to avoid excessive API calls
        url_scores = []
        url_indicators = []
        for url in urls[:5]:
            url_result = analyze_url_with_llm(url)
            url_scores.append(url_result.get("overall_score", 0))
            url_indicators.extend(url_result.get("indicators", []))

        # Aggregate URL results
        if url_scores:
            modality_results["url"] = {
                "risk_level": "HIGH" if max(url_scores) >= 7 else "MEDIUM" if max(url_scores) >= 4 else "LOW",
                "overall_score": max(url_scores),  # Use highest risk URL
                "confidence": 0.7,
                "indicators": list(set(url_indicators)),
                "explanation": f"Analyzed {len(url_scores)} URL(s) from email. Highest risk score: {max(url_scores):.1f}",
            }

    # Check for suspicious email indicators
    from_addr = parsed.get("from", "").lower()
    subject = parsed.get("subject", "").lower()

    # Check for spoofed/suspicious sender patterns
    if "@" in from_addr:
        domain = from_addr.split("@")[-1].rstrip(">")
        suspicious_tlds = [".xyz", ".tk", ".top", ".click", ".link"]
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            email_indicators.append("suspicious_sender_tld")

    # Check for urgent subject lines
    urgent_words = ["urgent", "immediate", "action required", "verify", "suspended", "locked"]
    if any(word in subject for word in urgent_words):
        email_indicators.append("urgent_subject_line")

    # Check for attachments (potential malware vectors)
    attachments = parsed.get("attachments", [])
    if attachments:
        email_indicators.append(f"has_{len(attachments)}_attachments")
        risky_extensions = [".exe", ".zip", ".rar", ".js", ".vbs", ".bat", ".cmd", ".scr"]
        for att in attachments:
            filename = att.get("filename", "").lower()
            if any(filename.endswith(ext) for ext in risky_extensions):
                email_indicators.append(f"risky_attachment:{filename}")

    # If no modalities were analyzed, return basic result
    if not modality_results:
        return {
            "risk_level": "LOW",
            "overall_score": 0.0,
            "confidence": 0.3,
            "modality_scores": {"email": 0.0},
            "explanation": "Email parsed but no analyzable content found.",
            "indicators": email_indicators or ["empty_email"],
            "raw": {"parsed_email": parsed},
        }

    # Fuse modality results
    fused = fuse_modalities(modality_results)

    # Add email-specific indicators
    all_indicators = fused.get("indicators", []) + [f"email:{ind}" for ind in email_indicators]

    # Build comprehensive explanation
    explanation = (
        f"Email Analysis:\n"
        f"From: {parsed.get('from', 'Unknown')}\n"
        f"Subject: {parsed.get('subject', 'No subject')}\n"
        f"URLs found: {len(urls)}\n"
        f"Attachments: {len(attachments)}\n\n"
        f"{fused.get('explanation', '')}"
    )

    return {
        "risk_level": fused["risk_level"],
        "overall_score": fused["overall_score"],
        "confidence": fused.get("confidence", 0.5),
        "modality_scores": {"email": fused["overall_score"], **fused.get("modality_scores", {})},
        "explanation": explanation,
        "indicators": all_indicators,
        "raw": {
            "parsed_email": {
                "subject": parsed.get("subject"),
                "from": parsed.get("from"),
                "to": parsed.get("to"),
                "urls_count": len(urls),
                "attachments_count": len(attachments),
            },
            "modality_results": modality_results,
        },
    }


