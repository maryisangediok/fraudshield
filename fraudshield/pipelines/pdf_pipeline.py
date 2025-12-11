"""
PDF analysis pipeline.
Parses PDF files and analyzes text content + URLs for fraud.
"""

from typing import Dict, Any, List

from fastapi import UploadFile

from fraudshield.services.pdf_service import parse_pdf_file
from fraudshield.pipelines.text_pipeline import analyze_text_with_llm
from fraudshield.pipelines.url_pipeline import analyze_url_with_llm
from fraudshield.pipelines.fusion_engine import fuse_modalities


async def analyze_pdf_with_llm(upload_file: UploadFile) -> Dict[str, Any]:
    """
    Main PDF pipeline for /analyze when type == 'pdf' or 'document'.

    1) Parse the PDF file
    2) Analyze the text content
    3) Analyze any URLs found
    4) Fuse results together
    """
    # Parse the PDF
    parsed = await parse_pdf_file(upload_file)

    # Check for parsing errors
    if parsed.get("error"):
        return {
            "risk_level": "UNKNOWN",
            "overall_score": 0.0,
            "confidence": 0.0,
            "modality_scores": {"pdf": 0.0},
            "explanation": f"Failed to parse PDF: {parsed.get('error')}",
            "indicators": ["pdf_parse_error"],
            "raw": {"error": parsed.get("error")},
        }

    modality_results: Dict[str, Dict[str, Any]] = {}
    pdf_indicators: List[str] = []

    text = parsed.get("text", "").strip()
    urls = parsed.get("urls", [])
    pages = parsed.get("pages", 0)
    metadata = parsed.get("metadata", {})

    # Analyze text content
    if text:
        # Limit text length to avoid excessive API costs
        analysis_text = text[:10000] if len(text) > 10000 else text
        text_result = analyze_text_with_llm(analysis_text)
        modality_results["text"] = text_result

    # Analyze URLs found in PDF
    if urls:
        url_scores = []
        url_indicators = []
        for url in urls[:5]:  # Limit to 5 URLs
            url_result = analyze_url_with_llm(url)
            url_scores.append(url_result.get("overall_score", 0))
            url_indicators.extend(url_result.get("indicators", []))

        if url_scores:
            modality_results["url"] = {
                "risk_level": "HIGH" if max(url_scores) >= 7 else "MEDIUM" if max(url_scores) >= 4 else "LOW",
                "overall_score": max(url_scores),
                "confidence": 0.7,
                "indicators": list(set(url_indicators)),
                "explanation": f"Analyzed {len(url_scores)} URL(s) from PDF. Highest risk score: {max(url_scores):.1f}",
            }

    # PDF-specific indicators
    if pages == 1:
        pdf_indicators.append("single_page_document")

    # Check for suspicious keywords in text
    text_lower = text.lower()
    suspicious_phrases = [
        "wire transfer", "gift card", "bitcoin", "cryptocurrency",
        "act now", "limited time", "verify your", "update your payment",
        "account suspended", "unusual activity",
    ]
    for phrase in suspicious_phrases:
        if phrase in text_lower:
            pdf_indicators.append(f"suspicious_phrase:{phrase.replace(' ', '_')}")

    # Check metadata for suspicious signs
    creator = metadata.get("creator", "").lower()
    if "invoice" in creator or "receipt" in creator:
        pdf_indicators.append("invoice_document")

    # If no content to analyze
    if not modality_results:
        return {
            "risk_level": "LOW",
            "overall_score": 0.0,
            "confidence": 0.3,
            "modality_scores": {"pdf": 0.0},
            "explanation": f"PDF parsed ({pages} pages) but no analyzable text content found.",
            "indicators": pdf_indicators or ["empty_pdf"],
            "raw": {"parsed_pdf": {"pages": pages, "urls_count": len(urls)}},
        }

    # Fuse results
    fused = fuse_modalities(modality_results)

    # Add PDF-specific indicators
    all_indicators = fused.get("indicators", []) + [f"pdf:{ind}" for ind in pdf_indicators]

    # Build explanation
    explanation = (
        f"PDF Analysis:\n"
        f"Pages: {pages}\n"
        f"Text length: {len(text)} characters\n"
        f"URLs found: {len(urls)}\n\n"
        f"{fused.get('explanation', '')}"
    )

    return {
        "risk_level": fused["risk_level"],
        "overall_score": fused["overall_score"],
        "confidence": fused.get("confidence", 0.5),
        "modality_scores": {"pdf": fused["overall_score"], **fused.get("modality_scores", {})},
        "explanation": explanation,
        "indicators": all_indicators,
        "raw": {
            "parsed_pdf": {
                "pages": pages,
                "text_length": len(text),
                "urls_count": len(urls),
                "metadata": metadata,
            },
            "modality_results": modality_results,
        },
    }


