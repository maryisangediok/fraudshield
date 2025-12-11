"""
PDF parsing service.
Extracts text and metadata from PDF files.
"""

import logging
from typing import Dict, Any, List
from io import BytesIO

from fastapi import UploadFile

logger = logging.getLogger(__name__)


def extract_text_from_pdf(pdf_bytes: bytes) -> Dict[str, Any]:
    """
    Extract text and metadata from a PDF file.

    Returns:
        {
            "text": str,
            "pages": int,
            "metadata": dict,
            "urls": [str, ...],
        }
    """
    try:
        from pypdf import PdfReader
    except ImportError:
        logger.error("pypdf not installed. Run: pip install pypdf")
        return {
            "text": "",
            "pages": 0,
            "metadata": {},
            "urls": [],
            "error": "pypdf not installed",
        }

    try:
        reader = PdfReader(BytesIO(pdf_bytes))

        # Extract metadata
        metadata = {}
        if reader.metadata:
            metadata = {
                "title": reader.metadata.get("/Title", ""),
                "author": reader.metadata.get("/Author", ""),
                "creator": reader.metadata.get("/Creator", ""),
                "producer": reader.metadata.get("/Producer", ""),
            }

        # Extract text from all pages
        text_parts = []
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text_parts.append(page_text)

        full_text = "\n\n".join(text_parts)

        # Extract URLs from text
        import re
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        urls = list(set(url_pattern.findall(full_text)))

        # Also try to extract URLs from annotations/links
        for page in reader.pages:
            if "/Annots" in page:
                annotations = page["/Annots"]
                if annotations:
                    for annot in annotations:
                        annot_obj = annot.get_object()
                        if annot_obj.get("/Subtype") == "/Link":
                            action = annot_obj.get("/A")
                            if action and action.get("/URI"):
                                urls.append(str(action["/URI"]))

        urls = list(set(urls))  # Deduplicate

        return {
            "text": full_text,
            "pages": len(reader.pages),
            "metadata": metadata,
            "urls": urls,
        }

    except Exception as e:
        logger.error(f"Error parsing PDF: {e}")
        return {
            "text": "",
            "pages": 0,
            "metadata": {},
            "urls": [],
            "error": str(e),
        }


async def parse_pdf_file(upload_file: UploadFile) -> Dict[str, Any]:
    """Parse an uploaded PDF file."""
    data = await upload_file.read()
    return extract_text_from_pdf(data)


