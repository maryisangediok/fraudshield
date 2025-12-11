"""
Email (.eml) parsing service.
Extracts text, URLs, and attachments from email files.
"""

import email
import re
from email import policy
from email.parser import BytesParser
from typing import Dict, Any, List, Tuple
from io import BytesIO

from fastapi import UploadFile


# URL regex pattern
URL_PATTERN = re.compile(
    r'https?://[^\s<>"{}|\\^`\[\]]+'
)


def extract_urls_from_text(text: str) -> List[str]:
    """Extract all URLs from text."""
    return list(set(URL_PATTERN.findall(text)))


def parse_email_bytes(email_bytes: bytes) -> Dict[str, Any]:
    """
    Parse an email from bytes and extract relevant content.

    Returns:
        {
            "subject": str,
            "from": str,
            "to": str,
            "date": str,
            "body_text": str,
            "body_html": str,
            "urls": [str, ...],
            "attachments": [{"filename": str, "content_type": str, "size": int}, ...],
            "headers": {str: str, ...},
        }
    """
    msg = BytesParser(policy=policy.default).parsebytes(email_bytes)

    # Extract headers
    subject = msg.get("Subject", "")
    from_addr = msg.get("From", "")
    to_addr = msg.get("To", "")
    date = msg.get("Date", "")

    headers = {
        "subject": subject,
        "from": from_addr,
        "to": to_addr,
        "date": date,
        "reply-to": msg.get("Reply-To", ""),
        "return-path": msg.get("Return-Path", ""),
    }

    # Extract body
    body_text = ""
    body_html = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            # Check if it's an attachment
            if "attachment" in content_disposition:
                filename = part.get_filename() or "unknown"
                payload = part.get_payload(decode=True)
                attachments.append({
                    "filename": filename,
                    "content_type": content_type,
                    "size": len(payload) if payload else 0,
                })
            elif content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    body_text += payload.decode("utf-8", errors="ignore")
            elif content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    body_html += payload.decode("utf-8", errors="ignore")
    else:
        # Single part email
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            if content_type == "text/html":
                body_html = payload.decode("utf-8", errors="ignore")
            else:
                body_text = payload.decode("utf-8", errors="ignore")

    # Extract URLs from both text and HTML bodies
    all_text = body_text + " " + body_html
    urls = extract_urls_from_text(all_text)

    # Also check for URLs in headers (sometimes phishing links are there)
    header_urls = extract_urls_from_text(str(headers))
    urls.extend(header_urls)
    urls = list(set(urls))  # Deduplicate

    return {
        "subject": subject,
        "from": from_addr,
        "to": to_addr,
        "date": date,
        "body_text": body_text,
        "body_html": body_html,
        "urls": urls,
        "attachments": attachments,
        "headers": headers,
    }


async def parse_email_file(upload_file: UploadFile) -> Dict[str, Any]:
    """Parse an uploaded .eml file."""
    data = await upload_file.read()
    return parse_email_bytes(data)


def get_email_analysis_text(parsed_email: Dict[str, Any]) -> str:
    """
    Combine email components into a single text for analysis.
    """
    parts = []

    if parsed_email.get("subject"):
        parts.append(f"Subject: {parsed_email['subject']}")

    if parsed_email.get("from"):
        parts.append(f"From: {parsed_email['from']}")

    if parsed_email.get("body_text"):
        parts.append(f"Body:\n{parsed_email['body_text']}")

    if parsed_email.get("urls"):
        parts.append(f"URLs found: {', '.join(parsed_email['urls'])}")

    if parsed_email.get("attachments"):
        attachment_names = [a["filename"] for a in parsed_email["attachments"]]
        parts.append(f"Attachments: {', '.join(attachment_names)}")

    return "\n\n".join(parts)


