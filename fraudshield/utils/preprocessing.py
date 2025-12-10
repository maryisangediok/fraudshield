import re


def normalize_text(text: str) -> str:
    text = text or ""
    text = text.strip()
    text = re.sub(r"\s+", " ", text)
    return text


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    return url
