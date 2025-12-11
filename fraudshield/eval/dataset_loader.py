# fraudshield/eval/dataset_loader.py
"""
Dataset loader for FraudShield evaluation.

Supports loading phishing and benign samples from JSONL files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Iterable, Any, Optional


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    """
    Load a JSONL file into a list of dicts.
    Skips blank lines gracefully.
    """
    records: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def _load_with_fallback(dataset_dir: Path, primary: str, fallback: Optional[str] = None) -> List[Dict[str, Any]]:
    """Load from primary path, optionally falling back to another file."""
    path = dataset_dir / primary
    if path.exists():
        return load_jsonl(path)
    if fallback:
        fallback_path = dataset_dir / fallback
        if fallback_path.exists():
            return load_jsonl(fallback_path)
    return []


def _find_file(dataset_dir: Path, patterns: List[str]) -> Optional[Path]:
    """Find first existing file matching any pattern."""
    for pattern in patterns:
        path = dataset_dir / pattern
        if path.exists():
            return path
    return None


def load_url_samples(dataset_dir: Path, include_benign: bool = True) -> List[Dict[str, Any]]:
    """
    Load URL samples (phishing and optionally benign).

    Supports multiple filename patterns for flexibility.
    """
    samples = []
    
    # Load phishing URLs (try multiple patterns)
    phishing_path = _find_file(dataset_dir, ["urls_500.jsonl", "urls_20.jsonl", "urls.jsonl"])
    if phishing_path:
        samples.extend(load_jsonl(phishing_path))
    
    # Load benign URLs
    if include_benign:
        benign_path = dataset_dir / "urls_benign.jsonl"
        if benign_path.exists():
            samples.extend(load_jsonl(benign_path))
    
    if not samples:
        raise FileNotFoundError(f"No URL dataset found in {dataset_dir}")
    
    return samples


def load_sms_samples(dataset_dir: Path, include_benign: bool = True) -> List[Dict[str, Any]]:
    """
    Load SMS samples (phishing and optionally benign).

    Supports multiple filename patterns for flexibility.
    """
    samples = []
    
    # Load phishing SMS (try multiple patterns)
    phishing_path = _find_file(dataset_dir, ["sms_250.jsonl", "sms_20.jsonl", "sms.jsonl"])
    if phishing_path:
        samples.extend(load_jsonl(phishing_path))
    
    # Load benign SMS
    if include_benign:
        benign_path = dataset_dir / "sms_benign.jsonl"
        if benign_path.exists():
            samples.extend(load_jsonl(benign_path))
    
    if not samples:
        raise FileNotFoundError(f"No SMS dataset found in {dataset_dir}")
    
    return samples


def load_email_samples(dataset_dir: Path, include_benign: bool = True) -> List[Dict[str, Any]]:
    """
    Load email samples (phishing and optionally benign).

    Supports multiple filename patterns for flexibility.
    """
    samples = []
    
    # Load phishing emails (try multiple patterns)
    phishing_path = _find_file(dataset_dir, ["emails_150.jsonl", "emails_20.jsonl", "emails.jsonl"])
    if phishing_path:
        samples.extend(load_jsonl(phishing_path))
    
    # Load benign emails
    if include_benign:
        benign_path = dataset_dir / "emails_benign.jsonl"
        if benign_path.exists():
            samples.extend(load_jsonl(benign_path))
    
    if not samples:
        raise FileNotFoundError(f"No email dataset found in {dataset_dir}")
    
    return samples


def iter_all_samples(
    dataset_dir: Path,
    include_benign: bool = True,
    modalities: Optional[List[str]] = None,
) -> Iterable[Dict[str, Any]]:
    """
    Convenience generator that yields a unified view of all text/url samples.

    Args:
        dataset_dir: Path to dataset directory
        include_benign: Whether to include benign samples
        modalities: List of modalities to include ('url', 'sms', 'email'). None = all.

    Yields dicts of the form:
      {
        "id": ...,
        "modality": "url" | "sms" | "email",
        "content": str,
        "label": str,
        "raw": original_record_dict,
      }
    """
    if modalities is None:
        modalities = ["url", "sms", "email"]
    
    # URLs
    if "url" in modalities:
        try:
            for rec in load_url_samples(dataset_dir, include_benign):
                yield {
                    "id": f"url_{rec.get('id')}",
                    "modality": "url",
                    "content": rec.get("url", ""),
                    "label": rec.get("label", "unknown"),
                    "raw": rec,
                }
        except FileNotFoundError:
            pass

    # SMS
    if "sms" in modalities:
        try:
            for rec in load_sms_samples(dataset_dir, include_benign):
                yield {
                    "id": f"sms_{rec.get('id')}",
                    "modality": "sms",
                    "content": rec.get("text", ""),
                    "label": rec.get("label", "unknown"),
                    "raw": rec,
                }
        except FileNotFoundError:
            pass

    # Emails (treat subject + body as text)
    if "email" in modalities:
        try:
            for rec in load_email_samples(dataset_dir, include_benign):
                subj = rec.get("subject", "")
                body = rec.get("body", "")
                content = (subj + "\n\n" + body).strip()
                yield {
                    "id": f"email_{rec.get('id')}",
                    "modality": "email",
                    "content": content,
                    "label": rec.get("label", "unknown"),
                    "raw": rec,
                }
        except FileNotFoundError:
            pass


def get_dataset_stats(dataset_dir: Path, include_benign: bool = True) -> Dict[str, Any]:
    """Get statistics about the dataset."""
    stats = {
        "total": 0,
        "by_modality": {},
        "by_label": {},
    }
    
    for sample in iter_all_samples(dataset_dir, include_benign):
        stats["total"] += 1
        
        modality = sample["modality"]
        label = sample["label"]
        
        if modality not in stats["by_modality"]:
            stats["by_modality"][modality] = 0
        stats["by_modality"][modality] += 1
        
        if label not in stats["by_label"]:
            stats["by_label"][label] = 0
        stats["by_label"][label] += 1
    
    return stats
