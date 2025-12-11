# fraudshield/eval/adversarial.py
"""
Adversarial sample generation for FraudShield testing.

Generates evasion attempts to stress-test the detection system:
- URL obfuscation techniques
- Text manipulation (homoglyphs, spacing, encoding)
- Social engineering variations
"""

from __future__ import annotations

import json
import os
import random
import re
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, quote

from openai import OpenAI


# Homoglyph mappings (characters that look similar)
HOMOGLYPHS = {
    'a': ['а', 'ą', 'ä', 'à', 'á', 'ạ'],  # Cyrillic а, etc.
    'e': ['е', 'ę', 'ë', 'è', 'é', 'ẹ'],
    'i': ['і', 'ì', 'í', 'ï', 'ị'],
    'o': ['о', 'ö', 'ò', 'ó', 'ọ', '0'],
    'u': ['ù', 'ú', 'ü', 'ụ'],
    'c': ['с', 'ç'],  # Cyrillic с
    'p': ['р'],  # Cyrillic р
    's': ['ѕ', '$'],
    'y': ['у'],  # Cyrillic у
    'l': ['1', '|', 'ⅼ'],
    'g': ['ɡ'],
}

# Zero-width characters for insertion
ZERO_WIDTH = [
    '\u200b',  # Zero-width space
    '\u200c',  # Zero-width non-joiner
    '\u200d',  # Zero-width joiner
    '\ufeff',  # Zero-width no-break space
]


@dataclass
class AdversarialSample:
    """An adversarial sample generated from an original."""
    original_id: str
    original_content: str
    adversarial_content: str
    technique: str
    technique_description: str
    modality: str
    expected_detection: bool  # Should this still be detected?
    difficulty: str  # "easy", "medium", "hard"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AdversarialTestResult:
    """Result of testing an adversarial sample."""
    sample: AdversarialSample
    detected: bool
    risk_level: str
    score: float
    indicators: List[str]
    evasion_successful: bool  # True if it should be detected but wasn't
    latency_ms: float = 0.0
    error: Optional[str] = None


class AdversarialGenerator:
    """Generate adversarial samples to test detection robustness."""
    
    LLM_REWRITE_PROMPT = """You are a security researcher testing a phishing detection system.

Rewrite the following phishing content to try to evade detection while keeping the same malicious intent.
The rewritten version should still be recognizable as an attempt to deceive users.

Original content ({content_type}):
{content}

Technique to apply: {technique}

Instructions for this technique:
{technique_instructions}

Respond in JSON format:
{{
    "adversarial_content": "<rewritten content>",
    "changes_made": ["<change 1>", "<change 2>"],
    "evasion_strategy": "<brief explanation of why this might evade detection>"
}}"""

    TECHNIQUES = {
        "homoglyph_substitution": {
            "description": "Replace characters with visually similar Unicode characters",
            "instructions": "Replace some Latin characters with Cyrillic or other lookalikes (e.g., 'a' → 'а', 'e' → 'е'). The URL/text should look the same to humans but be different bytes.",
            "difficulty": "medium",
        },
        "zero_width_injection": {
            "description": "Insert invisible zero-width characters",
            "instructions": "Insert zero-width Unicode characters (U+200B, U+200C, U+FEFF) between characters in key words like 'verify', 'account', 'password' to break pattern matching.",
            "difficulty": "easy",
        },
        "url_encoding": {
            "description": "Use URL encoding to obfuscate",
            "instructions": "URL-encode parts of the URL (e.g., 'login' → '%6c%6f%67%69%6e'). Mix encoded and plain characters.",
            "difficulty": "easy",
        },
        "subdomain_abuse": {
            "description": "Use legitimate-looking subdomains",
            "instructions": "Add legitimate-looking subdomains like 'secure.microsoft.com.evil.com' or 'login-paypal.attacker.com'. Make the malicious domain less obvious.",
            "difficulty": "medium",
        },
        "semantic_rewrite": {
            "description": "Rewrite text to convey same meaning differently",
            "instructions": "Rewrite the message to convey the same urgency and action request but using different words. Avoid common phishing keywords like 'urgent', 'verify', 'suspended'.",
            "difficulty": "hard",
        },
        "authority_impersonation": {
            "description": "Make the message appear more legitimate",
            "instructions": "Add legitimate-looking elements: reference numbers, partial account info, professional formatting, realistic sender details. Make it look like a real corporate communication.",
            "difficulty": "hard",
        },
        "urgency_reduction": {
            "description": "Reduce obvious urgency signals",
            "instructions": "Remove or soften urgent language ('URGENT', 'immediately', 'suspended'). Use more subtle pressure tactics. Make the request seem routine.",
            "difficulty": "medium",
        },
        "link_disguise": {
            "description": "Disguise malicious links",
            "instructions": "Use URL shorteners, redirect chains, or hide the real URL. For text, use phrases like 'click here' or 'visit our site' instead of showing the URL.",
            "difficulty": "medium",
        },
    }
    
    def __init__(
        self,
        use_llm: bool = True,
        model: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
    ):
        """Initialize the adversarial generator.
        
        Args:
            use_llm: Whether to use LLM for advanced techniques
            model: OpenAI model for LLM-based generation
            api_key: OpenAI API key
        """
        self.use_llm = use_llm
        self.model = model
        
        if use_llm:
            api_key = api_key or os.getenv("OPENAI_API_KEY")
            if api_key:
                self.client = OpenAI(api_key=api_key)
            else:
                self.use_llm = False
                print("[WARN] No OpenAI API key. LLM-based adversarial generation disabled.")
    
    def _apply_homoglyphs(self, text: str, density: float = 0.3) -> str:
        """Apply homoglyph substitution to text."""
        result = []
        for char in text:
            lower = char.lower()
            if lower in HOMOGLYPHS and random.random() < density:
                replacement = random.choice(HOMOGLYPHS[lower])
                result.append(replacement if char.islower() else replacement.upper())
            else:
                result.append(char)
        return ''.join(result)
    
    def _inject_zero_width(self, text: str, keywords: List[str] = None) -> str:
        """Inject zero-width characters into keywords."""
        if keywords is None:
            keywords = ['verify', 'account', 'password', 'login', 'secure', 'update', 
                       'suspended', 'urgent', 'confirm', 'click', 'bank', 'paypal']
        
        result = text
        for keyword in keywords:
            if keyword.lower() in result.lower():
                # Insert zero-width char in middle of keyword
                mid = len(keyword) // 2
                replacement = keyword[:mid] + random.choice(ZERO_WIDTH) + keyword[mid:]
                result = re.sub(re.escape(keyword), replacement, result, flags=re.IGNORECASE)
        
        return result
    
    def _url_encode_parts(self, url: str) -> str:
        """Partially URL-encode a URL."""
        parsed = urlparse(url)
        
        # Encode parts of the path
        path = parsed.path
        if path:
            words = re.findall(r'[a-zA-Z]+', path)
            for word in words[:2]:  # Encode first 2 words
                encoded = quote(word)
                path = path.replace(word, encoded, 1)
        
        # Reconstruct URL
        return f"{parsed.scheme}://{parsed.netloc}{path}"
        if parsed.query:
            return f"{parsed.scheme}://{parsed.netloc}{path}?{parsed.query}"
        return f"{parsed.scheme}://{parsed.netloc}{path}"
    
    def _generate_with_llm(
        self,
        content: str,
        content_type: str,
        technique: str,
    ) -> Optional[str]:
        """Use LLM to generate adversarial content."""
        if not self.use_llm:
            return None
        
        tech_info = self.TECHNIQUES.get(technique, {})
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security researcher creating test cases for phishing detection. Generate realistic but clearly test content."},
                    {"role": "user", "content": self.LLM_REWRITE_PROMPT.format(
                        content_type=content_type,
                        content=content,
                        technique=technique,
                        technique_instructions=tech_info.get("instructions", "Apply this evasion technique."),
                    )}
                ],
                temperature=0.7,
                response_format={"type": "json_object"},
            )
            
            result = json.loads(response.choices[0].message.content)
            return result.get("adversarial_content")
            
        except Exception as e:
            print(f"[WARN] LLM generation failed: {e}")
            return None
    
    def generate_adversarial(
        self,
        original_id: str,
        content: str,
        modality: str,
        technique: str,
    ) -> AdversarialSample:
        """Generate a single adversarial sample.
        
        Args:
            original_id: ID of the original sample
            content: Original content
            modality: Type of content ("url", "sms", "email")
            technique: Evasion technique to apply
            
        Returns:
            AdversarialSample with the modified content
        """
        tech_info = self.TECHNIQUES.get(technique, {})
        adversarial_content = content
        
        # Apply rule-based techniques
        if technique == "homoglyph_substitution":
            adversarial_content = self._apply_homoglyphs(content)
        elif technique == "zero_width_injection":
            adversarial_content = self._inject_zero_width(content)
        elif technique == "url_encoding" and modality == "url":
            adversarial_content = self._url_encode_parts(content)
        else:
            # Use LLM for complex techniques
            llm_result = self._generate_with_llm(content, modality, technique)
            if llm_result:
                adversarial_content = llm_result
            else:
                # Fallback: combine basic techniques
                adversarial_content = self._inject_zero_width(
                    self._apply_homoglyphs(content, density=0.15)
                )
        
        return AdversarialSample(
            original_id=original_id,
            original_content=content,
            adversarial_content=adversarial_content,
            technique=technique,
            technique_description=tech_info.get("description", ""),
            modality=modality,
            expected_detection=True,  # These should still be detected
            difficulty=tech_info.get("difficulty", "medium"),
        )
    
    def generate_batch(
        self,
        samples: List[Dict[str, Any]],
        techniques: Optional[List[str]] = None,
        samples_per_technique: int = 5,
    ) -> List[AdversarialSample]:
        """Generate a batch of adversarial samples.
        
        Args:
            samples: List of original samples with 'id', 'content', 'modality'
            techniques: Techniques to apply (default: all)
            samples_per_technique: How many samples to generate per technique
            
        Returns:
            List of adversarial samples
        """
        if techniques is None:
            techniques = list(self.TECHNIQUES.keys())
        
        adversarial_samples = []
        
        for technique in techniques:
            # Select random samples for this technique
            selected = random.sample(samples, min(samples_per_technique, len(samples)))
            
            for sample in selected:
                adv_sample = self.generate_adversarial(
                    original_id=str(sample.get("id", "")),
                    content=sample.get("content", ""),
                    modality=sample.get("modality", "text"),
                    technique=technique,
                )
                adversarial_samples.append(adv_sample)
        
        return adversarial_samples


@dataclass
class AdversarialReport:
    """Summary report of adversarial testing."""
    total_samples: int = 0
    total_detected: int = 0
    total_evaded: int = 0
    
    # Overall evasion rate
    evasion_rate: float = 0.0
    
    # Per-technique breakdown
    by_technique: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Per-difficulty breakdown
    by_difficulty: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Most effective techniques
    most_effective_techniques: List[Dict[str, Any]] = field(default_factory=list)
    
    # Individual results
    results: List[Dict] = field(default_factory=list)


def aggregate_adversarial_results(
    results: List[AdversarialTestResult],
) -> AdversarialReport:
    """Aggregate adversarial test results into a summary report."""
    report = AdversarialReport()
    
    valid_results = [r for r in results if r.error is None]
    report.total_samples = len(valid_results)
    report.total_detected = sum(1 for r in valid_results if r.detected)
    report.total_evaded = sum(1 for r in valid_results if r.evasion_successful)
    
    if report.total_samples > 0:
        report.evasion_rate = report.total_evaded / report.total_samples
    
    # Per-technique analysis
    technique_results: Dict[str, List[AdversarialTestResult]] = {}
    for r in valid_results:
        tech = r.sample.technique
        if tech not in technique_results:
            technique_results[tech] = []
        technique_results[tech].append(r)
    
    for tech, tech_results in technique_results.items():
        total = len(tech_results)
        evaded = sum(1 for r in tech_results if r.evasion_successful)
        detected = sum(1 for r in tech_results if r.detected)
        
        report.by_technique[tech] = {
            "total": total,
            "detected": detected,
            "evaded": evaded,
            "evasion_rate": evaded / total if total > 0 else 0,
            "detection_rate": detected / total if total > 0 else 0,
        }
    
    # Per-difficulty analysis
    difficulty_results: Dict[str, List[AdversarialTestResult]] = {}
    for r in valid_results:
        diff = r.sample.difficulty
        if diff not in difficulty_results:
            difficulty_results[diff] = []
        difficulty_results[diff].append(r)
    
    for diff, diff_results in difficulty_results.items():
        total = len(diff_results)
        evaded = sum(1 for r in diff_results if r.evasion_successful)
        
        report.by_difficulty[diff] = {
            "total": total,
            "evaded": evaded,
            "evasion_rate": evaded / total if total > 0 else 0,
        }
    
    # Most effective techniques (highest evasion rate)
    report.most_effective_techniques = sorted(
        [{"technique": k, **v} for k, v in report.by_technique.items()],
        key=lambda x: x["evasion_rate"],
        reverse=True,
    )
    
    # Store individual results
    report.results = [
        {
            "sample": asdict(r.sample),
            "detected": r.detected,
            "risk_level": r.risk_level,
            "score": r.score,
            "evasion_successful": r.evasion_successful,
        }
        for r in valid_results
    ]
    
    return report

