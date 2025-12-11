"""
Blacklist and Whitelist service.
Known bad/good patterns for instant classification.
"""

import re
import hashlib
from typing import Set, Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class ListType(str, Enum):
    BLACKLIST = "blacklist"
    WHITELIST = "whitelist"


@dataclass
class ListMatch:
    """Result of a list check."""
    matched: bool
    list_type: Optional[ListType]
    pattern: Optional[str]
    category: Optional[str]
    risk_override: Optional[str]  # "HIGH", "LOW", or None


class PatternLists:
    """
    Manages blacklists and whitelists for known patterns.
    
    Supports:
    - Exact matches (URLs, domains, hashes)
    - Regex patterns
    - Categories for organization
    """
    
    def __init__(self):
        # Structure: {category: {pattern: metadata}}
        self._blacklist_exact: Dict[str, Set[str]] = {
            "domains": set(),
            "urls": set(),
            "content_hashes": set(),
            "phone_numbers": set(),
            "emails": set(),
        }
        
        self._whitelist_exact: Dict[str, Set[str]] = {
            "domains": set(),
            "urls": set(),
            "content_hashes": set(),
        }
        
        self._blacklist_patterns: List[Tuple[str, re.Pattern, str]] = []  # (category, pattern, description)
        self._whitelist_patterns: List[Tuple[str, re.Pattern, str]] = []
        
        # Initialize with common known bad patterns
        self._initialize_default_blacklists()
        self._initialize_default_whitelists()
    
    def _initialize_default_blacklists(self):
        """Add known bad patterns."""
        # Known phishing domains
        bad_domains = [
            "paypa1.com",
            "paypal-secure.com", 
            "amaz0n-support.com",
            "microsoft-alert.com",
            "apple-id-verify.com",
            "bank0famerica.com",
            "chase-secure-login.com",
            "wells-fargo-alert.com",
        ]
        self._blacklist_exact["domains"].update(bad_domains)
        
        # Regex patterns for common scam indicators
        scam_patterns = [
            (r"paypal.*(?!paypal\.com).*\.(com|net|org)", "paypal_impersonation"),
            (r"amazon.*(?!amazon\.).*\.(com|net|org)", "amazon_impersonation"),
            (r"apple.*(?!apple\.com).*verify", "apple_impersonation"),
            (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/.*login", "ip_login_page"),
            (r"bit\.ly\/.*(?:verify|login|account)", "shortener_phishing"),
        ]
        
        for pattern, category in scam_patterns:
            try:
                self._blacklist_patterns.append((category, re.compile(pattern, re.I), pattern))
            except re.error:
                pass
    
    def _initialize_default_whitelists(self):
        """Add known good patterns."""
        good_domains = [
            "google.com",
            "amazon.com",
            "paypal.com",
            "apple.com",
            "microsoft.com",
            "facebook.com",
            "twitter.com",
            "linkedin.com",
            "github.com",
            "stripe.com",
            "chase.com",
            "bankofamerica.com",
            "wellsfargo.com",
        ]
        self._whitelist_exact["domains"].update(good_domains)
    
    def add_to_blacklist(
        self,
        value: str,
        category: str = "domains",
        is_regex: bool = False,
    ) -> bool:
        """Add a pattern to the blacklist."""
        if is_regex:
            try:
                pattern = re.compile(value, re.I)
                self._blacklist_patterns.append((category, pattern, value))
                return True
            except re.error:
                return False
        else:
            if category in self._blacklist_exact:
                self._blacklist_exact[category].add(value.lower())
                return True
        return False
    
    def add_to_whitelist(
        self,
        value: str,
        category: str = "domains",
        is_regex: bool = False,
    ) -> bool:
        """Add a pattern to the whitelist."""
        if is_regex:
            try:
                pattern = re.compile(value, re.I)
                self._whitelist_patterns.append((category, pattern, value))
                return True
            except re.error:
                return False
        else:
            if category in self._whitelist_exact:
                self._whitelist_exact[category].add(value.lower())
                return True
        return False
    
    def remove_from_blacklist(self, value: str, category: str = "domains") -> bool:
        """Remove from blacklist."""
        if category in self._blacklist_exact:
            self._blacklist_exact[category].discard(value.lower())
            return True
        return False
    
    def remove_from_whitelist(self, value: str, category: str = "domains") -> bool:
        """Remove from whitelist."""
        if category in self._whitelist_exact:
            self._whitelist_exact[category].discard(value.lower())
            return True
        return False
    
    def check_url(self, url: str) -> ListMatch:
        """Check a URL against lists."""
        url_lower = url.lower()
        
        # Extract domain from URL
        domain = None
        if "://" in url_lower:
            domain = url_lower.split("://")[1].split("/")[0].split(":")[0]
        
        # Check whitelist first (whitelist = safe, skip further checks)
        if domain and domain in self._whitelist_exact["domains"]:
            return ListMatch(
                matched=True,
                list_type=ListType.WHITELIST,
                pattern=domain,
                category="domains",
                risk_override="LOW",
            )
        
        if url_lower in self._whitelist_exact["urls"]:
            return ListMatch(
                matched=True,
                list_type=ListType.WHITELIST,
                pattern=url_lower,
                category="urls",
                risk_override="LOW",
            )
        
        # Check blacklist exact matches
        if domain and domain in self._blacklist_exact["domains"]:
            return ListMatch(
                matched=True,
                list_type=ListType.BLACKLIST,
                pattern=domain,
                category="domains",
                risk_override="HIGH",
            )
        
        if url_lower in self._blacklist_exact["urls"]:
            return ListMatch(
                matched=True,
                list_type=ListType.BLACKLIST,
                pattern=url_lower,
                category="urls",
                risk_override="HIGH",
            )
        
        # Check blacklist regex patterns
        for category, pattern, pattern_str in self._blacklist_patterns:
            if pattern.search(url_lower):
                return ListMatch(
                    matched=True,
                    list_type=ListType.BLACKLIST,
                    pattern=pattern_str,
                    category=category,
                    risk_override="HIGH",
                )
        
        return ListMatch(
            matched=False,
            list_type=None,
            pattern=None,
            category=None,
            risk_override=None,
        )
    
    def check_content_hash(self, content: str) -> ListMatch:
        """Check content hash against lists."""
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:64]
        
        if content_hash in self._whitelist_exact["content_hashes"]:
            return ListMatch(
                matched=True,
                list_type=ListType.WHITELIST,
                pattern=content_hash,
                category="content_hashes",
                risk_override="LOW",
            )
        
        if content_hash in self._blacklist_exact["content_hashes"]:
            return ListMatch(
                matched=True,
                list_type=ListType.BLACKLIST,
                pattern=content_hash,
                category="content_hashes",
                risk_override="HIGH",
            )
        
        return ListMatch(
            matched=False,
            list_type=None,
            pattern=None,
            category=None,
            risk_override=None,
        )
    
    def get_stats(self) -> Dict[str, int]:
        """Get list statistics."""
        return {
            "blacklist_domains": len(self._blacklist_exact["domains"]),
            "blacklist_urls": len(self._blacklist_exact["urls"]),
            "blacklist_patterns": len(self._blacklist_patterns),
            "whitelist_domains": len(self._whitelist_exact["domains"]),
            "whitelist_urls": len(self._whitelist_exact["urls"]),
        }


# Global instance
pattern_lists = PatternLists()


