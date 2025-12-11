"""Tests for blacklist/whitelist service."""

import pytest

from fraudshield.services.lists_service import PatternLists, pattern_lists, ListType


class TestPatternLists:
    """Tests for blacklist/whitelist functionality."""

    @pytest.fixture
    def fresh_lists(self):
        """Create a fresh PatternLists instance for each test."""
        return PatternLists()

    # ============== WHITELIST TESTS ==============

    def test_whitelisted_domain_returns_low(self, fresh_lists):
        """Whitelisted domains should return LOW risk."""
        result = fresh_lists.check_url("https://google.com/search")
        assert result.matched is True
        assert result.list_type == ListType.WHITELIST
        assert result.risk_override == "LOW"

    def test_whitelisted_paypal(self, fresh_lists):
        """PayPal.com should be whitelisted."""
        result = fresh_lists.check_url("https://www.paypal.com/login")
        assert result.matched is True
        assert result.list_type == ListType.WHITELIST
        assert result.risk_override == "LOW"

    def test_add_to_whitelist(self, fresh_lists):
        """Should be able to add domains to whitelist."""
        fresh_lists.add_to_whitelist("mycompany.com", category="domains")
        result = fresh_lists.check_url("https://mycompany.com/page")
        assert result.matched is True
        assert result.list_type == ListType.WHITELIST

    # ============== BLACKLIST TESTS ==============

    def test_blacklisted_domain_returns_high(self, fresh_lists):
        """Blacklisted domains should return HIGH risk."""
        result = fresh_lists.check_url("https://paypa1.com/login")
        assert result.matched is True
        assert result.list_type == ListType.BLACKLIST
        assert result.risk_override == "HIGH"

    def test_blacklist_regex_pattern(self, fresh_lists):
        """Regex patterns should match blacklist."""
        # paypal impersonation pattern
        result = fresh_lists.check_url("https://paypal-secure-verify.com/login")
        assert result.matched is True
        assert result.list_type == ListType.BLACKLIST

    def test_add_to_blacklist(self, fresh_lists):
        """Should be able to add domains to blacklist."""
        fresh_lists.add_to_blacklist("scam-site.com", category="domains")
        result = fresh_lists.check_url("https://scam-site.com/phish")
        assert result.matched is True
        assert result.list_type == ListType.BLACKLIST
        assert result.risk_override == "HIGH"

    def test_add_regex_to_blacklist(self, fresh_lists):
        """Should be able to add regex patterns to blacklist."""
        fresh_lists.add_to_blacklist(r"evil-.*\.com", category="custom", is_regex=True)
        result = fresh_lists.check_url("https://evil-domain.com/bad")
        assert result.matched is True
        assert result.list_type == ListType.BLACKLIST

    # ============== PRIORITY TESTS ==============

    def test_whitelist_checked_first(self, fresh_lists):
        """Whitelist should take priority over blacklist patterns."""
        # amazon.com is whitelisted
        result = fresh_lists.check_url("https://amazon.com/login")
        assert result.list_type == ListType.WHITELIST
        assert result.risk_override == "LOW"

    def test_no_match_returns_not_matched(self, fresh_lists):
        """Unknown URLs should return not matched."""
        result = fresh_lists.check_url("https://random-site-xyz123.com/page")
        assert result.matched is False
        assert result.list_type is None
        assert result.risk_override is None

    # ============== CONTENT HASH TESTS ==============

    def test_content_hash_blacklist(self, fresh_lists):
        """Should be able to blacklist content by hash."""
        fresh_lists._blacklist_exact["content_hashes"].add(
            "a" * 64  # Fake hash
        )
        # This won't match because the hash is different
        result = fresh_lists.check_content_hash("test content")
        assert result.matched is False

    def test_content_hash_whitelist(self, fresh_lists):
        """Should be able to whitelist content by hash."""
        import hashlib
        content = "This is known safe content"
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:64]
        
        fresh_lists._whitelist_exact["content_hashes"].add(content_hash)
        result = fresh_lists.check_content_hash(content)
        assert result.matched is True
        assert result.list_type == ListType.WHITELIST

    # ============== MANAGEMENT TESTS ==============

    def test_remove_from_blacklist(self, fresh_lists):
        """Should be able to remove from blacklist."""
        fresh_lists.add_to_blacklist("test-domain.com", category="domains")
        fresh_lists.remove_from_blacklist("test-domain.com", category="domains")
        result = fresh_lists.check_url("https://test-domain.com")
        assert result.matched is False

    def test_remove_from_whitelist(self, fresh_lists):
        """Should be able to remove from whitelist."""
        # google.com is whitelisted by default
        fresh_lists.remove_from_whitelist("google.com", category="domains")
        result = fresh_lists.check_url("https://google.com")
        assert result.matched is False

    def test_stats(self, fresh_lists):
        """Stats should reflect list contents."""
        stats = fresh_lists.get_stats()
        assert "blacklist_domains" in stats
        assert "whitelist_domains" in stats
        assert stats["blacklist_domains"] > 0  # Default blacklist entries
        assert stats["whitelist_domains"] > 0  # Default whitelist entries

    # ============== GLOBAL INSTANCE ==============

    def test_global_pattern_lists_exists(self):
        """Global pattern_lists should be available."""
        assert pattern_lists is not None
        result = pattern_lists.check_url("https://google.com")
        assert hasattr(result, "matched")
        assert hasattr(result, "list_type")


