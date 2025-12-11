import pytest
from fastapi.testclient import TestClient

from fraudshield.api.server import app


@pytest.fixture
def client():
    """FastAPI test client fixture."""
    return TestClient(app)


@pytest.fixture
def sample_scam_text():
    """Sample scam message for testing."""
    return "URGENT: Your PayPal account has been compromised! Click here immediately to verify your password and OTP code."


@pytest.fixture
def sample_safe_text():
    """Sample safe message for testing."""
    return "Hi, just wanted to check in about our meeting tomorrow at 3pm."


@pytest.fixture
def sample_phishing_url():
    """Sample phishing URL for testing."""
    return "http://bit.ly/paypal-verify-account-login"


@pytest.fixture
def sample_safe_url():
    """Sample safe URL for testing."""
    return "https://www.google.com"


