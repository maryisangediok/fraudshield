"""Tests for the FastAPI endpoints."""

import pytest


class TestHealthEndpoint:
    """Tests for /health endpoint."""

    def test_health_returns_ok(self, client):
        """Test health endpoint returns OK status."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestAnalyzeEndpoint:
    """Tests for /analyze endpoint."""

    def test_analyze_text_success(self, client, sample_scam_text):
        """Test text analysis returns valid response."""
        response = client.post(
            "/analyze",
            data={"type": "text", "text": sample_scam_text},
        )
        assert response.status_code == 200
        data = response.json()
        assert "risk_level" in data
        assert data["risk_level"] in {"LOW", "MEDIUM", "HIGH"}
        assert "overall_score" in data
        assert "modality_scores" in data
        assert "indicators" in data
        assert "explanation" in data

    def test_analyze_text_missing_text_field(self, client):
        """Test text analysis fails without text field."""
        response = client.post(
            "/analyze",
            data={"type": "text"},
        )
        assert response.status_code == 400
        assert "text" in response.json()["detail"].lower()

    def test_analyze_url_success(self, client, sample_phishing_url):
        """Test URL analysis returns valid response."""
        response = client.post(
            "/analyze",
            data={"type": "url", "url": sample_phishing_url},
        )
        assert response.status_code == 200
        data = response.json()
        assert "risk_level" in data
        assert "modality_scores" in data

    def test_analyze_url_missing_url_field(self, client):
        """Test URL analysis fails without url field."""
        response = client.post(
            "/analyze",
            data={"type": "url"},
        )
        assert response.status_code == 400
        assert "url" in response.json()["detail"].lower()

    def test_analyze_invalid_type(self, client):
        """Test invalid type returns error."""
        response = client.post(
            "/analyze",
            data={"type": "invalid_type", "text": "test"},
        )
        assert response.status_code == 400
        assert "unsupported" in response.json()["detail"].lower()

    def test_analyze_audio_missing_file(self, client):
        """Test audio analysis fails without file."""
        response = client.post(
            "/analyze",
            data={"type": "audio"},
        )
        assert response.status_code == 400
        assert "file" in response.json()["detail"].lower()

    def test_analyze_image_missing_file(self, client):
        """Test image analysis fails without file."""
        response = client.post(
            "/analyze",
            data={"type": "image"},
        )
        assert response.status_code == 400
        assert "file" in response.json()["detail"].lower()

    def test_analyze_multi_with_text_and_url(self, client, sample_scam_text, sample_phishing_url):
        """Test multi-modal analysis with text and URL."""
        response = client.post(
            "/analyze",
            data={
                "type": "multi",
                "text": sample_scam_text,
                "url": sample_phishing_url,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "risk_level" in data
        # Should have scores for both modalities
        assert "text" in data["modality_scores"]
        assert "url" in data["modality_scores"]

    def test_analyze_multi_empty_inputs(self, client):
        """Test multi-modal analysis fails with no inputs."""
        response = client.post(
            "/analyze",
            data={"type": "multi"},
        )
        assert response.status_code == 400
        assert "at least one" in response.json()["detail"].lower()


