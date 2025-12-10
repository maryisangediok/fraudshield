from fraudshield.services.risk_service import RiskService


def test_risk_service_basic():
    level, score, explanation = RiskService.compute({"text": 0.8, "url": 0.2}, ["x"])
    assert level in {"LOW", "MEDIUM", "HIGH"}
    assert 0.0 <= score <= 1.0
    assert isinstance(explanation, str)
