"""
Client-specific configuration.
Allows different thresholds and settings per API client.
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel


class ClientThresholds(BaseModel):
    """Score thresholds for risk level determination."""
    high_threshold: float = 7.0  # Score >= this = HIGH
    medium_threshold: float = 4.0  # Score >= this = MEDIUM (below = LOW)


class ClientConfig(BaseModel):
    """Per-client configuration."""
    client_id: str
    name: str = "default"
    thresholds: ClientThresholds = ClientThresholds()
    enabled_modalities: list = ["text", "url", "audio", "image", "video", "email", "pdf", "multi"]
    max_requests_per_minute: int = 60
    webhook_url: Optional[str] = None  # For async notifications
    

# Default configuration
DEFAULT_CONFIG = ClientConfig(client_id="default")

# In-memory client config store (replace with DB in production)
_client_configs: Dict[str, ClientConfig] = {
    "default": DEFAULT_CONFIG,
}


def get_client_config(client_id: str = "default") -> ClientConfig:
    """Get configuration for a specific client."""
    return _client_configs.get(client_id, DEFAULT_CONFIG)


def set_client_config(config: ClientConfig) -> None:
    """Set configuration for a client."""
    _client_configs[config.client_id] = config


def get_client_thresholds(client_id: str = "default") -> ClientThresholds:
    """Get thresholds for a specific client."""
    return get_client_config(client_id).thresholds


def derive_risk_from_score_with_thresholds(
    score: float,
    thresholds: ClientThresholds,
) -> str:
    """Derive risk level using client-specific thresholds."""
    if score >= thresholds.high_threshold:
        return "HIGH"
    elif score >= thresholds.medium_threshold:
        return "MEDIUM"
    else:
        return "LOW"


# Pre-configured client examples
CONSERVATIVE_CLIENT = ClientConfig(
    client_id="conservative",
    name="High Security Client",
    thresholds=ClientThresholds(high_threshold=5.0, medium_threshold=2.5),
)

PERMISSIVE_CLIENT = ClientConfig(
    client_id="permissive", 
    name="Low False Positive Client",
    thresholds=ClientThresholds(high_threshold=8.5, medium_threshold=5.5),
)

# Register example configs
set_client_config(CONSERVATIVE_CLIENT)
set_client_config(PERMISSIVE_CLIENT)


