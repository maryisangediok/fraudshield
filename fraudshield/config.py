from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    # ==========================================================================
    # ENVIRONMENT
    # ==========================================================================
    environment: str = "dev"  # "dev", "prod"
    debug: bool = True

    # ==========================================================================
    # DATABASE
    # ==========================================================================
    database_url: str = "sqlite:///./fraudshield.db"

    # ==========================================================================
    # OPENAI
    # ==========================================================================
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_vision_model: str = "gpt-4o-mini"
    openai_transcription_model: str = "gpt-4o-mini-transcribe"
    openai_max_tokens: int = 1000  # Max tokens for LLM responses

    # ==========================================================================
    # API SECURITY
    # ==========================================================================
    api_token: str = ""  # Required in production, optional in dev
    api_token_header: str = "X-API-Key"

    # ==========================================================================
    # RATE LIMITING
    # ==========================================================================
    rate_limit_requests: int = 60  # Max requests per window
    rate_limit_window: int = 60  # Window in seconds (60 = per minute)

    # ==========================================================================
    # CORS
    # ==========================================================================
    cors_origins: str = "*"  # Comma-separated origins, or "*" for all

    # ==========================================================================
    # RISK THRESHOLDS (0-10 scale)
    # ==========================================================================
    high_risk_threshold: float = 7.0  # Score >= this = HIGH
    medium_risk_threshold: float = 4.0  # Score >= this = MEDIUM (below = LOW)

    # ==========================================================================
    # CRITICAL INDICATORS (force HIGH risk)
    # ==========================================================================
    critical_indicators: str = (
        "credential_theft,identity_theft,brand_impersonation_paypal,"
        "brand_impersonation,wire_transfer_request,gift_card_scam,"
        "malware_distribution,known_phishing_url,blacklisted_content,"
        "blacklisted_domains"
    )

    # ==========================================================================
    # ELEVATED INDICATORS (bump LOW to MEDIUM)
    # ==========================================================================
    elevated_indicators: str = (
        "urgency_language,suspicious_keywords,crypto_reference,"
        "url_shortener_used,phishing_path_keywords,sensitive_query_parameters,"
        "velocity_duplicate_content,velocity_high_ip_rate"
    )

    # ==========================================================================
    # VELOCITY CHECKING
    # ==========================================================================
    velocity_content_window: int = 300  # Seconds to track duplicate content (5 min)
    velocity_content_max_duplicates: int = 3  # Max same content before flagging
    velocity_ip_window: int = 60  # Seconds for IP rate tracking
    velocity_ip_max_requests: int = 30  # Max requests per IP in window

    # ==========================================================================
    # CACHING
    # ==========================================================================
    cache_capacity: int = 128  # Max cached items
    cache_ttl: int = 3600  # Cache TTL in seconds (1 hour)

    # ==========================================================================
    # FEEDBACK
    # ==========================================================================
    whitelist_suggestion_threshold: int = 3  # False positives before suggesting whitelist

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ==========================================================================
    # COMPUTED PROPERTIES
    # ==========================================================================

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "prod"

    @property
    def cors_origins_list(self) -> list:
        if self.cors_origins == "*":
            return ["*"]
        return [origin.strip() for origin in self.cors_origins.split(",")]

    @property
    def critical_indicators_list(self) -> List[str]:
        return [ind.strip() for ind in self.critical_indicators.split(",") if ind.strip()]

    @property
    def elevated_indicators_list(self) -> List[str]:
        return [ind.strip() for ind in self.elevated_indicators.split(",") if ind.strip()]


settings = Settings()
