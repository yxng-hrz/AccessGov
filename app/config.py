from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AccessGov"
    app_version: str = "2.0.0"
    database_url: str = "sqlite:///./accessgov.db"
    cors_origins: str = "*"

    # Detection thresholds
    dormant_days: int = 90
    excessive_entitlement_threshold: int = 8
    mover_recertification_days: int = 30

    # Governance guardrails
    campaign_default_duration_days: int = 21
    exception_max_days: int = 180
    expiry_warning_days: int = 14

    # Security: "key:role,key2:role2" — empty means demo mode (everyone is admin)
    api_keys: str = ""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
