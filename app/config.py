from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AccessGov"
    database_url: str = "sqlite:///./accessgov.db"
    cors_origins: str = "*"
    dormant_days: int = 90
    excessive_entitlement_threshold: int = 8

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
