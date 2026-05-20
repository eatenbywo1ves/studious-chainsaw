from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-driven configuration. Variables are prefixed PMA_."""

    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="PMA_", extra="ignore"
    )

    database_url: str = "sqlite:///./polymarket_agent.db"
    clob_base_url: str = "https://clob.polymarket.com"
    gamma_base_url: str = "https://gamma-api.polymarket.com"
    http_timeout_seconds: float = 30.0


def get_settings() -> Settings:
    """Return a freshly-loaded Settings instance."""
    return Settings()
