"""
ML-SecTest Framework Configuration
====================================

Environment-based configuration using Pydantic BaseSettings.
Supports .env files and environment variables.

Usage:
    from config.settings import get_settings
    settings = get_settings()
    print(settings.API_HOST)
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, validator
from typing import List, Optional
from functools import lru_cache


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables or .env file.

    Priority order:
    1. Environment variables
    2. .env file
    3. Default values
    """

    # ============================================================================
    # API Server Configuration
    # ============================================================================

    API_TITLE: str = Field(
        default="ML-SecTest API",
        description="API title displayed in OpenAPI docs"
    )

    API_VERSION: str = Field(
        default="1.0.0",
        description="API version"
    )

    API_HOST: str = Field(
        default="0.0.0.0",
        description="API server host"
    )

    API_PORT: int = Field(
        default=8081,
        ge=1024,
        le=65535,
        description="API server port"
    )

    API_WORKERS: int = Field(
        default=1,
        ge=1,
        le=16,
        description="Number of Uvicorn workers"
    )

    API_RELOAD: bool = Field(
        default=False,
        description="Enable auto-reload (development only)"
    )

    # ============================================================================
    # CORS Configuration
    # ============================================================================

    CORS_ALLOWED_ORIGINS: str = Field(
        default="http://localhost:3000,http://localhost:8080,http://127.0.0.1:3000,http://127.0.0.1:8080",
        description="Comma-separated list of allowed CORS origins"
    )

    CORS_ALLOW_CREDENTIALS: bool = Field(
        default=True,
        description="Allow cookies in CORS requests"
    )

    CORS_MAX_AGE: int = Field(
        default=600,
        ge=0,
        description="CORS preflight cache duration (seconds)"
    )

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS origins into list."""
        return [origin.strip() for origin in self.CORS_ALLOWED_ORIGINS.split(",") if origin.strip()]

    # ============================================================================
    # Rate Limiting Configuration
    # ============================================================================

    RATE_LIMIT_ENABLED: bool = Field(
        default=True,
        description="Enable rate limiting"
    )

    RATE_LIMIT_REQUESTS: int = Field(
        default=10,
        ge=1,
        description="Number of requests allowed per window"
    )

    RATE_LIMIT_WINDOW: str = Field(
        default="minute",
        description="Rate limit window (second/minute/hour/day)"
    )

    @property
    def rate_limit_string(self) -> str:
        """Format rate limit for slowapi."""
        return f"{self.RATE_LIMIT_REQUESTS}/{self.RATE_LIMIT_WINDOW}"

    @validator("RATE_LIMIT_WINDOW")
    def validate_rate_limit_window(cls, v):
        """Validate rate limit window."""
        allowed = ["second", "minute", "hour", "day"]
        if v not in allowed:
            raise ValueError(f"RATE_LIMIT_WINDOW must be one of {allowed}")
        return v

    # ============================================================================
    # Database Configuration
    # ============================================================================

    DATABASE_TYPE: str = Field(
        default="sqlite",
        description="Database type (sqlite/postgresql)"
    )

    DATABASE_URL: Optional[str] = Field(
        default=None,
        description="Database connection URL (overrides other DB settings)"
    )

    # SQLite specific
    SQLITE_DB_PATH: str = Field(
        default="data/ml_sectest.db",
        description="SQLite database file path"
    )

    # PostgreSQL specific
    POSTGRES_HOST: str = Field(
        default="localhost",
        description="PostgreSQL host"
    )

    POSTGRES_PORT: int = Field(
        default=5432,
        ge=1024,
        le=65535,
        description="PostgreSQL port"
    )

    POSTGRES_DB: str = Field(
        default="ml_sectest",
        description="PostgreSQL database name"
    )

    POSTGRES_USER: str = Field(
        default="ml_sectest",
        description="PostgreSQL username"
    )

    POSTGRES_PASSWORD: str = Field(
        default="",
        description="PostgreSQL password"
    )

    @property
    def database_url_computed(self) -> str:
        """Compute database URL based on settings."""
        if self.DATABASE_URL:
            return self.DATABASE_URL

        if self.DATABASE_TYPE == "sqlite":
            return f"sqlite:///{self.SQLITE_DB_PATH}"
        elif self.DATABASE_TYPE == "postgresql":
            return (
                f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
                f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
            )
        else:
            raise ValueError(f"Unknown database type: {self.DATABASE_TYPE}")

    @validator("DATABASE_TYPE")
    def validate_database_type(cls, v):
        """Validate database type."""
        allowed = ["sqlite", "postgresql"]
        if v not in allowed:
            raise ValueError(f"DATABASE_TYPE must be one of {allowed}")
        return v

    # ============================================================================
    # Logging Configuration
    # ============================================================================

    LOG_LEVEL: str = Field(
        default="INFO",
        description="Logging level (DEBUG/INFO/WARNING/ERROR/CRITICAL)"
    )

    LOG_FORMAT: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log message format"
    )

    LOG_FILE: Optional[str] = Field(
        default=None,
        description="Log file path (None = stdout only)"
    )

    @validator("LOG_LEVEL")
    def validate_log_level(cls, v):
        """Validate log level."""
        allowed = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v_upper = v.upper()
        if v_upper not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}")
        return v_upper

    # ============================================================================
    # Security Configuration
    # ============================================================================

    SECRET_KEY: str = Field(
        default="insecure-development-key-change-in-production",
        min_length=32,
        description="Secret key for signing tokens (MUST change in production)"
    )

    API_KEY_ENABLED: bool = Field(
        default=False,
        description="Require API key authentication"
    )

    API_KEYS: str = Field(
        default="",
        description="Comma-separated list of valid API keys"
    )

    @property
    def api_keys_list(self) -> List[str]:
        """Parse API keys into list."""
        if not self.API_KEYS:
            return []
        return [key.strip() for key in self.API_KEYS.split(",") if key.strip()]

    # ============================================================================
    # Scanning Configuration
    # ============================================================================

    SCAN_DEFAULT_TIMEOUT: int = Field(
        default=300,
        ge=10,
        le=3600,
        description="Default scan timeout (seconds)"
    )

    SCAN_MAX_CONCURRENT: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum concurrent scans"
    )

    SCAN_REPORTS_DIR: str = Field(
        default="reports",
        description="Directory for scan reports"
    )

    # ============================================================================
    # Prometheus Metrics Configuration
    # ============================================================================

    METRICS_ENABLED: bool = Field(
        default=True,
        description="Enable Prometheus metrics"
    )

    METRICS_PORT: int = Field(
        default=9090,
        ge=1024,
        le=65535,
        description="Prometheus metrics port (if separate server)"
    )

    # ============================================================================
    # Environment & Debug
    # ============================================================================

    ENVIRONMENT: str = Field(
        default="development",
        description="Environment name (development/staging/production)"
    )

    DEBUG: bool = Field(
        default=False,
        description="Enable debug mode"
    )

    @validator("ENVIRONMENT")
    def validate_environment(cls, v):
        """Validate environment."""
        allowed = ["development", "staging", "production"]
        if v not in allowed:
            raise ValueError(f"ENVIRONMENT must be one of {allowed}")
        return v

    # ============================================================================
    # Pydantic Settings Configuration
    # ============================================================================

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"  # Ignore extra environment variables
    )


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.

    Uses lru_cache to ensure settings are loaded only once.
    Call this function to access settings throughout the application.

    Returns:
        Settings: Configured settings instance
    """
    return Settings()


# Convenience function to validate settings at startup
def validate_settings() -> None:
    """
    Validate settings and print configuration summary.

    Raises:
        ValueError: If settings are invalid
    """
    settings = get_settings()

    # Validate critical settings in production
    if settings.ENVIRONMENT == "production":
        if settings.SECRET_KEY == "insecure-development-key-change-in-production":
            raise ValueError(
                "CRITICAL: SECRET_KEY must be changed in production! "
                "Set the SECRET_KEY environment variable."
            )

        if settings.DEBUG:
            raise ValueError(
                "WARNING: DEBUG mode should be disabled in production! "
                "Set DEBUG=false in environment."
            )

        if "*" in settings.cors_origins_list:
            raise ValueError(
                "SECURITY: Wildcard CORS origins not allowed in production! "
                "Set specific origins in CORS_ALLOWED_ORIGINS."
            )

    print(f"[Config] Environment: {settings.ENVIRONMENT}")
    print(f"[Config] API: {settings.API_HOST}:{settings.API_PORT}")
    print(f"[Config] Database: {settings.DATABASE_TYPE}")
    print(f"[Config] CORS Origins: {len(settings.cors_origins_list)} configured")
    print(f"[Config] Rate Limiting: {settings.rate_limit_string if settings.RATE_LIMIT_ENABLED else 'disabled'}")
    print(f"[Config] Metrics: {'enabled' if settings.METRICS_ENABLED else 'disabled'}")
    print(f"[Config] Log Level: {settings.LOG_LEVEL}")
