"""
Centralized Configuration Management using Pydantic v2

Simplified version compatible with Pydantic v2 and pydantic-settings.
"""

import logging
from enum import Enum
from pathlib import Path
from typing import Optional, List
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, SecretStr, field_validator

logger = logging.getLogger(__name__)


# ============================================================================
# ENUMERATIONS
# ============================================================================


class Environment(str, Enum):
    """Deployment environment"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


class SecurityLevel(str, Enum):
    """Security configuration level"""
    BASIC = "basic"
    ENHANCED = "enhanced"
    STRICT = "strict"


class LogLevel(str, Enum):
    """Logging levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


# ============================================================================
# DOMAIN-SPECIFIC CONFIGURATION CLASSES
# ============================================================================


class DatabaseConfig(BaseSettings):
    """Database connection configuration"""

    model_config = SettingsConfigDict(env_prefix="DATABASE_", case_sensitive=False)

    url: str = Field(
        default="sqlite:///./catalytic_saas.db",
        description="Database connection URL"
    )
    pool_size: int = Field(default=20, ge=1, le=100)
    max_overflow: int = Field(default=40, ge=0, le=100)
    pool_pre_ping: bool = Field(default=True)
    echo: bool = Field(default=False)

    @property
    def is_sqlite(self) -> bool:
        return self.url.startswith("sqlite")

    @property
    def is_postgresql(self) -> bool:
        return self.url.startswith("postgresql")


class RedisConfig(BaseSettings):
    """Redis connection configuration"""

    model_config = SettingsConfigDict(env_prefix="REDIS_", case_sensitive=False)

    host: str = Field(default="localhost")
    port: int = Field(default=6379, ge=1, le=65535)
    password: Optional[SecretStr] = Field(default=None)
    db: int = Field(default=0, ge=0, le=15)
    max_connections: int = Field(default=100, ge=1, le=1000)
    socket_timeout: int = Field(default=5, ge=1, le=30)
    socket_connect_timeout: int = Field(default=5, ge=1, le=30)
    decode_responses: bool = Field(default=True)

    # Circuit breaker
    circuit_breaker_enabled: bool = Field(default=True)
    circuit_breaker_failure_threshold: int = Field(default=5, ge=1)
    circuit_breaker_recovery_timeout: int = Field(default=60, ge=1)

    @property
    def connection_url(self) -> str:
        """Get Redis connection URL"""
        auth = f":{self.password.get_secret_value()}@" if self.password else ""
        return f"redis://{auth}{self.host}:{self.port}/{self.db}"


class AuthConfig(BaseSettings):
    """Authentication and JWT configuration"""

    model_config = SettingsConfigDict(env_prefix="JWT_", case_sensitive=False)

    secret_key: Optional[SecretStr] = Field(default=None, alias="JWT_SECRET_KEY")
    algorithm: str = Field(default="RS256")
    private_key_path: Optional[Path] = Field(default=None)
    public_key_path: Optional[Path] = Field(default=None)

    # Token expiration
    access_token_expire_minutes: int = Field(default=15, ge=1, le=1440)
    refresh_token_expire_days: int = Field(default=30, ge=1, le=90)

    # API Key
    api_key_prefix: str = Field(default="clc_")

    # Session
    session_secret_key: Optional[SecretStr] = Field(default=None)
    session_cookie_secure: bool = Field(default=True)
    session_cookie_httponly: bool = Field(default=True)
    session_cookie_samesite: str = Field(default="strict")

    # CSRF
    csrf_enabled: bool = Field(default=True)
    csrf_secret_key: Optional[SecretStr] = Field(default=None)


class SecurityConfig(BaseSettings):
    """Security-related configuration"""

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)

    security_level: SecurityLevel = Field(default=SecurityLevel.ENHANCED)
    api_encryption_key_path: Optional[Path] = Field(default=None)
    db_encryption_key_path: Optional[Path] = Field(default=None)

    # Rate Limiting
    rate_limit_enabled: bool = Field(default=True)
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10000)
    rate_limit_burst: int = Field(default=10, ge=1, le=1000)

    # DDoS Protection
    ddos_protection_enabled: bool = Field(default=True)
    ddos_block_duration_minutes: int = Field(default=60, ge=1, le=1440)


class CORSConfig(BaseSettings):
    """CORS configuration"""

    model_config = SettingsConfigDict(env_prefix="CORS_", case_sensitive=False)

    allowed_origins: List[str] = Field(default=["http://localhost:3000"])
    allow_credentials: bool = Field(default=True)
    allow_methods: List[str] = Field(default=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
    allow_headers: List[str] = Field(default=["*"])
    max_age: int = Field(default=600, ge=0)

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_origins(cls, v):
        """Parse comma-separated string or list"""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v


class EmailConfig(BaseSettings):
    """Email service configuration"""

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)

    # SendGrid
    sendgrid_api_key: Optional[SecretStr] = Field(default=None)

    # AWS SES
    aws_access_key_id: Optional[SecretStr] = Field(default=None)
    aws_secret_access_key: Optional[SecretStr] = Field(default=None)
    aws_region: str = Field(default="us-east-1")

    # SMTP
    smtp_host: Optional[str] = Field(default=None)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: Optional[str] = Field(default=None)
    smtp_password: Optional[SecretStr] = Field(default=None)

    # Common
    email_from: str = Field(default="noreply@catalyticcomputing.com")
    email_from_name: str = Field(default="Catalytic Computing")

    @property
    def provider(self) -> str:
        """Determine which email provider is configured"""
        if self.sendgrid_api_key:
            return "sendgrid"
        elif self.aws_access_key_id and self.aws_secret_access_key:
            return "ses"
        elif self.smtp_host:
            return "smtp"
        return "none"


class StripeConfig(BaseSettings):
    """Stripe payment configuration"""

    model_config = SettingsConfigDict(env_prefix="STRIPE_", case_sensitive=False)

    secret_key: Optional[SecretStr] = Field(default=None)
    publishable_key: Optional[str] = Field(default=None)
    webhook_secret: Optional[SecretStr] = Field(default=None)

    @property
    def is_test_mode(self) -> bool:
        """Check if using test mode keys"""
        if self.secret_key:
            return self.secret_key.get_secret_value().startswith("sk_test_")
        return True


class AppConfig(BaseSettings):
    """Application-level configuration"""

    model_config = SettingsConfigDict(env_prefix="APP_", case_sensitive=False)

    name: str = Field(default="Catalytic Computing SaaS")
    env: Environment = Field(default=Environment.DEVELOPMENT)
    debug: bool = Field(default=False)
    log_level: LogLevel = Field(default=LogLevel.INFO)

    # URLs
    frontend_url: str = Field(default="http://localhost:3000")
    backend_url: str = Field(default="http://localhost:8000")

    # Server
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000, ge=1, le=65535)
    workers: int = Field(default=1, ge=1, le=16)


# ============================================================================
# MAIN SETTINGS CLASS
# ============================================================================


class Settings(BaseSettings):
    """Main application settings combining all configuration domains"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # Domain configurations
    app: AppConfig = Field(default_factory=AppConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    cors: CORSConfig = Field(default_factory=CORSConfig)
    email: EmailConfig = Field(default_factory=EmailConfig)
    stripe: StripeConfig = Field(default_factory=StripeConfig)

    # Legacy support
    deployment_env: Environment = Field(default=Environment.DEVELOPMENT)

    def model_post_init(self, __context) -> None:
        """Log configuration summary after initialization"""
        logger.info("=" * 70)
        logger.info("Configuration Loaded Successfully")
        logger.info("=" * 70)
        logger.info(f"Environment: {self.app.env.value}")
        logger.info(f"Debug Mode: {self.app.debug}")
        logger.info(f"Log Level: {self.app.log_level.value}")
        logger.info(f"Database: {'SQLite' if self.database.is_sqlite else 'PostgreSQL'}")
        logger.info(f"Redis: {self.redis.host}:{self.redis.port}")
        logger.info(f"JWT Algorithm: {self.auth.algorithm}")
        logger.info(f"Security Level: {self.security.security_level.value}")
        logger.info(f"Rate Limiting: {'Enabled' if self.security.rate_limit_enabled else 'Disabled'}")
        logger.info(f"CORS Origins: {len(self.cors.allowed_origins)} configured")
        logger.info(f"Email Provider: {self.email.provider}")
        logger.info(f"Stripe: {'Test Mode' if self.stripe.is_test_mode else 'Live Mode'}")
        logger.info("=" * 70)


# ============================================================================
# SETTINGS INSTANCE
# ============================================================================


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()


def get_config() -> Settings:
    """Alias for get_settings()"""
    return get_settings()
