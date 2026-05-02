"""
Centralized Configuration Management using Pydantic BaseSettings

This module provides type-safe, validated configuration for the entire application.
All environment variables are defined here with proper types, defaults, and validation.

Benefits:
- Type safety (IDE autocomplete, mypy validation)
- Fail-fast on startup (invalid config discovered before deployment)
- Security (SecretStr never logged, required secrets in production)
- Documentation (self-documenting configuration)
- Testing (easy to override for tests)

Usage:
    from shared.config import get_settings
    
    settings = get_settings()
    print(settings.database.url)
    print(settings.auth.jwt_algorithm)
"""

import os
import logging
from enum import Enum
from pathlib import Path
from typing import Optional, List
from functools import lru_cache

try:
    # Pydantic v2
    from pydantic_settings import BaseSettings
    from pydantic import Field, SecretStr, field_validator, HttpUrl
    PYDANTIC_V2 = True
except ImportError:
    # Pydantic v1 fallback
    from pydantic import BaseSettings, Field, SecretStr, validator
    PYDANTIC_V2 = False

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

    url: str = Field(
        default="sqlite:///./catalytic_saas.db",
        description="Database connection URL (PostgreSQL or SQLite)"
    )

    # PostgreSQL pool settings (ignored for SQLite)
    pool_size: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Number of connections to keep in pool"
    )

    max_overflow: int = Field(
        default=40,
        ge=0,
        le=100,
        description="Additional connections allowed under high load"
    )

    pool_pre_ping: bool = Field(
        default=True,
        description="Verify connections are alive before using"
    )

    echo: bool = Field(
        default=False,
        description="Log all SQL statements (development only)"
    )

    @validator("url")
    def validate_url(cls, v: str, values: dict) -> str:
        """Ensure database URL is valid"""
        if not v:
            raise ValueError("DATABASE_URL cannot be empty")

        # In production, require PostgreSQL
        env = os.getenv("DEPLOYMENT_ENV", "development")
        if env == "production" and v.startswith("sqlite"):
            raise ValueError("SQLite not allowed in production - use PostgreSQL")

        return v

    @property
    def is_sqlite(self) -> bool:
        """Check if using SQLite"""
        return self.url.startswith("sqlite")

    @property
    def is_postgresql(self) -> bool:
        """Check if using PostgreSQL"""
        return self.url.startswith("postgresql")

    class Config:
        env_prefix = "DATABASE_"
        case_sensitive = False


class RedisConfig(BaseSettings):
    """Redis connection configuration"""

    host: str = Field(
        default="localhost",
        description="Redis server hostname"
    )

    port: int = Field(
        default=6379,
        ge=1,
        le=65535,
        description="Redis server port"
    )

    password: Optional[SecretStr] = Field(
        default=None,
        description="Redis authentication password"
    )

    db: int = Field(
        default=0,
        ge=0,
        le=15,
        description="Redis database number"
    )

    # Connection pool settings
    max_connections: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Maximum number of connections in pool"
    )

    socket_timeout: int = Field(
        default=5,
        ge=1,
        le=30,
        description="Socket timeout in seconds"
    )

    socket_connect_timeout: int = Field(
        default=5,
        ge=1,
        le=30,
        description="Socket connection timeout in seconds"
    )

    decode_responses: bool = Field(
        default=True,
        description="Decode Redis responses as strings"
    )

    # Circuit breaker settings
    circuit_breaker_enabled: bool = Field(
        default=True,
        description="Enable circuit breaker for Redis operations"
    )

    circuit_breaker_failure_threshold: int = Field(
        default=5,
        ge=1,
        description="Number of failures before opening circuit"
    )

    circuit_breaker_recovery_timeout: int = Field(
        default=60,
        ge=1,
        description="Seconds before attempting recovery"
    )

    @property
    def connection_url(self) -> str:
        """Get Redis connection URL"""
        auth = f":{self.password.get_secret_value()}@" if self.password else ""
        return f"redis://{auth}{self.host}:{self.port}/{self.db}"

    class Config:
        env_prefix = "REDIS_"
        case_sensitive = False


class AuthConfig(BaseSettings):
    """Authentication and JWT configuration"""

    # JWT Settings
    jwt_secret_key: Optional[SecretStr] = Field(
        default=None,
        description="Secret key for JWT signing (REQUIRED in production)"
    )

    jwt_algorithm: str = Field(
        default="RS256",
        description="JWT signing algorithm (RS256 for RSA, HS256 for HMAC)"
    )

    jwt_private_key_path: Optional[Path] = Field(
        default=None,
        description="Path to RSA private key (for RS256)"
    )

    jwt_public_key_path: Optional[Path] = Field(
        default=None,
        description="Path to RSA public key (for RS256)"
    )

    # Token expiration
    access_token_expire_minutes: int = Field(
        default=15,
        ge=1,
        le=1440,  # Max 24 hours
        description="Access token lifetime in minutes"
    )

    refresh_token_expire_days: int = Field(
        default=30,
        ge=1,
        le=90,
        description="Refresh token lifetime in days"
    )

    # API Key settings
    api_key_prefix: str = Field(
        default="clc_",
        description="Prefix for API keys"
    )

    # Session settings
    session_secret_key: Optional[SecretStr] = Field(
        default=None,
        description="Secret key for session cookies"
    )

    session_cookie_secure: bool = Field(
        default=True,
        description="Require HTTPS for session cookies"
    )

    session_cookie_httponly: bool = Field(
        default=True,
        description="Prevent JavaScript access to cookies"
    )

    session_cookie_samesite: str = Field(
        default="strict",
        description="SameSite cookie policy"
    )

    # CSRF Protection
    csrf_enabled: bool = Field(
        default=True,
        description="Enable CSRF protection"
    )

    csrf_secret_key: Optional[SecretStr] = Field(
        default=None,
        description="Secret key for CSRF tokens"
    )

    @validator("jwt_secret_key", always=True)
    def validate_jwt_secret(cls, v: Optional[SecretStr], values: dict) -> Optional[SecretStr]:
        """Require JWT secret in production"""
        env = os.getenv("DEPLOYMENT_ENV", "development")

        if env == "production" and v is None:
            raise ValueError(
                "JWT_SECRET_KEY is REQUIRED in production. "
                "Set environment variable or use RSA keys."
            )

        return v

    @validator("jwt_private_key_path")
    def validate_private_key_path(cls, v: Optional[Path]) -> Optional[Path]:
        """Ensure private key exists if path provided"""
        if v is not None and not v.exists():
            raise ValueError(f"JWT private key not found at: {v}")
        return v

    @validator("jwt_public_key_path")
    def validate_public_key_path(cls, v: Optional[Path]) -> Optional[Path]:
        """Ensure public key exists if path provided"""
        if v is not None and not v.exists():
            raise ValueError(f"JWT public key not found at: {v}")
        return v

    class Config:
        env_prefix = "JWT_"
        case_sensitive = False


class SecurityConfig(BaseSettings):
    """Security-related configuration"""

    security_level: SecurityLevel = Field(
        default=SecurityLevel.ENHANCED,
        description="Overall security level"
    )

    # API Encryption
    api_encryption_key_path: Optional[Path] = Field(
        default=None,
        description="Path to API encryption key"
    )

    # Database Encryption
    db_encryption_key_path: Optional[Path] = Field(
        default=None,
        description="Path to database encryption key"
    )

    # Rate Limiting
    rate_limit_enabled: bool = Field(
        default=True,
        description="Enable rate limiting"
    )

    rate_limit_per_minute: int = Field(
        default=60,
        ge=1,
        le=10000,
        description="Maximum requests per minute per user"
    )

    rate_limit_burst: int = Field(
        default=10,
        ge=1,
        le=1000,
        description="Burst allowance for rate limiting"
    )

    # DDoS Protection
    ddos_protection_enabled: bool = Field(
        default=True,
        description="Enable DDoS protection"
    )

    ddos_block_duration_minutes: int = Field(
        default=60,
        ge=1,
        le=1440,
        description="Duration to block suspected attackers"
    )

    class Config:
        env_prefix = ""
        case_sensitive = False


class CORSConfig(BaseSettings):
    """CORS (Cross-Origin Resource Sharing) configuration"""

    allowed_origins: List[str] = Field(
        default=["http://localhost:3000"],
        description="Allowed CORS origins"
    )

    allow_credentials: bool = Field(
        default=True,
        description="Allow cookies in CORS requests"
    )

    allow_methods: List[str] = Field(
        default=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        description="Allowed HTTP methods"
    )

    allow_headers: List[str] = Field(
        default=["*"],
        description="Allowed HTTP headers"
    )

    max_age: int = Field(
        default=600,
        ge=0,
        description="CORS preflight cache duration in seconds"
    )

    @validator("allowed_origins", pre=True)
    def parse_origins(cls, v):
        """Parse comma-separated string or list"""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    class Config:
        env_prefix = "CORS_"
        case_sensitive = False


class EmailConfig(BaseSettings):
    """Email service configuration"""

    # SendGrid
    sendgrid_api_key: Optional[SecretStr] = Field(
        default=None,
        description="SendGrid API key"
    )

    # AWS SES
    aws_access_key_id: Optional[SecretStr] = Field(
        default=None,
        description="AWS access key ID"
    )

    aws_secret_access_key: Optional[SecretStr] = Field(
        default=None,
        description="AWS secret access key"
    )

    aws_region: str = Field(
        default="us-east-1",
        description="AWS region"
    )

    # SMTP Fallback
    smtp_host: Optional[str] = Field(
        default=None,
        description="SMTP server hostname"
    )

    smtp_port: int = Field(
        default=587,
        ge=1,
        le=65535,
        description="SMTP server port"
    )

    smtp_username: Optional[str] = Field(
        default=None,
        description="SMTP username"
    )

    smtp_password: Optional[SecretStr] = Field(
        default=None,
        description="SMTP password"
    )

    # Common settings
    email_from: str = Field(
        default="noreply@catalyticcomputing.com",
        description="From email address"
    )

    email_from_name: str = Field(
        default="Catalytic Computing",
        description="From name"
    )

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

    class Config:
        env_prefix = ""
        case_sensitive = False


class StripeConfig(BaseSettings):
    """Stripe payment configuration"""

    secret_key: Optional[SecretStr] = Field(
        default=None,
        description="Stripe secret key"
    )

    publishable_key: Optional[str] = Field(
        default=None,
        description="Stripe publishable key"
    )

    webhook_secret: Optional[SecretStr] = Field(
        default=None,
        description="Stripe webhook secret"
    )

    @property
    def is_test_mode(self) -> bool:
        """Check if using test mode keys"""
        if self.secret_key:
            return self.secret_key.get_secret_value().startswith("sk_test_")
        return True

    class Config:
        env_prefix = "STRIPE_"
        case_sensitive = False


class AppConfig(BaseSettings):
    """Application-level configuration"""

    name: str = Field(
        default="Catalytic Computing SaaS",
        description="Application name"
    )

    env: Environment = Field(
        default=Environment.DEVELOPMENT,
        description="Deployment environment"
    )

    debug: bool = Field(
        default=False,
        description="Enable debug mode"
    )

    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Logging level"
    )

    # URLs
    frontend_url: AnyHttpUrl = Field(
        default="http://localhost:3000",
        description="Frontend application URL"
    )

    backend_url: AnyHttpUrl = Field(
        default="http://localhost:8000",
        description="Backend API URL"
    )

    # Server settings
    host: str = Field(
        default="0.0.0.0",
        description="Server bind address"
    )

    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="Server port"
    )

    workers: int = Field(
        default=1,
        ge=1,
        le=16,
        description="Number of worker processes"
    )

    @validator("debug", always=True)
    def validate_debug(cls, v: bool, values: dict) -> bool:
        """Disable debug in production"""
        if "env" in values and values["env"] == Environment.PRODUCTION and v:
            logger.warning("Debug mode disabled in production")
            return False
        return v

    @validator("log_level", always=True)
    def validate_log_level(cls, v: LogLevel, values: dict) -> LogLevel:
        """Set appropriate log level for environment"""
        if "env" in values:
            env = values["env"]
            if env == Environment.PRODUCTION and v == LogLevel.DEBUG:
                logger.info("Setting log level to INFO for production")
                return LogLevel.INFO
        return v

    class Config:
        env_prefix = "APP_"
        case_sensitive = False


# ============================================================================
# MAIN SETTINGS CLASS
# ============================================================================


class Settings(BaseSettings):
    """
    Main application settings combining all configuration domains.
    
    This class aggregates all domain-specific configurations and provides
    a single point of access for the entire application.
    """

    # Domain configurations
    app: AppConfig = Field(default_factory=AppConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    cors: CORSConfig = Field(default_factory=CORSConfig)
    email: EmailConfig = Field(default_factory=EmailConfig)
    stripe: StripeConfig = Field(default_factory=StripeConfig)

    # Legacy environment variable support
    deployment_env: Environment = Field(
        default=Environment.DEVELOPMENT,
        description="Deployment environment (legacy)"
    )

    @validator("deployment_env", pre=True, always=True)
    def sync_deployment_env(cls, v):
        """Sync DEPLOYMENT_ENV with app.env for backward compatibility"""
        return v or Environment.DEVELOPMENT

    def __init__(self, **kwargs):
        """Initialize settings and log configuration summary"""
        super().__init__(**kwargs)
        self._log_configuration_summary()

    def _log_configuration_summary(self):
        """Log a summary of the loaded configuration"""
        logger.info("=" * 70)
        logger.info("Configuration Loaded Successfully")
        logger.info("=" * 70)
        logger.info(f"Environment: {self.app.env.value}")
        logger.info(f"Debug Mode: {self.app.debug}")
        logger.info(f"Log Level: {self.app.log_level.value}")
        logger.info(f"Database: {'SQLite' if self.database.is_sqlite else 'PostgreSQL'}")
        logger.info(f"Redis: {self.redis.host}:{self.redis.port}")
        logger.info(f"JWT Algorithm: {self.auth.jwt_algorithm}")
        logger.info(f"Security Level: {self.security.security_level.value}")
        logger.info(f"Rate Limiting: {'Enabled' if self.security.rate_limit_enabled else 'Disabled'}")
        logger.info(f"CORS Origins: {len(self.cors.allowed_origins)} configured")
        logger.info(f"Email Provider: {self.email.provider}")
        logger.info(f"Stripe: {'Test Mode' if self.stripe.is_test_mode else 'Live Mode'}")
        logger.info("=" * 70)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# ============================================================================
# SETTINGS INSTANCE
# ============================================================================


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    This function uses LRU cache to ensure settings are loaded only once
    and reused throughout the application lifecycle.
    
    Returns:
        Settings: Validated application settings
    """
    return Settings()


# Convenience function for backward compatibility
def get_config() -> Settings:
    """Alias for get_settings()"""
    return get_settings()
