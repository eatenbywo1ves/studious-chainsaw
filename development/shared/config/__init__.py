"""
Shared Configuration Module

This module provides centralized, type-safe configuration management
for the entire application using Pydantic BaseSettings.

Quick Start:
    from shared.config import get_settings
    
    settings = get_settings()
    
    # Access configuration
    db_url = settings.database.url
    redis_host = settings.redis.host
    jwt_secret = settings.auth.jwt_secret_key.get_secret_value()

Features:
- Type-safe configuration with IDE autocomplete
- Automatic validation on startup
- Environment-specific settings
- Secure handling of secrets (never logged)
- Comprehensive documentation
"""

from .settings import (
    # Main settings
    Settings,
    get_settings,
    get_config,

    # Domain configurations
    AppConfig,
    DatabaseConfig,
    RedisConfig,
    AuthConfig,
    SecurityConfig,
    CORSConfig,
    EmailConfig,
    StripeConfig,

    # Enumerations
    Environment,
    SecurityLevel,
    LogLevel,
)

__all__ = [
    # Main settings
    "Settings",
    "get_settings",
    "get_config",

    # Domain configurations
    "AppConfig",
    "DatabaseConfig",
    "RedisConfig",
    "AuthConfig",
    "SecurityConfig",
    "CORSConfig",
    "EmailConfig",
    "StripeConfig",

    # Enumerations
    "Environment",
    "SecurityLevel",
    "LogLevel",
]
