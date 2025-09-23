"""
Secure Configuration Management
Handles environment variables and sensitive configuration data
"""

import os
import json
from typing import Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass
from utilities.logging_utils import setup_service_logging, LogLevel


@dataclass
class DatabaseConfig:
    """Database configuration"""

    type: str = "sqlite"
    path: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    database: Optional[str] = None


@dataclass
class RedisConfig:
    """Redis configuration"""

    host: str = "localhost"
    port: int = 6379
    password: Optional[str] = None
    db: int = 0
    max_connections: int = 10


@dataclass
class SecurityConfig:
    """Security configuration"""

    jwt_secret: str
    api_key_secret: str
    encryption_key: Optional[str] = None
    tls_cert_path: Optional[str] = None
    tls_key_path: Optional[str] = None


class SecureConfigManager:
    """Secure configuration manager using environment variables"""

    def __init__(self, config_file: Optional[str] = None):
        self.logger = setup_service_logging("secure-config", LogLevel.INFO)
        self.config_file = config_file
        self._base_config = {}
        self._load_config()

    def _load_config(self):
        """Load base configuration from file"""
        if self.config_file and Path(self.config_file).exists():
            try:
                with open(self.config_file, "r") as f:
                    self._base_config = json.load(f)
            except Exception as e:
                self.logger.error(f"Failed to load config file {self.config_file}: {e}")
                self._base_config = {}

    def get_database_config(self, service_name: str = "default") -> DatabaseConfig:
        """Get database configuration for a service"""
        # Try environment variables first
        env_prefix = f"{service_name.upper().replace('-', '_')}_DB_"

        db_type = os.getenv(f"{env_prefix}TYPE", "sqlite")

        if db_type == "sqlite":
            # For SQLite, use secure path in data directory
            data_dir = os.getenv("DATA_DIR", "/data")
            db_path = os.getenv(f"{env_prefix}PATH", f"{data_dir}/{service_name}.db")
            return DatabaseConfig(type=db_type, path=db_path)

        elif db_type in ["postgresql", "mysql"]:
            return DatabaseConfig(
                type=db_type,
                host=os.getenv(f"{env_prefix}HOST", "localhost"),
                port=int(
                    os.getenv(
                        f"{env_prefix}PORT",
                        "5432" if db_type == "postgresql" else "3306",
                    )
                ),
                username=os.getenv(f"{env_prefix}USER"),
                password=os.getenv(f"{env_prefix}PASSWORD"),
                database=os.getenv(f"{env_prefix}NAME", service_name),
            )

        return DatabaseConfig()

    def get_redis_config(self, instance: str = "cache") -> RedisConfig:
        """Get Redis configuration for an instance"""
        env_prefix = f"REDIS_{instance.upper()}_"

        return RedisConfig(
            host=os.getenv(f"{env_prefix}HOST", "localhost"),
            port=int(os.getenv(f"{env_prefix}PORT", "6379")),
            password=os.getenv(f"{env_prefix}PASSWORD"),
            db=int(os.getenv(f"{env_prefix}DB", "0")),
            max_connections=int(os.getenv(f"{env_prefix}MAX_CONN", "10")),
        )

    def get_security_config(self) -> SecurityConfig:
        """Get security configuration"""
        jwt_secret = os.getenv("JWT_SECRET")
        api_key_secret = os.getenv("API_KEY_SECRET")

        if not jwt_secret:
            self.logger.warning("JWT_SECRET not set, using insecure default")
            jwt_secret = "insecure-default-jwt-secret-change-me"

        if not api_key_secret:
            self.logger.warning("API_KEY_SECRET not set, using insecure default")
            api_key_secret = "insecure-default-api-key-secret-change-me"

        return SecurityConfig(
            jwt_secret=jwt_secret,
            api_key_secret=api_key_secret,
            encryption_key=os.getenv("ENCRYPTION_KEY"),
            tls_cert_path=os.getenv("TLS_CERT_PATH"),
            tls_key_path=os.getenv("TLS_KEY_PATH"),
        )

    def get_service_port(self, service_name: str, default_port: int) -> int:
        """Get port for a service"""
        env_var = f"{service_name.upper().replace('-', '_')}_PORT"
        return int(os.getenv(env_var, str(default_port)))

    def get_service_host(
        self, service_name: str, default_host: str = "localhost"
    ) -> str:
        """Get host for a service"""
        env_var = f"{service_name.upper().replace('-', '_')}_HOST"
        return os.getenv(env_var, default_host)

    def get_base_path(self, path_type: str) -> str:
        """Get base paths for different types"""
        paths = {
            "data": os.getenv("DATA_DIR", "/data"),
            "logs": os.getenv("LOGS_DIR", "/logs"),
            "config": os.getenv("CONFIG_DIR", "/config"),
            "secrets": os.getenv("SECRETS_DIR", "/secrets"),
        }
        return paths.get(path_type, f"/{path_type}")

    def sanitize_config_for_logging(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive data from config for logging"""
        sensitive_keys = {
            "password",
            "secret",
            "key",
            "token",
            "credential",
            "auth",
            "private",
            "cert",
            "ssl",
            "tls",
        }

        def _sanitize_dict(d: Dict[str, Any]) -> Dict[str, Any]:
            sanitized = {}
            for key, value in d.items():
                key_lower = key.lower()

                # Check if key contains sensitive information
                if any(sensitive in key_lower for sensitive in sensitive_keys):
                    sanitized[key] = "[REDACTED]"
                elif isinstance(value, dict):
                    sanitized[key] = _sanitize_dict(value)
                elif isinstance(value, list):
                    sanitized[key] = [
                        _sanitize_dict(item) if isinstance(item, dict) else item
                        for item in value
                    ]
                else:
                    sanitized[key] = value

            return sanitized

        return _sanitize_dict(config)

    def get_secure_gateway_config(self) -> Dict[str, Any]:
        """Get secure API gateway configuration"""
        security_config = self.get_security_config()

        # Start with base config but remove sensitive data
        config = {
            "port": self.get_service_port("gateway", 9000),
            "host": self.get_service_host("gateway", "localhost"),
            "cors": {
                "enabled": os.getenv("CORS_ENABLED", "true").lower() == "true",
                "origins": os.getenv("CORS_ORIGINS", "*").split(","),
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "headers": ["*"],
            },
            "rate_limiting": {
                "enabled": True,
                "requests_per_minute": int(os.getenv("RATE_LIMIT_RPM", "100")),
                "burst_size": int(os.getenv("RATE_LIMIT_BURST", "20")),
                "enumeration_limit": int(
                    os.getenv("ENUMERATION_LIMIT", "10")
                ),  # New: specific limit for enumeration
            },
            "authentication": {
                "enabled": True,
                "jwt_secret": security_config.jwt_secret,
                "api_key_secret": security_config.api_key_secret,
                "jwt_expiry_hours": int(os.getenv("JWT_EXPIRY_HOURS", "24")),
                "require_https": os.getenv("REQUIRE_HTTPS", "false").lower() == "true",
            },
            "circuit_breaker": {
                "enabled": True,
                "failure_threshold": int(os.getenv("CB_FAILURE_THRESHOLD", "5")),
                "timeout_seconds": int(os.getenv("CB_TIMEOUT", "60")),
                "recovery_timeout": int(os.getenv("CB_RECOVERY_TIMEOUT", "30")),
            },
            "security": {
                "max_request_size": int(
                    os.getenv("MAX_REQUEST_SIZE", "1048576")
                ),  # 1MB
                "request_timeout": int(os.getenv("REQUEST_TIMEOUT", "30")),
                "log_sensitive_data": os.getenv("LOG_SENSITIVE_DATA", "false").lower()
                == "true",
            },
        }

        return config


# Global instance
_secure_config_manager: Optional[SecureConfigManager] = None


def get_secure_config_manager(config_file: Optional[str] = None) -> SecureConfigManager:
    """Get the global secure configuration manager"""
    global _secure_config_manager

    if _secure_config_manager is None:
        _secure_config_manager = SecureConfigManager(config_file)

    return _secure_config_manager


def get_sanitized_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Utility function to sanitize any config for logging"""
    manager = get_secure_config_manager()
    return manager.sanitize_config_for_logging(config)
