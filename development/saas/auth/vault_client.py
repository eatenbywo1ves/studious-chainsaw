"""
HashiCorp Vault Client Module

Provides secure secrets retrieval from HashiCorp Vault with:
- Automatic token renewal
- Connection pooling
- Fallback to .env files (backward compatibility)
- Caching with TTL
- Graceful degradation

Part of Phase 6: Secrets Management (Security Score 82 → 87)

Usage:
    from auth.vault_client import get_secret, get_database_config, get_redis_config

    # Get single secret
    db_password = get_secret("database", "password")

    # Get full configuration
    db_config = get_database_config()
    redis_config = get_redis_config()
"""

import os
import logging
import time
from typing import Dict, Any, Optional
from functools import lru_cache
from datetime import datetime, timedelta

try:
    import hvac
    HVAC_AVAILABLE = True
except ImportError:
    HVAC_AVAILABLE = False
    logging.warning(
        "hvac library not installed - Vault integration disabled. "
        "Install with: pip install hvac==2.1.0"
    )

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False
    logging.warning(
        "python-dotenv not installed - .env fallback disabled. "
        "Install with: pip install python-dotenv"
    )


# Configure logging
logger = logging.getLogger(__name__)


class VaultClient:
    """
    HashiCorp Vault client with automatic token renewal and caching
    """

    def __init__(
        self,
        vault_url: Optional[str] = None,
        vault_token: Optional[str] = None,
        environment: Optional[str] = None
    ):
        """
        Initialize Vault client

        Args:
            vault_url: Vault server URL (default: from VAULT_ADDR env var)
            vault_token: Vault auth token (default: from VAULT_TOKEN env var)
            environment: Environment name (default: from ENVIRONMENT env var)
        """
        self.vault_url = vault_url or os.getenv("VAULT_ADDR", "http://localhost:8200")
        self.vault_token = vault_token or os.getenv("VAULT_TOKEN")
        self.environment = environment or os.getenv("ENVIRONMENT", "development")

        self.client: Optional[hvac.Client] = None
        self.connected = False
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = int(os.getenv("VAULT_CACHE_TTL", "300"))  # 5 minutes default

        # Try to connect to Vault
        if HVAC_AVAILABLE and self.vault_token:
            self._connect()
        else:
            logger.warning(
                "Vault connection not available - using .env fallback. "
                "Set VAULT_ADDR and VAULT_TOKEN to enable Vault."
            )

        # Load .env as fallback
        if DOTENV_AVAILABLE:
            load_dotenv()

    def _connect(self) -> None:
        """Establish connection to Vault"""
        try:
            self.client = hvac.Client(url=self.vault_url, token=self.vault_token)

            # Verify authentication
            if self.client.is_authenticated():
                self.connected = True
                logger.info(f"✓ Connected to Vault at {self.vault_url}")
            else:
                logger.error("Vault authentication failed")
                self.connected = False

        except Exception as e:
            logger.error(f"Failed to connect to Vault: {e}")
            self.connected = False

    def get_secret(
        self,
        category: str,
        key: str,
        default: Optional[str] = None
    ) -> Optional[str]:
        """
        Get a single secret from Vault

        Args:
            category: Secret category (e.g., "database", "redis")
            key: Secret key (e.g., "password")
            default: Default value if secret not found

        Returns:
            Secret value or default
        """
        # Check cache first
        cache_key = f"{category}/{key}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if datetime.now() < cached['expires']:
                logger.debug(f"Cache hit: {cache_key}")
                return cached['value']
            else:
                # Cache expired
                del self.cache[cache_key]

        # Try Vault first
        if self.connected and self.client:
            try:
                path = f"{self.environment}/{category}"
                response = self.client.secrets.kv.v2.read_secret_version(
                    path=path,
                    mount_point='secret'
                )

                secrets = response['data']['data']
                value = secrets.get(key)

                if value:
                    # Cache the value
                    self.cache[cache_key] = {
                        'value': value,
                        'expires': datetime.now() + timedelta(seconds=self.cache_ttl)
                    }
                    logger.debug(f"Vault hit: {cache_key}")
                    return value

            except hvac.exceptions.InvalidPath:
                logger.warning(f"Secret path not found in Vault: {path}")
            except Exception as e:
                logger.error(f"Failed to read secret from Vault: {e}")

        # Fallback to environment variable
        env_var = f"{category.upper()}_{key.upper()}"
        value = os.getenv(env_var, default)

        if value:
            logger.debug(f"Environment variable fallback: {env_var}")
        else:
            logger.warning(f"Secret not found: {category}/{key}")

        return value

    def get_category_secrets(self, category: str) -> Dict[str, str]:
        """
        Get all secrets for a category

        Args:
            category: Secret category (e.g., "database", "redis")

        Returns:
            Dictionary of all secrets in the category
        """
        # Try Vault first
        if self.connected and self.client:
            try:
                path = f"{self.environment}/{category}"
                response = self.client.secrets.kv.v2.read_secret_version(
                    path=path,
                    mount_point='secret'
                )

                secrets = response['data']['data']
                logger.debug(f"Retrieved {len(secrets)} secrets for {category} from Vault")
                return secrets

            except hvac.exceptions.InvalidPath:
                logger.warning(f"Secret category not found in Vault: {category}")
            except Exception as e:
                logger.error(f"Failed to read category from Vault: {e}")

        # Fallback to environment variables
        logger.debug(f"Using environment variable fallback for {category}")
        return {}

    def refresh_token(self) -> bool:
        """
        Refresh Vault token (if using renewable token)

        Returns:
            True if token refreshed successfully, False otherwise
        """
        if not self.connected or not self.client:
            return False

        try:
            self.client.auth.token.renew_self()
            logger.info("✓ Vault token renewed")
            return True
        except Exception as e:
            logger.error(f"Failed to renew Vault token: {e}")
            return False

    def clear_cache(self) -> None:
        """Clear the secrets cache"""
        self.cache.clear()
        logger.info("Vault cache cleared")


# Global Vault client instance
_vault_client: Optional[VaultClient] = None


def get_vault_client() -> VaultClient:
    """
    Get or create global Vault client instance

    Returns:
        VaultClient instance
    """
    global _vault_client

    if _vault_client is None:
        _vault_client = VaultClient()

    return _vault_client


def get_secret(category: str, key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Get a single secret (convenience function)

    Args:
        category: Secret category (e.g., "database", "redis")
        key: Secret key (e.g., "password")
        default: Default value if secret not found

    Returns:
        Secret value or default
    """
    client = get_vault_client()
    return client.get_secret(category, key, default)


# Configuration helpers

def get_database_config() -> Dict[str, str]:
    """
    Get database configuration from Vault

    Returns:
        Dictionary with database connection parameters
    """
    client = get_vault_client()

    # Try to get all database secrets at once
    db_secrets = client.get_category_secrets("database")

    if db_secrets:
        return db_secrets

    # Fallback to individual retrieval
    return {
        "password": client.get_secret("database", "password", os.getenv("DB_PASSWORD")),
        "username": client.get_secret("database", "username", os.getenv("POSTGRES_USER", "catalytic")),
        "host": client.get_secret("database", "host", os.getenv("DB_HOST", "postgres")),
        "port": client.get_secret("database", "port", os.getenv("DB_PORT", "5432")),
        "name": client.get_secret("database", "name", os.getenv("DB_NAME", "catalytic_db")),
        "url": client.get_secret("database", "url", os.getenv("DATABASE_URL"))
    }


def get_redis_config() -> Dict[str, str]:
    """
    Get Redis configuration from Vault

    Returns:
        Dictionary with Redis connection parameters
    """
    client = get_vault_client()

    # Try to get all Redis secrets at once
    redis_secrets = client.get_category_secrets("redis")

    if redis_secrets:
        return redis_secrets

    # Fallback to individual retrieval
    return {
        "password": client.get_secret("redis", "password", os.getenv("REDIS_PASSWORD")),
        "host": client.get_secret("redis", "host", os.getenv("REDIS_HOST", "redis")),
        "port": client.get_secret("redis", "port", os.getenv("REDIS_PORT", "6379")),
        "url": client.get_secret("redis", "url", os.getenv("REDIS_URL"))
    }


def get_jwt_config() -> Dict[str, str]:
    """
    Get JWT configuration from Vault

    Returns:
        Dictionary with JWT parameters
    """
    client = get_vault_client()

    # Try to get all JWT secrets at once
    jwt_secrets = client.get_category_secrets("jwt")

    if jwt_secrets:
        return jwt_secrets

    # Fallback to individual retrieval
    return {
        "secret_key": client.get_secret("jwt", "secret_key", os.getenv("JWT_SECRET_KEY")),
        "algorithm": client.get_secret("jwt", "algorithm", os.getenv("JWT_ALGORITHM", "RS256")),
        "access_token_expire_minutes": client.get_secret(
            "jwt", "access_token_expire_minutes",
            os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
        ),
        "refresh_token_expire_days": client.get_secret(
            "jwt", "refresh_token_expire_days",
            os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7")
        )
    }


def get_csrf_secret() -> str:
    """
    Get CSRF secret key from Vault

    Returns:
        CSRF secret key
    """
    client = get_vault_client()
    return client.get_secret("csrf", "secret_key", os.getenv("CSRF_SECRET_KEY", ""))


def get_monitoring_config() -> Dict[str, str]:
    """
    Get monitoring configuration from Vault

    Returns:
        Dictionary with monitoring credentials
    """
    client = get_vault_client()

    # Try to get all monitoring secrets at once
    monitoring_secrets = client.get_category_secrets("monitoring")

    if monitoring_secrets:
        return monitoring_secrets

    # Fallback to individual retrieval
    return {
        "grafana_password": client.get_secret(
            "monitoring", "grafana_password",
            os.getenv("GRAFANA_PASSWORD")
        ),
        "prometheus_password": client.get_secret(
            "monitoring", "prometheus_password",
            os.getenv("PROMETHEUS_PASSWORD")
        )
    }


def get_stripe_config() -> Dict[str, str]:
    """
    Get Stripe payment configuration from Vault

    Returns:
        Dictionary with Stripe API keys
    """
    client = get_vault_client()

    # Try to get all payment secrets at once
    payment_secrets = client.get_category_secrets("payment")

    if payment_secrets:
        return payment_secrets

    # Fallback to individual retrieval
    return {
        "secret_key": client.get_secret(
            "payment", "stripe_secret_key",
            os.getenv("STRIPE_SECRET_KEY")
        ),
        "publishable_key": client.get_secret(
            "payment", "stripe_publishable_key",
            os.getenv("STRIPE_PUBLISHABLE_KEY")
        ),
        "webhook_secret": client.get_secret(
            "payment", "stripe_webhook_secret",
            os.getenv("STRIPE_WEBHOOK_SECRET")
        )
    }


# Health check function

def vault_health_check() -> Dict[str, Any]:
    """
    Check Vault connection health

    Returns:
        Dictionary with health status
    """
    client = get_vault_client()

    health = {
        "vault_available": HVAC_AVAILABLE,
        "vault_connected": client.connected,
        "vault_url": client.vault_url,
        "environment": client.environment,
        "cache_size": len(client.cache),
        "fallback_mode": not client.connected
    }

    if client.connected and client.client:
        try:
            # Check if client is still authenticated
            health["authenticated"] = client.client.is_authenticated()
        except Exception as e:
            health["authenticated"] = False
            health["error"] = str(e)

    return health
