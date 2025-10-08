"""
Security Initialization Module
Centralizes initialization of all security components for the Catalytic Computing Platform
"""

import os
import logging
from typing import Optional

from .redis_manager import get_redis
from .jwt_security import JWTSecurityManager, SecurityLevel
from .rate_limiting import AdvancedRateLimiter
from .input_validation import SecurityInputValidator

logger = logging.getLogger(__name__)


class SecurityManager:
    """
    Centralized security manager that initializes and coordinates all security components

    Usage:
        # Initialize with environment variables
        security_mgr = SecurityManager()

        # Or initialize with explicit configuration
        security_mgr = SecurityManager(
            private_key_path="./security/keys/jwt_private.pem",
            public_key_path="./security/keys/jwt_public.pem",
            security_level=SecurityLevel.ENHANCED
        )

        # Use components
        token = security_mgr.jwt.create_access_token(...)
        result = await security_mgr.rate_limiter.check_rate_limit(...)
        is_valid = security_mgr.validator.validate_email(email)
    """

    def __init__(
        self,
        private_key_path: Optional[str] = None,
        public_key_path: Optional[str] = None,
        security_level: Optional[SecurityLevel] = None,
        redis_host: Optional[str] = None,
        redis_port: Optional[int] = None,
        redis_password: Optional[str] = None,
        enable_ddos_protection: bool = True,
        access_token_expire_minutes: int = 15,
        refresh_token_expire_days: int = 7
    ):
        """
        Initialize security manager with all components

        Args:
            private_key_path: Path to JWT private key (default: from env JWT_PRIVATE_KEY_PATH)
            public_key_path: Path to JWT public key (default: from env JWT_PUBLIC_KEY_PATH)
            security_level: Security level (default: from env SECURITY_LEVEL or ENHANCED)
            redis_host: Redis host (default: from env REDIS_HOST or localhost)
            redis_port: Redis port (default: from env REDIS_PORT or 6379)
            redis_password: Redis password (default: from env REDIS_PASSWORD)
            enable_ddos_protection: Enable DDoS protection (default: True)
            access_token_expire_minutes: Access token expiration (default: 15)
            refresh_token_expire_days: Refresh token expiration (default: 7)
        """
        # Get configuration from environment or defaults
        self.private_key_path = private_key_path or os.getenv(
            "JWT_PRIVATE_KEY_PATH",
            "./security/keys/jwt_development_private.pem"
        )
        self.public_key_path = public_key_path or os.getenv(
            "JWT_PUBLIC_KEY_PATH",
            "./security/keys/jwt_development_public.pem"
        )

        # Parse security level from env if string
        if security_level is None:
            security_level_str = os.getenv("SECURITY_LEVEL", "enhanced").lower()
            security_level = {
                "basic": SecurityLevel.BASIC,
                "enhanced": SecurityLevel.ENHANCED,
                "strict": SecurityLevel.STRICT
            }.get(security_level_str, SecurityLevel.ENHANCED)

        self.security_level = security_level

        # Redis configuration
        self.redis_host = redis_host or os.getenv("REDIS_HOST", "localhost")
        self.redis_port = redis_port or int(os.getenv("REDIS_PORT", "6379"))
        self.redis_password = redis_password or os.getenv("REDIS_PASSWORD")

        # Initialize Redis connection manager
        logger.info("Initializing Redis connection manager...")
        try:
            self.redis = get_redis()
            if self.redis.is_available:
                logger.info(f"Redis connected at {self.redis_host}:{self.redis_port}")
            else:
                logger.warning("Redis unavailable - using in-memory fallback (NOT for production!)")
        except Exception as e:
            logger.error(f"Failed to initialize Redis: {e}")
            self.redis = None

        # Initialize JWT Security Manager
        logger.info("Initializing JWT security manager...")
        try:
            self.jwt = JWTSecurityManager(
                private_key_path=self.private_key_path,
                public_key_path=self.public_key_path,
                redis_client=self.redis,
                access_token_expire_minutes=access_token_expire_minutes,
                refresh_token_expire_days=refresh_token_expire_days,
                security_level=self.security_level
            )
            logger.info(f"JWT manager initialized with {self.security_level.value} security level")
        except Exception as e:
            logger.error(f"Failed to initialize JWT manager: {e}")
            raise

        # Initialize Rate Limiter
        logger.info("Initializing rate limiter...")
        try:
            self.rate_limiter = AdvancedRateLimiter(
                redis_client=self.redis,
                enable_ddos_protection=enable_ddos_protection
            )
            logger.info("Rate limiter initialized")
        except Exception as e:
            logger.error(f"Failed to initialize rate limiter: {e}")
            raise

        # Initialize Input Validator
        logger.info("Initializing input validator...")
        try:
            self.validator = SecurityInputValidator()
            logger.info("Input validator initialized")
        except Exception as e:
            logger.error(f"Failed to initialize input validator: {e}")
            raise

        logger.info("✓ Security Manager initialization complete")

    def health_check(self) -> dict:
        """
        Check health status of all security components

        Returns:
            dict: Health status of each component
        """
        return {
            "redis": {
                "available": self.redis.is_available if self.redis else False,
                "host": self.redis_host,
                "port": self.redis_port
            },
            "jwt": {
                "initialized": self.jwt is not None,
                "security_level": self.security_level.value,
                "using_redis": self.jwt.use_redis if self.jwt else False
            },
            "rate_limiter": {
                "initialized": self.rate_limiter is not None,
                "ddos_protection": self.rate_limiter.enable_ddos_protection if self.rate_limiter else False,
                "using_redis": self.rate_limiter.use_redis if self.rate_limiter else False
            },
            "validator": {
                "initialized": self.validator is not None
            }
        }

    def __repr__(self) -> str:
        return f"<SecurityManager security_level={self.security_level.value} redis_available={self.redis.is_available if self.redis else False}>"


# Singleton instance
_security_manager: Optional[SecurityManager] = None


def get_security_manager(
    private_key_path: Optional[str] = None,
    public_key_path: Optional[str] = None,
    security_level: Optional[SecurityLevel] = None,
    redis_host: Optional[str] = None,
    redis_port: Optional[int] = None,
    redis_password: Optional[str] = None,
    enable_ddos_protection: bool = True,
    access_token_expire_minutes: int = 15,
    refresh_token_expire_days: int = 7,
    force_reinit: bool = False
) -> SecurityManager:
    """
    Get or create singleton SecurityManager instance

    Args:
        Same as SecurityManager.__init__
        force_reinit: Force reinitialization even if instance exists (default: False)

    Returns:
        SecurityManager: Singleton instance

    Example:
        # Get singleton with default configuration
        security = get_security_manager()

        # Or with custom configuration (first call only)
        security = get_security_manager(
            security_level=SecurityLevel.STRICT,
            enable_ddos_protection=True
        )
    """
    global _security_manager

    if _security_manager is None or force_reinit:
        _security_manager = SecurityManager(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            security_level=security_level,
            redis_host=redis_host,
            redis_port=redis_port,
            redis_password=redis_password,
            enable_ddos_protection=enable_ddos_protection,
            access_token_expire_minutes=access_token_expire_minutes,
            refresh_token_expire_days=refresh_token_expire_days
        )

    return _security_manager


# Convenience function for FastAPI dependency injection
def get_security():
    """
    FastAPI dependency for injecting security manager

    Usage in FastAPI:
        from fastapi import Depends
        from security.application.security_init import get_security

        @app.post("/api/auth/login")
        async def login(
            credentials: LoginCredentials,
            security: SecurityManager = Depends(get_security)
        ):
            # Validate input
            if not security.validator.validate_email(credentials.email):
                raise HTTPException(400, "Invalid email")

            # Create token
            token = security.jwt.create_access_token(...)
            return {"access_token": token}
    """
    return get_security_manager()


# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Initialize security manager
    print("Initializing Security Manager...")
    security = get_security_manager()

    # Check health
    print("\nHealth Check:")
    import json
    print(json.dumps(security.health_check(), indent=2))

    # Test JWT creation
    print("\nTesting JWT creation...")
    try:
        token = security.jwt.create_access_token(
            subject="test_user",
            user_id="user_12345",
            roles=["user", "premium"],
            permissions=["read", "write"]
        )
        print(f"✓ Token created: {token[:50]}...")

        # Verify token
        payload = security.jwt.verify_token(token)
        print(f"✓ Token verified for user: {payload['user_id']}")

        # Revoke token
        security.jwt.revoke_token(token)
        print("✓ Token revoked")

        # Try to verify revoked token (should fail)
        try:
            security.jwt.verify_token(token)
            print("✗ ERROR: Revoked token was verified!")
        except Exception:
            print("✓ Revoked token correctly rejected")

    except Exception as e:
        print(f"✗ JWT test failed: {e}")

    # Test input validation
    print("\nTesting input validation...")
    print(f"✓ Valid email: {security.validator.validate_email('user@example.com')}")
    print(f"✓ Invalid email: {security.validator.validate_email('not-an-email')}")

    print("\n✓ All tests complete!")
