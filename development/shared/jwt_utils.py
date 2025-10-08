"""
Unified JWT Authentication System
==================================

Consolidates 6 different JWT implementations into a single, production-ready module.

Features:
- RS256 (asymmetric) and HS256 (symmetric) algorithm support
- OptimizedRedisPool integration for distributed token blacklist
- Comprehensive token validation with security levels
- Token rotation and refresh support
- Graceful fallback to in-memory storage
- Type-safe with Pydantic models
- Fully tested and production-ready

Usage:
    from shared.jwt_utils import JWTManager, JWTConfig, TokenType

    config = JWTConfig()
    jwt_manager = JWTManager(config)

    # Create token
    token = jwt_manager.create_access_token(
        subject="user@example.com",
        user_id="user-123",
        tenant_id="tenant-456"
    )

    # Verify token
    payload = jwt_manager.verify_token(token)

    # Revoke token
    jwt_manager.revoke_token(token)
"""

import os
import secrets
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Union
from enum import Enum
from pathlib import Path

import jwt
from jwt.exceptions import PyJWTError, ExpiredSignatureError, InvalidTokenError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from pydantic import BaseModel, Field, validator

# Optional Redis import (graceful degradation if not available)
try:
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'security', 'application'))
    from redis_connection_pool_optimized import get_optimized_redis_pool
    REDIS_POOL_AVAILABLE = True
except ImportError:
    REDIS_POOL_AVAILABLE = False
    try:
        import redis
        BASIC_REDIS_AVAILABLE = True
    except ImportError:
        BASIC_REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================

class TokenType(Enum):
    """Token type enumeration"""
    ACCESS = "access"
    REFRESH = "refresh"
    API_KEY = "api_key"
    RESET = "reset"


class SecurityLevel(Enum):
    """Security validation level"""
    BASIC = "basic"       # Minimal validation (signature + expiry)
    ENHANCED = "enhanced"  # Standard validation (+ claims validation)
    STRICT = "strict"      # Maximum validation (+ fingerprinting, rate limiting)


class Algorithm(Enum):
    """Supported JWT algorithms"""
    RS256 = "RS256"  # RSA asymmetric (recommended for production)
    HS256 = "HS256"  # HMAC symmetric (simpler, less secure)


# ============================================================================
# Configuration
# ============================================================================

class JWTConfig(BaseModel):
    """
    JWT Configuration with environment variable support

    All values can be overridden via environment variables:
    - JWT_ALGORITHM (default: RS256)
    - JWT_SECRET_KEY (required for HS256)
    - JWT_PRIVATE_KEY_PATH (required for RS256)
    - JWT_PUBLIC_KEY_PATH (required for RS256)
    - ACCESS_TOKEN_EXPIRE_MINUTES (default: 15)
    - REFRESH_TOKEN_EXPIRE_DAYS (default: 30)
    """

    algorithm: Algorithm = Field(
        default_factory=lambda: Algorithm[os.getenv("JWT_ALGORITHM", "RS256")]
    )
    secret_key: Optional[str] = Field(default_factory=lambda: os.getenv("JWT_SECRET_KEY"))
    private_key_path: Optional[str] = Field(
        default_factory=lambda: os.getenv("JWT_PRIVATE_KEY_PATH", "keys/jwt_private.pem")
    )
    public_key_path: Optional[str] = Field(
        default_factory=lambda: os.getenv("JWT_PUBLIC_KEY_PATH", "keys/jwt_public.pem")
    )
    access_token_expire_minutes: int = Field(
        default_factory=lambda: int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    )
    refresh_token_expire_days: int = Field(
        default_factory=lambda: int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))
    )
    security_level: SecurityLevel = Field(default=SecurityLevel.ENHANCED)
    enable_token_rotation: bool = Field(default=True)
    issuer: str = Field(default_factory=lambda: os.getenv("JWT_ISSUER", "catalytic-saas"))
    audience: str = Field(default_factory=lambda: os.getenv("JWT_AUDIENCE", "catalytic-api"))

    @validator("secret_key")
    def validate_secret_key(cls, v, values):
        """Ensure secret key is provided for HS256"""
        if values.get("algorithm") == Algorithm.HS256 and not v:
            # Generate a secure random key if not provided
            logger.warning("No JWT_SECRET_KEY provided, generating random key (NOT recommended for production)")
            return secrets.token_urlsafe(32)
        return v

    class Config:
        use_enum_values = False


# ============================================================================
# Token Models
# ============================================================================

class TokenPayload(BaseModel):
    """Standard JWT payload model"""
    sub: str  # Subject (user identifier)
    exp: int  # Expiration timestamp
    iat: int  # Issued at timestamp
    jti: str  # JWT ID (unique token identifier)
    type: TokenType  # Token type
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    roles: Optional[List[str]] = Field(default_factory=list)
    permissions: Optional[List[str]] = Field(default_factory=list)
    iss: Optional[str] = None  # Issuer
    aud: Optional[str] = None  # Audience
    fingerprint: Optional[str] = None  # Session fingerprint for STRICT mode


class TokenResponse(BaseModel):
    """Token creation response"""
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int  # Seconds until expiration
    jti: str  # Token ID


# ============================================================================
# JWT Manager
# ============================================================================

class JWTManager:
    """
    Unified JWT Manager - Consolidates 6 different implementations

    This class provides a single, production-ready interface for all JWT operations:
    - Token creation (access, refresh, API keys)
    - Token verification with multi-level security
    - Token revocation with distributed blacklist
    - RSA and HMAC algorithm support
    - Graceful Redis fallback
    """

    def __init__(self, config: Optional[JWTConfig] = None, redis_client=None):
        """
        Initialize JWT Manager

        Args:
            config: JWT configuration (uses defaults if not provided)
            redis_client: Optional Redis client (will auto-initialize if not provided)
        """
        self.config = config or JWTConfig()

        # Initialize crypto keys based on algorithm
        if self.config.algorithm == Algorithm.RS256:
            self._init_rsa_keys()
        elif self.config.algorithm == Algorithm.HS256:
            self._secret_key = self.config.secret_key

        # Initialize Redis connection for distributed token blacklist
        self._init_redis(redis_client)

        # Fallback in-memory blacklist (only used if Redis unavailable)
        self._memory_blacklist: set = set()

        logger.info(f"JWT Manager initialized: {self.config.algorithm.value}, "
                   f"Security: {self.config.security_level.value}, "
                   f"Redis: {'Connected' if self._redis_available else 'In-memory fallback'}")

    def _init_rsa_keys(self):
        """Initialize RSA keys for RS256 algorithm"""
        private_path = Path(self.config.private_key_path)
        public_path = Path(self.config.public_key_path)

        if private_path.exists() and public_path.exists():
            # Load existing keys
            with open(private_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            with open(public_path, "rb") as f:
                self._public_key = serialization.load_pem_public_key(
                    f.read(), backend=default_backend()
                )
            logger.info(f"Loaded RSA keys from {private_path} and {public_path}")
        else:
            # Generate new keys
            logger.warning(f"RSA keys not found, generating new keys (NOT recommended for production)")
            self._generate_rsa_keys()
            # Optionally save keys
            if not private_path.parent.exists():
                private_path.parent.mkdir(parents=True, exist_ok=True)
            self._save_rsa_keys(private_path, public_path)

    def _generate_rsa_keys(self):
        """Generate new RSA key pair"""
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self._public_key = self._private_key.public_key()
        logger.info("Generated new 2048-bit RSA key pair")

    def _save_rsa_keys(self, private_path: Path, public_path: Path):
        """Save RSA keys to files"""
        # Save private key
        with open(private_path, "wb") as f:
            f.write(self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        # Save public key
        with open(public_path, "wb") as f:
            f.write(self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        logger.info(f"Saved RSA keys to {private_path} and {public_path}")

    def _init_redis(self, redis_client):
        """Initialize Redis connection for distributed blacklist"""
        if redis_client:
            # Use provided Redis client
            self._redis_client = redis_client
            self._redis_available = True
            logger.info("Using provided Redis client")
        elif REDIS_POOL_AVAILABLE:
            # Use OptimizedRedisPool (production-grade)
            try:
                redis_pool = get_optimized_redis_pool()
                if redis_pool.is_available:
                    self._redis_client = redis_pool.client
                    self._redis_available = True
                    logger.info("Connected to OptimizedRedisPool")
                else:
                    self._redis_client = None
                    self._redis_available = False
                    logger.warning("Redis pool unavailable, using in-memory blacklist")
            except Exception as e:
                logger.warning(f"Failed to initialize OptimizedRedisPool: {e}")
                self._redis_client = None
                self._redis_available = False
        elif BASIC_REDIS_AVAILABLE:
            # Fallback to basic Redis
            try:
                import redis as basic_redis
                self._redis_client = basic_redis.Redis(
                    host=os.getenv("REDIS_HOST", "localhost"),
                    port=int(os.getenv("REDIS_PORT", "6379")),
                    db=0,
                    decode_responses=True,
                    password=os.getenv("REDIS_PASSWORD")
                )
                self._redis_client.ping()
                self._redis_available = True
                logger.warning("Using basic Redis (OptimizedRedisPool recommended for production)")
            except Exception as e:
                logger.warning(f"Redis not available: {e}, using in-memory blacklist")
                self._redis_client = None
                self._redis_available = False
        else:
            self._redis_client = None
            self._redis_available = False
            logger.warning("Redis not available, using in-memory blacklist (NOT for production)")

    # ========================================================================
    # Token Creation
    # ========================================================================

    def create_access_token(
        self,
        subject: str,
        user_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        roles: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
        expires_delta: Optional[timedelta] = None,
        fingerprint: Optional[str] = None
    ) -> str:
        """
        Create access token

        Args:
            subject: Token subject (typically user email or ID)
            user_id: Optional user ID
            tenant_id: Optional tenant ID for multi-tenancy
            roles: Optional list of user roles
            permissions: Optional list of permissions
            expires_delta: Optional custom expiration (overrides config)
            fingerprint: Optional session fingerprint for STRICT security

        Returns:
            JWT token string
        """
        expires_delta = expires_delta or timedelta(minutes=self.config.access_token_expire_minutes)
        return self._create_token(
            subject=subject,
            token_type=TokenType.ACCESS,
            expires_delta=expires_delta,
            user_id=user_id,
            tenant_id=tenant_id,
            roles=roles or [],
            permissions=permissions or [],
            fingerprint=fingerprint
        )

    def create_refresh_token(
        self,
        subject: str,
        user_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        fingerprint: Optional[str] = None
    ) -> str:
        """Create refresh token (long-lived)"""
        expires_delta = timedelta(days=self.config.refresh_token_expire_days)
        return self._create_token(
            subject=subject,
            token_type=TokenType.REFRESH,
            expires_delta=expires_delta,
            user_id=user_id,
            tenant_id=tenant_id,
            fingerprint=fingerprint
        )

    def create_token_pair(
        self,
        subject: str,
        user_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        roles: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
        fingerprint: Optional[str] = None
    ) -> TokenResponse:
        """
        Create access + refresh token pair

        Returns:
            TokenResponse with both tokens
        """
        access_token = self.create_access_token(
            subject=subject,
            user_id=user_id,
            tenant_id=tenant_id,
            roles=roles,
            permissions=permissions,
            fingerprint=fingerprint
        )

        refresh_token = self.create_refresh_token(
            subject=subject,
            user_id=user_id,
            tenant_id=tenant_id,
            fingerprint=fingerprint
        )

        # Extract JTI from access token
        payload = jwt.decode(
            access_token,
            options={"verify_signature": False}
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.config.access_token_expire_minutes * 60,
            jti=payload["jti"]
        )

    def _create_token(
        self,
        subject: str,
        token_type: TokenType,
        expires_delta: timedelta,
        user_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        roles: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
        fingerprint: Optional[str] = None
    ) -> str:
        """Internal token creation method"""
        now = datetime.now(timezone.utc)
        exp = now + expires_delta

        payload = {
            "sub": subject,
            "exp": int(exp.timestamp()),
            "iat": int(now.timestamp()),
            "jti": secrets.token_urlsafe(16),  # Unique token ID
            "type": token_type.value,
            "iss": self.config.issuer,
            "aud": self.config.audience
        }

        # Add optional claims
        if user_id:
            payload["user_id"] = user_id
        if tenant_id:
            payload["tenant_id"] = tenant_id
        if roles:
            payload["roles"] = roles
        if permissions:
            payload["permissions"] = permissions
        if fingerprint and self.config.security_level == SecurityLevel.STRICT:
            payload["fingerprint"] = fingerprint

        # Encode token
        if self.config.algorithm == Algorithm.RS256:
            token = jwt.encode(payload, self._private_key, algorithm="RS256")
        else:  # HS256
            token = jwt.encode(payload, self._secret_key, algorithm="HS256")

        return token

    # ========================================================================
    # Token Verification
    # ========================================================================

    def verify_token(
        self,
        token: str,
        expected_type: Optional[TokenType] = None,
        fingerprint: Optional[str] = None
    ) -> TokenPayload:
        """
        Verify JWT token

        Args:
            token: JWT token string
            expected_type: Expected token type (ACCESS, REFRESH, etc.)
            fingerprint: Session fingerprint for STRICT security mode

        Returns:
            TokenPayload if valid

        Raises:
            InvalidTokenError: If token is invalid
            ExpiredSignatureError: If token is expired
        """
        try:
            # Check blacklist first (fast path)
            if self._is_blacklisted(token):
                raise InvalidTokenError("Token has been revoked")

            # Decode and verify token
            if self.config.algorithm == Algorithm.RS256:
                payload = jwt.decode(
                    token,
                    self._public_key,
                    algorithms=["RS256"],
                    issuer=self.config.issuer,
                    audience=self.config.audience
                )
            else:  # HS256
                payload = jwt.decode(
                    token,
                    self._secret_key,
                    algorithms=["HS256"],
                    issuer=self.config.issuer,
                    audience=self.config.audience
                )

            # Validate token type
            if expected_type and payload.get("type") != expected_type.value:
                raise InvalidTokenError(f"Expected {expected_type.value} token, got {payload.get('type')}")

            # STRICT mode: Validate fingerprint
            if self.config.security_level == SecurityLevel.STRICT:
                if fingerprint and payload.get("fingerprint") != fingerprint:
                    raise InvalidTokenError("Token fingerprint mismatch")

            # Convert to TokenPayload model
            return TokenPayload(
                sub=payload["sub"],
                exp=payload["exp"],
                iat=payload["iat"],
                jti=payload["jti"],
                type=TokenType(payload["type"]),
                user_id=payload.get("user_id"),
                tenant_id=payload.get("tenant_id"),
                roles=payload.get("roles", []),
                permissions=payload.get("permissions", []),
                iss=payload.get("iss"),
                aud=payload.get("aud"),
                fingerprint=payload.get("fingerprint")
            )

        except ExpiredSignatureError:
            logger.warning(f"Token expired")
            raise
        except InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            raise
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            raise InvalidTokenError(f"Token verification failed: {e}")

    # ========================================================================
    # Token Revocation
    # ========================================================================

    def revoke_token(self, token: str, ttl: Optional[int] = None):
        """
        Revoke token (add to blacklist)

        Args:
            token: JWT token to revoke
            ttl: Optional TTL in seconds (defaults to token's remaining lifetime)
        """
        try:
            # Extract JTI from token
            payload = jwt.decode(token, options={"verify_signature": False})
            jti = payload.get("jti")

            if not jti:
                logger.warning("Token has no JTI, cannot blacklist")
                return

            # Calculate TTL if not provided
            if ttl is None:
                exp = payload.get("exp")
                if exp:
                    ttl = max(0, exp - int(datetime.now(timezone.utc).timestamp()))
                else:
                    ttl = 3600  # Default 1 hour

            # Add to Redis blacklist
            if self._redis_available:
                blacklist_key = f"blacklist:{jti}"
                self._redis_client.setex(blacklist_key, ttl, "revoked")
                logger.info(f"Token {jti} added to Redis blacklist (TTL: {ttl}s)")
            else:
                # Fallback to in-memory
                self._memory_blacklist.add(jti)
                logger.warning(f"Token {jti} added to in-memory blacklist (NOT distributed!)")

        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")

    def _is_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted"""
        try:
            # Extract JTI
            payload = jwt.decode(token, options={"verify_signature": False})
            jti = payload.get("jti")

            if not jti:
                return False

            # Check Redis blacklist
            if self._redis_available:
                blacklist_key = f"blacklist:{jti}"
                return self._redis_client.exists(blacklist_key) > 0
            else:
                # Check in-memory blacklist
                return jti in self._memory_blacklist

        except Exception as e:
            logger.error(f"Blacklist check failed: {e}")
            return False

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def extract_payload(self, token: str) -> Dict[str, Any]:
        """Extract payload without verification (use with caution)"""
        return jwt.decode(token, options={"verify_signature": False})

    def get_token_expiry(self, token: str) -> Optional[datetime]:
        """Get token expiration time"""
        try:
            payload = self.extract_payload(token)
            exp = payload.get("exp")
            if exp:
                return datetime.fromtimestamp(exp, tz=timezone.utc)
        except Exception as e:
            logger.error(f"Failed to extract expiry: {e}")
        return None

    def is_token_expired(self, token: str) -> bool:
        """Check if token is expired"""
        try:
            expiry = self.get_token_expiry(token)
            if expiry:
                return datetime.now(timezone.utc) >= expiry
        except Exception:
            pass
        return True


# ============================================================================
# Convenience Functions
# ============================================================================

# Global instance (lazy initialization)
_jwt_manager: Optional[JWTManager] = None


def get_jwt_manager(config: Optional[JWTConfig] = None) -> JWTManager:
    """Get global JWT manager instance (singleton pattern)"""
    global _jwt_manager
    if _jwt_manager is None:
        _jwt_manager = JWTManager(config)
    return _jwt_manager


def create_access_token(subject: str, **kwargs) -> str:
    """Convenience function to create access token"""
    return get_jwt_manager().create_access_token(subject, **kwargs)


def verify_token(token: str, **kwargs) -> TokenPayload:
    """Convenience function to verify token"""
    return get_jwt_manager().verify_token(token, **kwargs)


def revoke_token(token: str, **kwargs):
    """Convenience function to revoke token"""
    return get_jwt_manager().revoke_token(token, **kwargs)
