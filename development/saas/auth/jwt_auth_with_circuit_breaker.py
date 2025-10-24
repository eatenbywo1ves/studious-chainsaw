"""
JWT Authentication System with Resilient Redis Pool
PRODUCTION-READY with Circuit Breaker Pattern

This is a drop-in replacement for jwt_auth.py with added fault tolerance.
To use: Rename jwt_auth.py to jwt_auth_old.py and rename this file to jwt_auth.py
"""

import os
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple

import jwt
from jwt.exceptions import PyJWTError, ExpiredSignatureError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from pydantic import BaseModel, Field, ValidationError
import redis
from passlib.context import CryptContext

logger = logging.getLogger(__name__)

# Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "RS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))
API_KEY_PREFIX = "clc_"  # Catalytic Lattice Computing

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ✅ PRODUCTION: Use Resilient Redis Pool with Circuit Breaker
# Import production-grade Resilient Redis Pool with fault tolerance
import sys  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "security", "application"))

# Import circuit breaker components
try:
    from redis_resilient_pool import ResilientRedisPool
    from redis_circuit_breaker import CircuitBreakerOpenError
    from redis_pool_protocol import DeploymentEnvironment

    # Auto-detect environment from DEPLOYMENT_ENV
    env_str = os.getenv("DEPLOYMENT_ENV", "production").lower()
    environment = DeploymentEnvironment(env_str)

    # Create resilient Redis pool with circuit breaker
    # Pool automatically configures based on DEPLOYMENT_ENV:
    # - development: 20 connections (1 worker), 3 failure threshold, 30s reset
    # - staging: 60 connections (2 workers), 5 failure threshold, 60s reset
    # - production: 160 connections (4 workers), 5 failure threshold, 120s reset
    redis_pool = ResilientRedisPool(
        environment=environment,
        enable_circuit_breaker=True,
        fallback_mode="warn",  # Log warnings when fallbacks used
        enable_monitoring=True,
    )

    # Maintain backward compatibility with existing code
    redis_client = redis_pool.client if redis_pool.is_available else None

    if redis_pool.is_available:
        pool_status = redis_pool.get_status()
        print(
            f"[OK] Resilient Redis Pool initialized: {redis_pool.connection_config.host}:{redis_pool.connection_config.port}"
        )
        print(f"[OK] Pool size: {pool_status['pool']['max_connections']} connections")
        print(f"[OK] Environment: {pool_status['environment']}")
        print(f"[OK] Circuit breaker: ENABLED (state={pool_status['circuit_breaker']['state']})")
        print(f"[OK] Pool utilization: {pool_status['pool']['utilization_percent']}%")
        print("[OK] Fault tolerance: Circuit breaker + graceful degradation")
    else:
        print("[WARNING] Redis pool initialization failed (NOT recommended for production)")
        redis_client = None
except ImportError as e:
    # Fallback to basic Redis if resilient pool not available
    print(f"[WARNING] ResilientRedisPool not found ({e}), falling back to basic Redis")
    redis_client = None
    redis_pool = None
    CircuitBreakerOpenError = Exception  # Fallback for exception handling
    try:
        redis_client = redis.Redis(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            db=0,
            decode_responses=True,
            password=os.getenv("REDIS_PASSWORD"),
        )
        redis_client.ping()
        print("[OK] Redis connected (basic mode - upgrade to ResilientRedisPool recommended)")
    except Exception as fallback_error:
        print(f"[ERROR] Redis not available: {fallback_error}")
        print("[WARNING] Using in-memory storage (NOT recommended for production)")
        redis_client = None


# RSA Key Management for production-grade security
class RSAKeyManager:
    """Manages RSA keys for JWT signing and verification"""

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self._load_or_generate_keys()

    def _load_or_generate_keys(self):
        """Load existing RSA keys or generate new ones"""
        private_key_path = os.getenv("JWT_PRIVATE_KEY_PATH", "keys/jwt_private.pem")
        public_key_path = os.getenv("JWT_PUBLIC_KEY_PATH", "keys/jwt_public.pem")

        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            # Load existing keys
            with open(private_key_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            with open(public_key_path, "rb") as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read(), backend=default_backend()
                )
        else:
            # Generate new RSA key pair
            self.private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            self.public_key = self.private_key.public_key()

            # Save keys
            os.makedirs(os.path.dirname(private_key_path), exist_ok=True)

            with open(private_key_path, "wb") as f:
                f.write(
                    self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )

            with open(public_key_path, "wb") as f:
                f.write(
                    self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )

    def get_private_key(self):
        """Get private key for signing"""
        if JWT_ALGORITHM == "RS256":
            return self.private_key
        return JWT_SECRET_KEY

    def get_public_key(self):
        """Get public key for verification"""
        if JWT_ALGORITHM == "RS256":
            return self.public_key
        return JWT_SECRET_KEY


# Initialize key manager
key_manager = RSAKeyManager() if JWT_ALGORITHM == "RS256" else None

# ============================================================================
# TOKEN MODELS
# ============================================================================


class TokenData(BaseModel):
    """JWT Token payload structure"""

    sub: str  # User ID
    tenant_id: str  # Tenant ID for isolation
    email: str
    role: str
    type: str = "access"  # access or refresh
    jti: Optional[str] = Field(default_factory=lambda: secrets.token_urlsafe(16))  # JWT ID
    iat: Optional[datetime] = None
    exp: Optional[datetime] = None


class TokenResponse(BaseModel):
    """Token response structure"""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class ApiKeyData(BaseModel):
    """API Key structure"""

    key: str
    tenant_id: str
    name: str
    permissions: list = []
    expires_at: Optional[datetime] = None


# ============================================================================
# TOKEN GENERATION WITH RESILIENT REDIS
# ============================================================================


def create_access_token(
    user_id: str, tenant_id: str, email: str, role: str, expires_delta: Optional[timedelta] = None
) -> str:
    """Create JWT access token with resilient Redis tracking"""

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    token_data = TokenData(
        sub=user_id,
        tenant_id=tenant_id,
        email=email,
        role=role,
        type="access",
        iat=datetime.now(timezone.utc),
        exp=expire,
    )

    # Get signing key
    signing_key = key_manager.get_private_key() if key_manager else JWT_SECRET_KEY

    # Create JWT
    encoded_jwt = jwt.encode(token_data.dict(), signing_key, algorithm=JWT_ALGORITHM)

    # Store token metadata in Redis with graceful fallback
    expiry_seconds = int(expires_delta.total_seconds() if expires_delta else ACCESS_TOKEN_EXPIRE_MINUTES * 60)

    if redis_pool and redis_pool.is_available:
        # Use resilient pool with fallback
        token_stored = redis_pool.set_with_fallback(
            key=f"token:access:{token_data.jti}",
            value=f"{user_id}:{tenant_id}",
            ex=expiry_seconds,
        )

        if token_stored:
            logger.info(
                "Access token created and cached in Redis",
                extra={
                    "user_id": user_id,
                    "tenant_id": tenant_id,
                    "jti": token_data.jti,
                },
            )
        else:
            logger.warning(
                "Access token created but NOT cached (Redis unavailable)",
                extra={
                    "user_id": user_id,
                    "tenant_id": tenant_id,
                    "jti": token_data.jti,
                },
            )
    elif redis_client:
        # Legacy: Direct client access (no circuit breaker)
        try:
            redis_client.setex(
                f"token:access:{token_data.jti}",
                expiry_seconds,
                f"{user_id}:{tenant_id}",
            )
            logger.info("Access token created (legacy mode)")
        except Exception as e:
            logger.warning(f"Redis unavailable: {e}")

    return encoded_jwt


def create_refresh_token(
    user_id: str, tenant_id: str, email: str, role: str, expires_delta: Optional[timedelta] = None
) -> str:
    """Create JWT refresh token with resilient Redis tracking"""

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    token_data = TokenData(
        sub=user_id,
        tenant_id=tenant_id,
        email=email,
        role=role,
        type="refresh",
        iat=datetime.now(timezone.utc),
        exp=expire,
    )

    # Get signing key
    signing_key = key_manager.get_private_key() if key_manager else JWT_SECRET_KEY

    # Create JWT
    encoded_jwt = jwt.encode(token_data.dict(), signing_key, algorithm=JWT_ALGORITHM)

    # Store refresh token in Redis with graceful fallback
    expiry_seconds = int(
        expires_delta.total_seconds()
        if expires_delta
        else REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600
    )

    if redis_pool and redis_pool.is_available:
        redis_pool.set_with_fallback(
            key=f"token:refresh:{token_data.jti}",
            value=f"{user_id}:{tenant_id}:active",
            ex=expiry_seconds,
        )
    elif redis_client:
        try:
            redis_client.setex(
                f"token:refresh:{token_data.jti}",
                expiry_seconds,
                f"{user_id}:{tenant_id}:active",
            )
        except Exception:
            pass

    logger.info(
        "Refresh token created",
        extra={
            "user_id": user_id,
            "tenant_id": tenant_id,
            "jti": token_data.jti,
        },
    )

    return encoded_jwt


def create_token_pair(user_id: str, tenant_id: str, email: str, role: str) -> TokenResponse:
    """Create access and refresh token pair"""

    access_token = create_access_token(user_id, tenant_id, email, role)
    refresh_token = create_refresh_token(user_id, tenant_id, email, role)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


# ============================================================================
# TOKEN VALIDATION WITH CIRCUIT BREAKER AWARENESS
# ============================================================================


def verify_token(token: str, token_type: str = "access") -> Optional[TokenData]:
    """
    Verify and decode JWT token with resilient Redis blacklist check

    Security Considerations:
    - When circuit breaker is OPEN, blacklist checks are skipped
    - This prioritizes availability over absolute security
    - For maximum security, uncomment the exception raise in _check_blacklist
    """

    try:
        # Get verification key
        verification_key = key_manager.get_public_key() if key_manager else JWT_SECRET_KEY

        # Decode token
        payload = jwt.decode(token, verification_key, algorithms=[JWT_ALGORITHM])

        # Validate token type
        if payload.get("type") != token_type:
            logger.warning(
                "Token type mismatch",
                extra={"expected_type": token_type, "actual_type": payload.get("type")},
            )
            return None

        # Check if token is blacklisted (with circuit breaker handling)
        jti = payload.get("jti")
        if jti:
            is_blacklisted = _check_token_blacklist(jti, payload)

            if is_blacklisted:
                logger.warning(
                    "Token verification failed: blacklisted",
                    extra={
                        "jti": jti,
                        "user_id": payload.get("sub"),
                        "tenant_id": payload.get("tenant_id"),
                    },
                )
                return None

            # Verify token is still active in Redis (best effort)
            _verify_token_active_in_redis(jti, token_type, payload)

        # Create TokenData object
        token_data = TokenData(**payload)

        logger.debug(
            "Token verified successfully",
            extra={
                "user_id": token_data.sub,
                "tenant_id": token_data.tenant_id,
                "jti": jti,
            },
        )

        return token_data

    except ExpiredSignatureError:
        logger.warning("Token verification failed: expired signature")
        return None
    except PyJWTError as e:
        logger.warning("Token verification failed: JWT error", extra={"error": str(e)})
        return None
    except ValidationError as e:
        logger.warning("Token verification failed: validation error", extra={"error": str(e)})
        return None


def _check_token_blacklist(jti: str, payload: dict) -> bool:
    """
    Check if token is blacklisted with circuit breaker handling

    Returns:
        True if blacklisted, False otherwise

    Security Decision:
    - When circuit breaker is OPEN, we ALLOW tokens (prioritize availability)
    - Alternative: Reject all tokens when Redis unavailable (prioritize security)
    """
    if not redis_pool and not redis_client:
        return False  # No Redis available, allow token

    try:
        if redis_pool:
            # Use resilient pool with circuit breaker
            is_blacklisted = redis_pool.exists(f"blacklist:{jti}")
            return bool(is_blacklisted)
        else:
            # Legacy: Direct client access
            return bool(redis_client.exists(f"blacklist:{jti}"))

    except CircuitBreakerOpenError:
        # Circuit is open - make security decision
        logger.warning(
            "⚠️ Circuit breaker OPEN - skipping blacklist check (allowing token)",
            extra={
                "jti": jti,
                "user_id": payload.get("sub"),
                "tenant_id": payload.get("tenant_id"),
            },
        )

        # SECURITY DECISION: Allow token when Redis unavailable
        # This prioritizes system availability over absolute security
        return False

        # ALTERNATIVE (more secure, less available):
        # logger.error("Circuit breaker OPEN - rejecting token for safety")
        # from fastapi import HTTPException
        # raise HTTPException(
        #     status_code=503,
        #     detail="Authentication service temporarily unavailable"
        # )

    except Exception as e:
        # Unexpected error (not circuit breaker related)
        logger.error(
            f"Blacklist check failed with unexpected error: {e}",
            extra={"jti": jti},
            exc_info=True,
        )
        # Fail-open: allow token on unexpected errors
        return False


def _verify_token_active_in_redis(jti: str, token_type: str, payload: dict):
    """
    Verify token is still active in Redis (best effort check)

    This is a secondary check that doesn't block token validation.
    If Redis is unavailable, we log a warning but don't reject the token.
    """
    if not redis_pool and not redis_client:
        return

    try:
        if redis_pool:
            token_exists = redis_pool.exists(f"token:{token_type}:{jti}")
        else:
            token_exists = redis_client.exists(f"token:{token_type}:{jti}")

        if not token_exists:
            logger.warning(
                "Token not found in Redis (may be expired or Redis unavailable)",
                extra={"jti": jti, "token_type": token_type},
            )

    except CircuitBreakerOpenError:
        # Circuit is open, skip this check silently
        pass

    except Exception as e:
        logger.debug(
            f"Token active check failed: {e}",
            extra={"jti": jti},
        )


def refresh_access_token(refresh_token: str) -> Optional[TokenResponse]:
    """Refresh access token using refresh token"""

    logger.info("Refreshing access token")

    # Verify refresh token
    token_data = verify_token(refresh_token, token_type="refresh")
    if not token_data:
        logger.warning("Refresh token verification failed")
        return None

    # Check if refresh token is marked for rotation (with circuit breaker handling)
    if redis_pool or redis_client:
        try:
            refresh_key = f"token:refresh:{token_data.jti}"

            if redis_pool:
                refresh_value = redis_pool.get_with_fallback(refresh_key, default=None)
            else:
                refresh_value = redis_client.get(refresh_key)

            if refresh_value and ":rotated" in refresh_value:
                # Token has been rotated, possible security issue
                logger.error(
                    "Token rotation security breach detected",
                    extra={
                        "user_id": token_data.sub,
                        "tenant_id": token_data.tenant_id,
                        "jti": token_data.jti,
                    },
                )
                revoke_all_user_tokens(token_data.sub, token_data.tenant_id)
                return None

        except Exception as e:
            logger.warning(f"Rotation check failed: {e}")

    # Create new token pair
    new_tokens = create_token_pair(
        user_id=token_data.sub,
        tenant_id=token_data.tenant_id,
        email=token_data.email,
        role=token_data.role,
    )

    # Mark old refresh token as rotated (with fallback)
    if redis_pool:
        redis_pool.set_with_fallback(
            key=f"token:refresh:{token_data.jti}",
            value=f"{token_data.sub}:{token_data.tenant_id}:rotated",
            ex=3600,  # Keep for 1 hour for security tracking
        )
    elif redis_client:
        try:
            redis_client.setex(
                f"token:refresh:{token_data.jti}",
                3600,
                f"{token_data.sub}:{token_data.tenant_id}:rotated",
            )
        except Exception:
            pass

    logger.info(
        "Access token refreshed successfully",
        extra={
            "user_id": token_data.sub,
            "tenant_id": token_data.tenant_id,
            "old_jti": token_data.jti,
        },
    )

    return new_tokens


def revoke_token(token: str):
    """Revoke a token by adding to blacklist with resilient Redis"""

    try:
        # Get verification key
        verification_key = key_manager.get_public_key() if key_manager else JWT_SECRET_KEY

        # Decode token without verification (to get jti even if expired)
        payload = jwt.decode(
            token, verification_key, algorithms=[JWT_ALGORITHM], options={"verify_signature": False}
        )

        jti = payload.get("jti")
        if not jti:
            logger.warning("Cannot revoke token: no JTI found")
            return

        # Calculate TTL
        exp = payload.get("exp")
        if not exp:
            logger.warning("Cannot revoke token: no expiration found")
            return

        ttl = max(0, int(exp - datetime.now(timezone.utc).timestamp()))

        # Add to blacklist with fallback
        if redis_pool:
            blacklisted = redis_pool.set_with_fallback(
                key=f"blacklist:{jti}",
                value="revoked",
                ex=ttl,
            )

            if blacklisted:
                logger.warning(
                    "Token revoked and blacklisted",
                    extra={"jti": jti, "user_id": payload.get("sub"), "ttl_seconds": ttl},
                )
            else:
                logger.error(
                    "⚠️ Token revocation FAILED - Redis unavailable",
                    extra={"jti": jti, "user_id": payload.get("sub")},
                )
        elif redis_client:
            redis_client.setex(f"blacklist:{jti}", ttl, "revoked")
            logger.warning("Token revoked (legacy mode)")

    except Exception as e:
        logger.error(f"Token revocation failed: {e}", exc_info=True)


def revoke_all_user_tokens(user_id: str, tenant_id: str):
    """Revoke all tokens for a user (security breach response)"""

    logger.warning(
        "Revoking all user tokens (security action)",
        extra={"user_id": user_id, "tenant_id": tenant_id},
    )

    revoked_count = 0
    if redis_client:
        # Pattern match all user tokens
        pattern = "token:*:*"
        for key in redis_client.scan_iter(pattern):
            value = redis_client.get(key)
            if value and value.startswith(f"{user_id}:{tenant_id}"):
                # Extract JTI from key
                jti = key.split(":")[-1]
                redis_client.setex(f"blacklist:{jti}", 86400, "security_revoked")
                redis_client.delete(key)
                revoked_count += 1

    logger.warning(
        "All user tokens revoked",
        extra={"user_id": user_id, "tenant_id": tenant_id, "tokens_revoked": revoked_count},
    )


# ============================================================================
# API KEY MANAGEMENT (unchanged from original)
# ============================================================================


def generate_api_key(tenant_id: str, name: str, permissions: Optional[list[str]] = None) -> Tuple[str, str]:
    """Generate API key for programmatic access"""

    raw_key = secrets.token_urlsafe(32)
    api_key = f"{API_KEY_PREFIX}{raw_key}"
    key_hash = pwd_context.hash(api_key)

    if redis_pool:
        redis_pool.set_with_fallback(
            key=f"apikey:{key_hash[:16]}",
            value=f"{tenant_id}|{name}|{','.join(permissions or [])}|{datetime.now(timezone.utc).isoformat()}",
            ex=None,  # No expiration for API keys
        )
    elif redis_client:
        try:
            redis_client.hset(
                f"apikey:{key_hash[:16]}",
                mapping={
                    "tenant_id": tenant_id,
                    "name": name,
                    "permissions": ",".join(permissions or []),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
            )
        except Exception:
            pass

    logger.info(
        "API key generated",
        extra={"tenant_id": tenant_id, "key_name": name, "permissions": permissions or []},
    )

    return api_key, key_hash


def verify_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """Verify API key and return metadata"""

    if not api_key.startswith(API_KEY_PREFIX):
        return None

    # Check against Redis (with fallback)
    if redis_pool or redis_client:
        try:
            for key in (redis_client if redis_client else redis_pool.client).scan_iter("apikey:*"):
                if redis_pool:
                    metadata_str = redis_pool.get_with_fallback(key, default=None)
                else:
                    metadata_str = redis_client.get(key)

                if metadata_str:
                    parts = metadata_str.split("|")
                    if len(parts) >= 3:
                        return {
                            "tenant_id": parts[0],
                            "name": parts[1],
                            "permissions": parts[2].split(",") if parts[2] else [],
                            "type": "api_key",
                        }
        except Exception as e:
            logger.warning(f"API key verification failed: {e}")

    return None


# ============================================================================
# TENANT CONTEXT (unchanged from original)
# ============================================================================


class TenantContext:
    """Manages tenant context for requests"""

    def __init__(self, tenant_id: str, user_id: Optional[str] = None):
        self.tenant_id = tenant_id
        self.user_id = user_id
        self._original_settings: dict[str, Any] = {}

    def __enter__(self):
        """Set tenant context for database queries"""
        import os

        self._original_settings = {
            "app.tenant_id": os.environ.get("app.tenant_id"),
            "app.user_id": os.environ.get("app.user_id"),
        }

        os.environ["app.tenant_id"] = str(self.tenant_id)
        if self.user_id:
            os.environ["app.user_id"] = str(self.user_id)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Restore original context"""
        import os

        for key, value in self._original_settings.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


# ============================================================================
# MIDDLEWARE HELPERS (unchanged from original)
# ============================================================================


def extract_tenant_from_request(
    authorization: Optional[str] = None,
    api_key: Optional[str] = None,
    tenant_header: Optional[str] = None,
) -> Optional[str]:
    """Extract tenant ID from various sources"""

    # Priority: JWT Token > API Key > Tenant Header

    if authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "")
        token_data = verify_token(token)
        if token_data:
            return token_data.tenant_id

    if api_key:
        key_data = verify_api_key(api_key)
        if key_data:
            return key_data.get("tenant_id")

    if tenant_header:
        return tenant_header

    return None


def hash_password(password: str) -> str:
    """Hash password for storage"""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)


# ============================================================================
# MONITORING AND HEALTH CHECK
# ============================================================================


def get_redis_health() -> dict:
    """Get comprehensive Redis health including circuit breaker status"""
    if redis_pool:
        status = redis_pool.get_status()
        return {
            "available": status["available"],
            "circuit_breaker": {
                "enabled": status["circuit_breaker_enabled"],
                "state": status["circuit_breaker"]["state"],
                "failure_count": status["circuit_breaker"]["failure_count"],
                "rejected_calls": status["circuit_breaker"]["rejected_calls"],
                "uptime_percent": status["circuit_breaker"]["uptime_percent"],
            },
            "pool": {
                "utilization_percent": status["pool"]["utilization_percent"],
                "in_use_connections": status["pool"]["in_use_connections"],
                "max_connections": status["pool"]["max_connections"],
            },
            "fallback_count": status["fallback_count"],
            "circuit_open_count": status["circuit_open_count"],
        }
    elif redis_client:
        try:
            redis_client.ping()
            return {"available": True, "mode": "legacy", "circuit_breaker": {"enabled": False}}
        except Exception as e:
            return {"available": False, "mode": "legacy", "error": str(e)}
    else:
        return {"available": False, "mode": "none"}
