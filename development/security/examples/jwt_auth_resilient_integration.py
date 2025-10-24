"""
Example: Integrating Resilient Redis Pool with JWT Authentication
Demonstrates how to update jwt_auth.py to use circuit breaker pattern
"""

import os
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from jwt.exceptions import PyJWTError, ExpiredSignatureError
from pydantic import BaseModel, Field

# Import resilient Redis pool with circuit breaker
from security.application.redis_resilient_pool import (
    ResilientRedisPool,
    with_redis_fallback,
)
from security.application.redis_circuit_breaker import CircuitBreakerOpenError
from security.application.redis_pool_protocol import DeploymentEnvironment

logger = logging.getLogger(__name__)

# Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))

# ============================================================================
# RESILIENT REDIS INITIALIZATION
# ============================================================================

# Initialize resilient Redis pool with circuit breaker
redis_pool = ResilientRedisPool(
    environment=DeploymentEnvironment.PRODUCTION,
    enable_circuit_breaker=True,
    fallback_mode="warn",  # Log warnings on fallback
)

logger.info(f"✅ Resilient Redis pool initialized (circuit breaker: enabled)")


# ============================================================================
# TOKEN MODELS
# ============================================================================


class TokenData(BaseModel):
    """JWT Token payload structure"""

    sub: str  # User ID
    tenant_id: str
    email: str
    role: str
    type: str = "access"
    jti: Optional[str] = Field(default_factory=lambda: secrets.token_urlsafe(16))
    iat: Optional[datetime] = None
    exp: Optional[datetime] = None


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

    # Create JWT
    encoded_jwt = jwt.encode(token_data.dict(), JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    # Store token metadata in Redis with graceful fallback
    expiry_seconds = int(expires_delta.total_seconds() if expires_delta else ACCESS_TOKEN_EXPIRE_MINUTES * 60)

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

    return encoded_jwt


# ============================================================================
# TOKEN VALIDATION WITH CIRCUIT BREAKER AWARENESS
# ============================================================================


def verify_token(token: str, token_type: str = "access") -> Optional[TokenData]:
    """
    Verify and decode JWT token with resilient Redis blacklist check

    Security Considerations:
    - When circuit breaker is OPEN, blacklist checks are skipped
    - This prioritizes availability over security
    - For maximum security, raise exception when circuit is open
    """

    try:
        # Decode token
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])

        # Validate token type
        if payload.get("type") != token_type:
            logger.warning("Token type mismatch", extra={"expected": token_type, "actual": payload.get("type")})
            return None

        # Check if token is blacklisted (with circuit breaker handling)
        jti = payload.get("jti")
        if jti:
            is_blacklisted = _check_token_blacklist(jti, payload)

            if is_blacklisted:
                logger.warning(
                    "Token verification failed: blacklisted",
                    extra={"jti": jti, "user_id": payload.get("sub")},
                )
                return None

            # Verify token is still active in Redis (best effort)
            _verify_token_active_in_redis(jti, token_type)

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
        logger.warning(f"Token verification failed: {e}")
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
    try:
        # Check blacklist in Redis
        is_blacklisted = redis_pool.exists(f"blacklist:{jti}")
        return bool(is_blacklisted)

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


def _verify_token_active_in_redis(jti: str, token_type: str):
    """
    Verify token is still active in Redis (best effort check)

    This is a secondary check that doesn't block token validation.
    If Redis is unavailable, we log a warning but don't reject the token.
    """
    try:
        token_exists = redis_pool.exists(f"token:{token_type}:{jti}")

        if not token_exists:
            logger.warning(
                "Token not found in Redis (may be expired or Redis unavailable)",
                extra={"jti": jti, "token_type": token_type},
            )

    except CircuitBreakerOpenError:
        # Circuit is open, skip this check silently (already logged in blacklist check)
        pass

    except Exception as e:
        logger.debug(
            f"Token active check failed: {e}",
            extra={"jti": jti},
        )


# ============================================================================
# TOKEN REVOCATION WITH RESILIENT REDIS
# ============================================================================


def revoke_token(token: str):
    """Revoke a token by adding to blacklist with resilient Redis"""

    try:
        # Decode token without verification to get jti
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM], options={"verify_signature": False})

        jti = payload.get("jti")
        if not jti:
            logger.warning("Cannot revoke token: no JTI found")
            return

        # Calculate TTL (how long until token expires)
        exp = payload.get("exp")
        if not exp:
            logger.warning("Cannot revoke token: no expiration found")
            return

        ttl = max(0, int(exp - datetime.now(timezone.utc).timestamp()))

        # Add to blacklist with fallback
        blacklisted = redis_pool.set_with_fallback(
            key=f"blacklist:{jti}",
            value="revoked",
            ex=ttl,
        )

        if blacklisted:
            logger.warning(
                "Token revoked and blacklisted",
                extra={
                    "jti": jti,
                    "user_id": payload.get("sub"),
                    "ttl_seconds": ttl,
                },
            )
        else:
            logger.error(
                "⚠️ Token revocation FAILED - Redis unavailable",
                extra={
                    "jti": jti,
                    "user_id": payload.get("sub"),
                },
            )
            # Consider: Should we store revocation in database as fallback?

    except Exception as e:
        logger.error(f"Token revocation failed: {e}", exc_info=True)


# ============================================================================
# MONITORING AND HEALTH CHECK
# ============================================================================


def get_redis_health() -> dict:
    """Get comprehensive Redis health including circuit breaker status"""
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


# ============================================================================
# HELPER FUNCTIONS WITH DECORATORS
# ============================================================================


@with_redis_fallback(default_value=None, fallback_mode="warn")
def get_user_session(user_id: str) -> Optional[dict]:
    """Get user session from Redis with automatic fallback"""
    session_data = redis_pool.get(f"session:{user_id}")
    if session_data:
        import json

        return json.loads(session_data)
    return None


@with_redis_fallback(default_value=False, fallback_mode="silent")
def cache_user_permissions(user_id: str, permissions: dict) -> bool:
    """Cache user permissions in Redis with silent fallback"""
    import json

    return redis_pool.set_with_fallback(
        key=f"permissions:{user_id}",
        value=json.dumps(permissions),
        ex=3600,  # 1 hour
    )


# ============================================================================
# EXAMPLE USAGE
# ============================================================================


def example_usage():
    """Demonstrate resilient Redis integration"""

    print("=" * 60)
    print("Resilient Redis Pool with Circuit Breaker - Example")
    print("=" * 60)

    # 1. Check Redis health
    health = get_redis_health()
    print(f"\n📊 Redis Health:")
    print(f"   Available: {health['available']}")
    print(f"   Circuit State: {health['circuit_breaker']['state']}")
    print(f"   Pool Utilization: {health['pool']['utilization_percent']}%")
    print(f"   Uptime: {health['circuit_breaker']['uptime_percent']}%")

    # 2. Create access token
    print(f"\n🔐 Creating access token...")
    token = create_access_token(
        user_id="user123",
        tenant_id="tenant456",
        email="user@example.com",
        role="admin",
    )
    print(f"   Token: {token[:50]}...")

    # 3. Verify token
    print(f"\n✅ Verifying token...")
    token_data = verify_token(token)
    if token_data:
        print(f"   Valid! User: {token_data.sub}, Role: {token_data.role}")
    else:
        print(f"   Invalid or blacklisted")

    # 4. Revoke token
    print(f"\n🚫 Revoking token...")
    revoke_token(token)

    # 5. Verify revoked token
    print(f"\n❌ Verifying revoked token...")
    token_data = verify_token(token)
    if token_data:
        print(f"   WARNING: Revoked token still valid (Redis unavailable?)")
    else:
        print(f"   Correctly rejected (blacklisted or expired)")

    # 6. Final health check
    health = get_redis_health()
    print(f"\n📊 Final Redis Health:")
    print(f"   Fallback Count: {health['fallback_count']}")
    print(f"   Circuit Opens: {health['circuit_open_count']}")
    print(f"   Rejected Calls: {health['circuit_breaker']['rejected_calls']}")


if __name__ == "__main__":
    example_usage()
