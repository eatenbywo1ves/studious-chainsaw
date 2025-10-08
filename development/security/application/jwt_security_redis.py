"""
Enhanced JWT Security Implementation with Redis-backed Token Blacklist
FIXES CRITICAL SECURITY ISSUE: Distributed token blacklist for production
"""

import jwt
import time
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from enum import Enum
import logging
import redis.asyncio as redis

logger = logging.getLogger(__name__)

class TokenType(Enum):
    ACCESS = "access"
    REFRESH = "refresh"
    API_KEY = "api_key"
    RESET = "reset"

class SecurityLevel(Enum):
    BASIC = "basic"
    ENHANCED = "enhanced"
    STRICT = "strict"

class JWTSecurityManager:
    """
    Enhanced JWT Security Manager with Redis-backed token blacklist

    D3FEND Techniques Implemented:
    - D3-UAC (User Account Control)
    - D3-CH (Credential Hardening)
    - D3-ST (Session Timeout)
    """

    def __init__(
        self,
        private_key_path: str,
        public_key_path: str,
        redis_client: redis.Redis,  # ✅ REQUIRED: Redis client for distributed state
        algorithm: str = "RS256",
        access_token_expire_minutes: int = 15,
        refresh_token_expire_days: int = 7,
        security_level: SecurityLevel = SecurityLevel.ENHANCED
    ):
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.security_level = security_level

        # Load RSA keys
        self.private_key = self._load_private_key(private_key_path)
        self.public_key = self._load_public_key(public_key_path)

        # ✅ FIXED: Redis-backed token blacklist (distributed, persistent)
        self.redis_client = redis_client

        # Rate limiting storage (also Redis-backed)
        # Format: failed_attempts:{user_id} -> list of timestamps

        logger.info(f"JWT Security Manager initialized with {security_level.value} security level (Redis-backed)")

    def _load_private_key(self, key_path: str):
        """Load RSA private key from file"""
        try:
            with open(key_path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            return private_key
        except Exception as e:
            logger.error(f"Failed to load private key: {e}")
            raise

    def _load_public_key(self, key_path: str):
        """Load RSA public key from file"""
        try:
            with open(key_path, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            return public_key
        except Exception as e:
            logger.error(f"Failed to load public key: {e}")
            raise

    def create_access_token(
        self,
        subject: str,
        user_id: str,
        roles: List[str],
        permissions: List[str],
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a secure access token with comprehensive claims
        """
        now = datetime.now(timezone.utc)
        expire = now + timedelta(minutes=self.access_token_expire_minutes)

        # Generate unique JTI (JWT ID) for blacklist tracking
        jti = secrets.token_urlsafe(32)

        claims = {
            "sub": subject,
            "user_id": user_id,
            "roles": roles,
            "permissions": permissions,
            "type": TokenType.ACCESS.value,
            "iat": int(now.timestamp()),
            "exp": int(expire.timestamp()),
            "nbf": int(now.timestamp()),
            "jti": jti,  # ✅ Unique token ID for revocation
            "iss": "catalytic-computing-api",
            "aud": "catalytic-computing-services"
        }

        if additional_claims:
            claims.update(additional_claims)

        # Add security fingerprint
        if self.security_level == SecurityLevel.STRICT:
            claims["fingerprint"] = self._generate_fingerprint(user_id)

        token = jwt.encode(claims, self.private_key, algorithm=self.algorithm)
        logger.info(f"Access token created for user {user_id} with JTI {jti}")

        return token

    def create_refresh_token(
        self,
        user_id: str,
        device_id: Optional[str] = None
    ) -> str:
        """Create a refresh token"""
        now = datetime.now(timezone.utc)
        expire = now + timedelta(days=self.refresh_token_expire_days)

        jti = secrets.token_urlsafe(32)

        claims = {
            "user_id": user_id,
            "type": TokenType.REFRESH.value,
            "iat": int(now.timestamp()),
            "exp": int(expire.timestamp()),
            "jti": jti,
            "device_id": device_id or "unknown"
        }

        token = jwt.encode(claims, self.private_key, algorithm=self.algorithm)
        logger.info(f"Refresh token created for user {user_id}")

        return token

    async def verify_token(self, token: str, expected_type: TokenType = TokenType.ACCESS) -> Dict[str, Any]:
        """
        Verify and decode token with comprehensive checks

        ✅ FIXED: Checks Redis-backed blacklist
        """
        try:
            # Decode token (signature verification happens here)
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=[self.algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "require": ["exp", "iat", "jti"]
                }
            )

            # ✅ FIXED: Check Redis blacklist (distributed across all servers)
            jti = payload.get("jti")
            if jti and await self.is_token_blacklisted(jti):
                logger.warning(f"Blacklisted token attempted: {jti}")
                raise jwt.InvalidTokenError("Token has been revoked")

            # Verify token type
            token_type = payload.get("type")
            if token_type != expected_type.value:
                raise jwt.InvalidTokenError(f"Invalid token type. Expected {expected_type.value}, got {token_type}")

            # Verify issuer and audience (STRICT mode)
            if self.security_level == SecurityLevel.STRICT:
                if payload.get("iss") != "catalytic-computing-api":
                    raise jwt.InvalidTokenError("Invalid issuer")
                if payload.get("aud") != "catalytic-computing-services":
                    raise jwt.InvalidTokenError("Invalid audience")

            logger.info(f"Token verified successfully for user {payload.get('user_id')}")
            return payload

        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            raise
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {e}")
            raise
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            raise

    async def revoke_token(self, token: str) -> bool:
        """
        Revoke a token by adding to Redis blacklist

        ✅ FIXED: Uses Redis for distributed blacklist across all servers
        """
        try:
            # Decode to get JTI and expiration
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=[self.algorithm],
                options={"verify_signature": False}  # Just need JTI and exp
            )

            jti = payload.get("jti")
            exp = payload.get("exp")

            if not jti:
                logger.error("Token missing JTI, cannot revoke")
                return False

            # Calculate TTL (time until token expires)
            ttl_seconds = max(0, exp - int(time.time()))

            # ✅ Store in Redis with TTL matching token expiry
            # After expiry, blacklist entry automatically deleted
            await self.redis_client.setex(
                f"token:blacklist:{jti}",
                ttl_seconds,
                "revoked"
            )

            logger.info(f"Token {jti} revoked and added to Redis blacklist (TTL: {ttl_seconds}s)")
            return True

        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")
            return False

    async def is_token_blacklisted(self, jti: str) -> bool:
        """
        Check if token is in Redis blacklist

        ✅ FIXED: Checks distributed Redis blacklist
        """
        try:
            exists = await self.redis_client.exists(f"token:blacklist:{jti}")
            return bool(exists)
        except Exception as e:
            logger.error(f"Error checking blacklist: {e}")
            # Fail secure: if Redis is down, deny access
            return True

    async def revoke_all_user_tokens(self, user_id: str) -> int:
        """
        Revoke all tokens for a user (e.g., on password change)

        ✅ Uses Redis to track and revoke all user tokens
        """
        try:
            # Set a user-level revocation timestamp
            revocation_time = int(time.time())

            # Store in Redis (expires after max token lifetime)
            max_lifetime_seconds = self.refresh_token_expire_days * 24 * 60 * 60
            await self.redis_client.setex(
                f"user:revoked:{user_id}",
                max_lifetime_seconds,
                revocation_time
            )

            logger.info(f"All tokens revoked for user {user_id}")
            return revocation_time

        except Exception as e:
            logger.error(f"Failed to revoke user tokens: {e}")
            return 0

    async def check_user_revocation(self, payload: Dict[str, Any]) -> bool:
        """Check if token was issued before user-level revocation"""
        try:
            user_id = payload.get("user_id")
            token_iat = payload.get("iat")

            revocation_time_str = await self.redis_client.get(f"user:revoked:{user_id}")

            if revocation_time_str:
                revocation_time = int(revocation_time_str)
                if token_iat < revocation_time:
                    logger.warning(f"Token for user {user_id} issued before revocation")
                    return True

            return False

        except Exception as e:
            logger.error(f"Error checking user revocation: {e}")
            return True  # Fail secure

    async def record_failed_attempt(self, user_id: str) -> int:
        """
        Record failed authentication attempt in Redis

        ✅ Uses Redis for distributed rate limiting
        """
        try:
            key = f"auth:failed:{user_id}"

            # Add current timestamp to list
            pipe = self.redis_client.pipeline()
            pipe.lpush(key, int(time.time()))
            pipe.ltrim(key, 0, 9)  # Keep only last 10 attempts
            pipe.expire(key, 3600)  # 1 hour expiry
            await pipe.execute()

            # Get count of recent attempts (last 15 minutes)
            attempts = await self.redis_client.lrange(key, 0, -1)
            cutoff_time = time.time() - 900  # 15 minutes ago
            recent_attempts = sum(1 for ts in attempts if int(ts) > cutoff_time)

            logger.warning(f"Failed attempt for user {user_id}, recent attempts: {recent_attempts}")
            return recent_attempts

        except Exception as e:
            logger.error(f"Error recording failed attempt: {e}")
            return 0

    async def is_account_locked(self, user_id: str) -> bool:
        """Check if account is locked due to too many failed attempts"""
        try:
            attempts = await self.redis_client.lrange(f"auth:failed:{user_id}", 0, -1)
            cutoff_time = time.time() - 900  # 15 minutes
            recent_attempts = sum(1 for ts in attempts if int(ts) > cutoff_time)

            # Lock account after 5 failed attempts in 15 minutes
            if recent_attempts >= 5:
                logger.warning(f"Account locked for user {user_id} due to {recent_attempts} failed attempts")
                return True

            return False

        except Exception as e:
            logger.error(f"Error checking account lock: {e}")
            return False

    def _generate_fingerprint(self, user_id: str) -> str:
        """Generate security fingerprint (for STRICT mode)"""
        # In production, this would include browser/device fingerprint
        data = f"{user_id}:{int(time.time())}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def _get_token_ttl(self, payload: Dict[str, Any]) -> int:
        """Get remaining TTL for token"""
        exp = payload.get("exp", 0)
        return max(0, exp - int(time.time()))


# Example usage with Redis
async def example_usage():
    """Example: Using JWT Security Manager with Redis"""
    import redis.asyncio as redis

    # Initialize Redis connection
    redis_client = await redis.from_url("redis://localhost:6379")

    # Initialize JWT manager with Redis
    jwt_manager = JWTSecurityManager(
        private_key_path="security/keys/private_key.pem",
        public_key_path="security/keys/public_key.pem",
        redis_client=redis_client,  # ✅ Pass Redis client
        security_level=SecurityLevel.STRICT
    )

    # Create token
    token = jwt_manager.create_access_token(
        subject="john.doe@example.com",
        user_id="user_12345",
        roles=["admin"],
        permissions=["read", "write", "delete"]
    )
    print(f"Token created: {token[:50]}...")

    # Verify token (checks Redis blacklist)
    payload = await jwt_manager.verify_token(token)
    print(f"Token verified: {payload['user_id']}")

    # Revoke token (adds to Redis blacklist)
    revoked = await jwt_manager.revoke_token(token)
    print(f"Token revoked: {revoked}")

    # Try to verify revoked token (should fail)
    try:
        await jwt_manager.verify_token(token)
    except jwt.InvalidTokenError:
        print("✅ Revoked token correctly rejected")

    # Clean up
    await redis_client.close()


if __name__ == "__main__":
    import asyncio
    asyncio.run(example_usage())
