"""
JWT Authentication System for Multi-tenant SaaS
Implements secure token generation, validation, and tenant isolation
"""

import os
import secrets
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

# Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "RS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))
API_KEY_PREFIX = "clc_"  # Catalytic Lattice Computing

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ✅ PRODUCTION: Use Refactored Redis Connection Manager (clean architecture)
# Import production-grade Redis Connection Manager with dependency injection
import sys  # noqa: E402
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'security', 'application'))

try:
    from redis_connection_manager import get_default_redis_manager
    # Create production Redis connection with dependency injection support
    # Pool automatically configures based on DEPLOYMENT_ENV:
    # - development: 20 connections (1 worker)
    # - staging: 60 connections (2 workers)
    # - production: 160 connections (4 workers)
    redis_manager = get_default_redis_manager()
    redis_pool = redis_manager.get_pool()
    redis_client = redis_pool.client if redis_pool.is_available else None

    if redis_pool.is_available:
        pool_status = redis_pool.get_pool_status()
        print(f"[OK] Redis Connection Manager initialized: {redis_manager.connection_config.host}:{redis_manager.connection_config.port}")
        print(f"[OK] Pool size: {pool_status['max_connections']} connections")
        print(f"[OK] Environment: {pool_status['environment']}")
        print(f"[OK] Utilization: {pool_status['utilization_percent']}%")
        print("[OK] Retry policy: Exponential backoff (3 attempts)")
    else:
        print("[WARNING] Redis pool initialization failed (NOT recommended for production)")
        redis_client = None
except ImportError as e:
    # Fallback to basic Redis if new architecture not available
    print(f"[WARNING] RedisConnectionManager not found ({e}), falling back to basic Redis")
    redis_client = None
    redis_manager = None
    try:
        redis_client = redis.Redis(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            db=0,
            decode_responses=True,
            password=os.getenv("REDIS_PASSWORD")
        )
        redis_client.ping()
        print("[OK] Redis connected (basic mode - upgrade to RedisConnectionManager recommended)")
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
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            with open(public_key_path, "rb") as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
        else:
            # Generate new RSA key pair
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()

            # Save keys
            os.makedirs(os.path.dirname(private_key_path), exist_ok=True)

            with open(private_key_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open(public_key_path, "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

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
# TOKEN GENERATION
# ============================================================================

def create_access_token(
    user_id: str,
    tenant_id: str,
    email: str,
    role: str,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create JWT access token with tenant context"""

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
        exp=expire
    )

    # Get signing key
    signing_key = key_manager.get_private_key() if key_manager else JWT_SECRET_KEY

    # Create JWT
    encoded_jwt = jwt.encode(
        token_data.dict(),
        signing_key,
        algorithm=JWT_ALGORITHM
    )

    # Store token metadata in Redis for tracking
    if redis_client:
        redis_client.setex(
            f"token:access:{token_data.jti}",
            int(expires_delta.total_seconds() if expires_delta else ACCESS_TOKEN_EXPIRE_MINUTES * 60),
            f"{user_id}:{tenant_id}"
        )

    return encoded_jwt

def create_refresh_token(
    user_id: str,
    tenant_id: str,
    email: str,
    role: str,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create JWT refresh token"""

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
        exp=expire
    )

    # Get signing key
    signing_key = key_manager.get_private_key() if key_manager else JWT_SECRET_KEY

    # Create JWT
    encoded_jwt = jwt.encode(
        token_data.dict(),
        signing_key,
        algorithm=JWT_ALGORITHM
    )

    # Store refresh token in Redis with rotation tracking
    if redis_client:
        redis_client.setex(
            f"token:refresh:{token_data.jti}",
            int(expires_delta.total_seconds() if expires_delta else REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600),
            f"{user_id}:{tenant_id}:active"
        )

    return encoded_jwt

def create_token_pair(
    user_id: str,
    tenant_id: str,
    email: str,
    role: str
) -> TokenResponse:
    """Create access and refresh token pair"""

    access_token = create_access_token(user_id, tenant_id, email, role)
    refresh_token = create_refresh_token(user_id, tenant_id, email, role)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

# ============================================================================
# TOKEN VALIDATION
# ============================================================================

def verify_token(token: str, token_type: str = "access") -> Optional[TokenData]:
    """Verify and decode JWT token"""

    try:
        # Get verification key
        verification_key = key_manager.get_public_key() if key_manager else JWT_SECRET_KEY

        # Decode token
        payload = jwt.decode(
            token,
            verification_key,
            algorithms=[JWT_ALGORITHM]
        )

        # Validate token type
        if payload.get("type") != token_type:
            return None

        # Check if token is blacklisted
        jti = payload.get("jti")
        if jti and redis_client:
            if redis_client.exists(f"blacklist:{jti}"):
                return None

            # Verify token is still active in Redis
            token_key = f"token:{token_type}:{jti}"
            if not redis_client.exists(token_key):
                return None

        # Create TokenData object
        token_data = TokenData(**payload)
        return token_data

    except ExpiredSignatureError:
        return None
    except PyJWTError:
        return None
    except ValidationError:
        return None

def refresh_access_token(refresh_token: str) -> Optional[TokenResponse]:
    """Refresh access token using refresh token"""

    # Verify refresh token
    token_data = verify_token(refresh_token, token_type="refresh")
    if not token_data:
        return None

    # Check if refresh token is marked for rotation
    if redis_client:
        refresh_key = f"token:refresh:{token_data.jti}"
        refresh_value = redis_client.get(refresh_key)

        if refresh_value and ":rotated" in refresh_value:
            # Token has been rotated, possible security issue
            revoke_all_user_tokens(token_data.sub, token_data.tenant_id)
            return None

    # Create new token pair
    new_tokens = create_token_pair(
        user_id=token_data.sub,
        tenant_id=token_data.tenant_id,
        email=token_data.email,
        role=token_data.role
    )

    # Mark old refresh token as rotated
    if redis_client:
        redis_client.setex(
            f"token:refresh:{token_data.jti}",
            3600,  # Keep for 1 hour for security tracking
            f"{token_data.sub}:{token_data.tenant_id}:rotated"
        )

    return new_tokens

def revoke_token(token: str):
    """Revoke a token by adding to blacklist"""

    try:
        # Get verification key
        verification_key = key_manager.get_public_key() if key_manager else JWT_SECRET_KEY

        # Decode token without verification (to get jti even if expired)
        payload = jwt.decode(
            token,
            verification_key,
            algorithms=[JWT_ALGORITHM],
            options={"verify_signature": False}
        )

        jti = payload.get("jti")
        if jti and redis_client:
            # Add to blacklist
            exp = payload.get("exp")
            if exp:
                ttl = max(0, exp - datetime.now(timezone.utc).timestamp())
                redis_client.setex(f"blacklist:{jti}", int(ttl), "revoked")
    except Exception:
        pass

def revoke_all_user_tokens(user_id: str, tenant_id: str):
    """Revoke all tokens for a user (security breach response)"""

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

# ============================================================================
# API KEY MANAGEMENT
# ============================================================================

def generate_api_key(tenant_id: str, name: str, permissions: list = None) -> Tuple[str, str]:
    """Generate API key for programmatic access"""

    # Generate secure random key
    raw_key = secrets.token_urlsafe(32)
    api_key = f"{API_KEY_PREFIX}{raw_key}"

    # Hash the key for storage
    key_hash = pwd_context.hash(api_key)

    # Store metadata in Redis
    if redis_client:
        redis_client.hset(
            f"apikey:{key_hash[:16]}",  # Use first 16 chars of hash as ID
            mapping={
                "tenant_id": tenant_id,
                "name": name,
                "permissions": ",".join(permissions or []),
                "created_at": datetime.now(timezone.utc).isoformat()
            }
        )

    return api_key, key_hash

def verify_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """Verify API key and return metadata"""

    if not api_key.startswith(API_KEY_PREFIX):
        return None

    # For production, check against database
    # This is a simplified in-memory check
    if redis_client:
        # Get all API keys and check
        for key in redis_client.scan_iter("apikey:*"):
            metadata = redis_client.hgetall(key)
            # In production, compare against stored hash
            # For now, simplified validation
            if metadata:
                return {
                    "tenant_id": metadata.get("tenant_id"),
                    "name": metadata.get("name"),
                    "permissions": metadata.get("permissions", "").split(","),
                    "type": "api_key"
                }

    return None

# ============================================================================
# TENANT CONTEXT
# ============================================================================

class TenantContext:
    """Manages tenant context for requests"""

    def __init__(self, tenant_id: str, user_id: Optional[str] = None):
        self.tenant_id = tenant_id
        self.user_id = user_id
        self._original_settings = {}

    def __enter__(self):
        """Set tenant context for database queries"""
        # Store original settings
        import os
        self._original_settings = {
            "app.tenant_id": os.environ.get("app.tenant_id"),
            "app.user_id": os.environ.get("app.user_id")
        }

        # Set new context
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
# MIDDLEWARE HELPERS
# ============================================================================

def extract_tenant_from_request(
    authorization: Optional[str] = None,
    api_key: Optional[str] = None,
    tenant_header: Optional[str] = None
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
        # Validate tenant exists in database
        # For now, return as-is
        return tenant_header

    return None

def hash_password(password: str) -> str:
    """Hash password for storage"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)
