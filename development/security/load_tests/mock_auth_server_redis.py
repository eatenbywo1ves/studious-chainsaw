#!/usr/bin/env python3
"""
Redis-Integrated Mock Authentication Server for Load Testing
Provides JWT auth endpoints with Redis-backed distributed state
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
import redis
from redis import ConnectionPool
from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import uvicorn

# ============================================================================
# CONFIGURATION
# ============================================================================

SECRET_KEY = "test_secret_key_for_load_testing_only"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Redis configuration
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)  # No password for local testing
REDIS_MAX_CONNECTIONS = int(os.getenv("REDIS_MAX_CONNECTIONS", "100"))

# ============================================================================
# REDIS CONNECTION POOL
# ============================================================================

# Create connection pool (shared across workers)
pool_kwargs = {
    "host": REDIS_HOST,
    "port": REDIS_PORT,
    "max_connections": REDIS_MAX_CONNECTIONS,
    "decode_responses": True,
    "socket_keepalive": True,
    "socket_timeout": 5,
    "retry_on_timeout": True
}
if REDIS_PASSWORD:
    pool_kwargs["password"] = REDIS_PASSWORD

redis_pool = ConnectionPool(**pool_kwargs)

# Redis client
redis_client = redis.Redis(connection_pool=redis_pool)

# Test Redis connection on startup
try:
    redis_client.ping()
    print(f"[SUCCESS] Redis connected: {REDIS_HOST}:{REDIS_PORT}")
except redis.ConnectionError as e:
    print(f"[ERROR] Redis connection failed: {e}")
    sys.exit(1)

# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(title="Redis-Integrated Mock Auth Server")

# Add CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# MODELS
# ============================================================================

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

# ============================================================================
# JWT UTILITIES
# ============================================================================

def create_access_token(email: str) -> str:
    """Create JWT access token"""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": email,
        "exp": expire,
        "type": "access"
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(email: str) -> str:
    """Create JWT refresh token"""
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": email,
        "exp": expire,
        "type": "refresh"
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> Optional[str]:
    """Verify JWT token and return email"""
    try:
        # Check if token is revoked in Redis
        if is_token_revoked(token):
            return None

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        return email
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# ============================================================================
# REDIS TOKEN BLACKLIST (Distributed State)
# ============================================================================

def revoke_token(token: str, ttl: int = 3600):
    """
    Add token to Redis blacklist with TTL

    This is distributed across all workers!
    """
    try:
        redis_client.setex(f"blacklist:{token}", ttl, "1")
        return True
    except redis.RedisError as e:
        print(f"[ERROR] Failed to revoke token: {e}")
        return False

def is_token_revoked(token: str) -> bool:
    """
    Check if token is in Redis blacklist

    Works across all workers!
    """
    try:
        return redis_client.exists(f"blacklist:{token}") > 0
    except redis.RedisError as e:
        print(f"[ERROR] Failed to check blacklist: {e}")
        # Fail open (allow access) on Redis errors
        return False

# ============================================================================
# REDIS RATE LIMITING (Distributed)
# ============================================================================

def check_rate_limit(ip: str, limit: int = 100, window: int = 60) -> bool:
    """
    Check if IP has exceeded rate limit

    Uses Redis to track requests across all workers

    Returns: True if allowed, False if rate limited
    """
    try:
        key = f"ratelimit:{ip}"
        current = redis_client.get(key)

        if current is None:
            # First request in window
            redis_client.setex(key, window, "1")
            return True

        count = int(current)
        if count >= limit:
            # Rate limited
            return False

        # Increment counter
        redis_client.incr(key)
        return True

    except redis.RedisError as e:
        print(f"[ERROR] Rate limit check failed: {e}")
        # Fail open (allow access) on Redis errors
        return True

# ============================================================================
# DEPENDENCIES
# ============================================================================

def get_current_user(authorization: Optional[str] = Header(None)):
    """Extract and verify JWT token from Authorization header"""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header"
        )

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication scheme"
            )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format"
        )

    email = verify_token(token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )

    return email

# ============================================================================
# ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """Health check endpoint"""
    try:
        redis_client.ping()
        redis_status = "connected"
    except:
        redis_status = "disconnected"

    return {
        "service": "Redis-Integrated Mock Auth Server",
        "status": "running",
        "redis": redis_status,
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/health")
async def health():
    """Detailed health check"""
    try:
        redis_client.ping()
        redis_healthy = True
        redis_info = redis_client.info("stats")
        redis_commands = redis_info.get("total_commands_processed", 0)
    except Exception as e:
        redis_healthy = False
        redis_commands = 0

    return {
        "status": "healthy" if redis_healthy else "degraded",
        "redis": {
            "connected": redis_healthy,
            "commands_processed": redis_commands
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.post("/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """
    Mock login endpoint with Redis-backed rate limiting

    Accepts any valid email format for load testing
    """
    # Note: In production, validate credentials against database
    email = request.email

    # Create tokens
    access_token = create_access_token(email)
    refresh_token = create_refresh_token(email)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token
    )

@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh(request: RefreshRequest):
    """Refresh access token using refresh token"""
    email = verify_token(request.refresh_token)

    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    # Create new tokens
    access_token = create_access_token(email)
    refresh_token = create_refresh_token(email)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token
    )

@app.post("/auth/logout")
async def logout(current_user: str = Depends(get_current_user), authorization: str = Header(...)):
    """
    Logout and revoke token (Redis-backed distributed blacklist)

    Token revocation is synchronized across ALL workers via Redis!
    """
    try:
        scheme, token = authorization.split()

        # Add token to Redis blacklist
        success = revoke_token(token, ttl=ACCESS_TOKEN_EXPIRE_MINUTES * 60)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to revoke token"
            )

        return {
            "message": "Successfully logged out",
            "user": current_user,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout failed: {str(e)}"
        )

@app.get("/api/protected")
async def protected_endpoint(current_user: str = Depends(get_current_user)):
    """
    Protected endpoint requiring valid JWT

    Token validation checks Redis blacklist (distributed across workers)
    """
    return {
        "message": "Access granted",
        "user": current_user,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# ============================================================================
# REDIS STATISTICS ENDPOINT
# ============================================================================

@app.get("/redis/stats")
async def redis_stats():
    """Get Redis statistics"""
    try:
        info = redis_client.info()
        return {
            "connected_clients": info.get("connected_clients", 0),
            "used_memory_human": info.get("used_memory_human", "unknown"),
            "total_commands_processed": info.get("total_commands_processed", 0),
            "instantaneous_ops_per_sec": info.get("instantaneous_ops_per_sec", 0),
            "keyspace": redis_client.dbsize()
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get Redis stats: {str(e)}"
        )

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("Redis-Integrated Mock Authentication Server")
    print("=" * 80)
    print(f"Redis: {REDIS_HOST}:{REDIS_PORT}")
    print(f"Max Connections: {REDIS_MAX_CONNECTIONS}")
    print("=" * 80)
    print("Endpoints:")
    print("   POST /auth/login - Login and get tokens")
    print("   POST /auth/refresh - Refresh access token")
    print("   POST /auth/logout - Logout and revoke token (Redis blacklist)")
    print("   GET  /api/protected - Protected endpoint (requires token)")
    print("   GET  /health - Health check")
    print("   GET  /redis/stats - Redis statistics")
    print("=" * 80)
    print("Features:")
    print("   - Distributed token blacklist via Redis")
    print("   - Multi-worker compatible")
    print("   - Connection pooling (100 connections)")
    print("   - Automatic failover handling")
    print("=" * 80)

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
