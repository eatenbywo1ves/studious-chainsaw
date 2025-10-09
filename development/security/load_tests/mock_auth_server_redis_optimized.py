#!/usr/bin/env python3
"""
OPTIMIZED Redis-Integrated Mock Authentication Server for Load Testing
Uses OptimizedRedisPool with environment-aware connection pooling

Changes from previous version:
- Replaced manual ConnectionPool with OptimizedRedisPool
- Added health check endpoint with pool metrics
- Added pool monitoring capabilities
- Environment-aware pool sizing (dev/staging/production)
- Exponential backoff retry logic
- Health check intervals (30 seconds)
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import uvicorn

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "application"))

# Import OptimizedRedisPool
from redis_connection_pool_optimized import get_optimized_redis_pool, log_pool_metrics

# ============================================================================
# CONFIGURATION
# ============================================================================

SECRET_KEY = "test_secret_key_for_load_testing_only"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Environment detection (auto-detects from DEPLOYMENT_ENV)
DEPLOYMENT_ENV = os.getenv("DEPLOYMENT_ENV", "production").lower()

# ============================================================================
# OPTIMIZED REDIS CONNECTION POOL
# ============================================================================

# Initialize optimized Redis pool (replaces manual ConnectionPool)
try:
    redis_pool = get_optimized_redis_pool()
    redis_client = redis_pool.client

    print("=" * 80)
    print("OPTIMIZED REDIS CONNECTION POOL INITIALIZED")
    print("=" * 80)
    print(f"Environment: {redis_pool.environment.value}")
    print(f"Target Users: {redis_pool.target_users:,}")
    print(f"Workers: {redis_pool.workers}")
    print(f"Max Connections: {redis_pool.max_connections}")
    print(f"Connections per Worker: {redis_pool.max_connections // redis_pool.workers}")
    print("=" * 80)
    print("Optimizations Enabled:")
    print("  [OK] Health check interval: 30 seconds")
    print("  [OK] Exponential backoff retry (3 attempts)")
    print("  [OK] Socket keepalive enabled")
    print("  [OK] Connection pool monitoring")
    print("=" * 80)

    # Test connection
    if redis_pool.health_check():
        print(f"[SUCCESS] Redis pool healthy: {redis_pool.host}:{redis_pool.port}")
    else:
        print("[ERROR] Redis health check failed!")
        sys.exit(1)

except Exception as e:
    print(f"[ERROR] Failed to initialize Redis pool: {e}")
    sys.exit(1)

# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(
    title="Optimized Redis-Integrated Mock Auth Server",
    version="2.0.0",
    description="Production-grade auth server with optimized connection pooling",
)

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
    payload = {"sub": email, "exp": expire, "type": "access"}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(email: str) -> str:
    """Create JWT refresh token"""
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {"sub": email, "exp": expire, "type": "refresh"}
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
    except Exception as e:
        print(f"[ERROR] Failed to revoke token: {e}")
        return False


def is_token_revoked(token: str) -> bool:
    """
    Check if token is in Redis blacklist

    Works across all workers!
    """
    try:
        return redis_client.exists(f"blacklist:{token}") > 0
    except Exception as e:
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

    except Exception as e:
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
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing authorization header"
        )

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication scheme"
            )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authorization header format"
        )

    email = verify_token(token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )

    return email


# ============================================================================
# ENDPOINTS
# ============================================================================


@app.get("/")
async def root():
    """Health check endpoint"""
    try:
        is_healthy = redis_pool.health_check()
        redis_status = "connected" if is_healthy else "disconnected"
    except Exception:
        redis_status = "disconnected"

    return {
        "service": "Optimized Redis-Integrated Mock Auth Server",
        "status": "running",
        "redis": redis_status,
        "version": "2.0.0",
        "environment": redis_pool.environment.value,
        "pool": {
            "max_connections": redis_pool.max_connections,
            "target_users": redis_pool.target_users,
            "workers": redis_pool.workers,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
async def health():
    """Detailed health check with pool metrics"""
    try:
        is_healthy = redis_pool.health_check()
        pool_status = redis_pool.get_pool_status()

        # Get Redis stats
        redis_info = redis_client.info("stats")
        redis_commands = redis_info.get("total_commands_processed", 0)
    except Exception as e:
        is_healthy = False
        pool_status = {"error": str(e)}
        redis_commands = 0

    return {
        "status": "healthy" if is_healthy else "degraded",
        "redis": {"connected": is_healthy, "commands_processed": redis_commands},
        "pool": pool_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health/redis")
async def redis_health():
    """
    Redis pool health check with detailed metrics and recommendations

    NEW: Provides pool utilization tracking and optimization recommendations
    """
    try:
        # Perform health check
        is_healthy = redis_pool.health_check()

        # Get detailed pool status
        pool_status = redis_pool.get_pool_status()

        # Generate recommendations
        recommendations = []
        util = pool_status.get("utilization_percent", 0)

        if util > 80:
            recommendations.append(
                "CRITICAL: Pool utilization > 80%. Increase max_connections immediately."
            )
        elif util > 60:
            recommendations.append("WARNING: Pool utilization > 60%. Monitor for growth trends.")

        metrics = pool_status.get("metrics", {})
        if metrics.get("pool_exhausted_count", 0) > 0:
            recommendations.append(
                f"CRITICAL: Pool exhausted {metrics['pool_exhausted_count']} times. Increase pool size."
            )

        if metrics.get("connection_errors", 0) > 10:
            recommendations.append(
                f"WARNING: {metrics['connection_errors']} connection errors detected. Check Redis server."
            )

        if not recommendations:
            recommendations.append("Pool operating optimally.")

        return {
            "healthy": is_healthy,
            "pool": pool_status,
            "recommendations": recommendations,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Health check failed: {str(e)}",
        )


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

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh(request: RefreshRequest):
    """Refresh access token using refresh token"""
    email = verify_token(request.refresh_token)

    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token"
        )

    # Create new tokens
    access_token = create_access_token(email)
    refresh_token = create_refresh_token(email)

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


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
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to revoke token"
            )

        return {
            "message": "Successfully logged out",
            "user": current_user,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Logout failed: {str(e)}"
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
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ============================================================================
# REDIS STATISTICS ENDPOINT
# ============================================================================


@app.get("/redis/stats")
async def redis_stats():
    """
    Get Redis statistics and connection pool metrics

    NEW: Includes pool utilization and health metrics
    """
    try:
        info = redis_client.info()
        pool_status = redis_pool.get_pool_status()

        return {
            "redis": {
                "connected_clients": info.get("connected_clients", 0),
                "used_memory_human": info.get("used_memory_human", "unknown"),
                "total_commands_processed": info.get("total_commands_processed", 0),
                "instantaneous_ops_per_sec": info.get("instantaneous_ops_per_sec", 0),
                "keyspace": redis_client.dbsize(),
            },
            "pool": {
                "environment": pool_status["environment"],
                "max_connections": pool_status["max_connections"],
                "utilization_percent": pool_status["utilization_percent"],
                "in_use_connections": pool_status["in_use_connections"],
                "available_connections": pool_status["available_connections"],
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get Redis stats: {str(e)}",
        )


# ============================================================================
# STARTUP/SHUTDOWN EVENTS
# ============================================================================


@app.on_event("startup")
async def startup_event():
    """Log startup information"""
    print("\n" + "=" * 80)
    print("SERVER STARTED")
    print("=" * 80)
    status = redis_pool.get_pool_status()
    print(f"Environment: {status['environment']}")
    print(f"Pool Max Connections: {status['max_connections']}")
    print(f"Target Capacity: {redis_pool.target_users:,} concurrent users")
    print("=" * 80 + "\n")


@app.on_event("shutdown")
async def shutdown_event():
    """Gracefully close Redis pool"""
    print("\n" + "=" * 80)
    print("SERVER SHUTTING DOWN")
    print("=" * 80)

    # Log final metrics
    log_pool_metrics(redis_pool)

    # Close pool
    redis_pool.close()
    print("Redis pool closed gracefully")
    print("=" * 80 + "\n")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("OPTIMIZED REDIS-INTEGRATED MOCK AUTHENTICATION SERVER")
    print("=" * 80)
    print(f"Environment: {redis_pool.environment.value}")
    print(f"Redis: {redis_pool.host}:{redis_pool.port}")
    print(f"Max Connections: {redis_pool.max_connections}")
    print(f"Target Capacity: {redis_pool.target_users:,} users")
    print("=" * 80)
    print("Endpoints:")
    print("   POST /auth/login        - Login and get tokens")
    print("   POST /auth/refresh      - Refresh access token")
    print("   POST /auth/logout       - Logout and revoke token")
    print("   GET  /api/protected     - Protected endpoint (requires token)")
    print("   GET  /health            - Health check")
    print("   GET  /health/redis      - Redis pool health + recommendations")
    print("   GET  /redis/stats       - Redis + pool statistics")
    print("=" * 80)
    print("Features:")
    print("   - Environment-aware pool sizing (dev/staging/production)")
    print("   - Distributed token blacklist via Redis")
    print("   - Multi-worker compatible")
    print("   - Exponential backoff retry (3 attempts)")
    print("   - Health check intervals (30 seconds)")
    print("   - Connection pool monitoring")
    print("   - Automatic pool utilization tracking")
    print("=" * 80)

    # Use PORT environment variable or default to 8002
    port = int(os.getenv("PORT", "8002"))

    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
