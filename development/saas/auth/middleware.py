"""
Authentication Middleware for FastAPI
Provides tenant isolation and authentication enforcement
"""

from typing import Optional, Callable
from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import time
import logging
import os
import sys
from pathlib import Path

from .jwt_auth import (
    verify_token,
    verify_api_key,
    extract_tenant_from_request,
    TenantContext,
    TokenData,
)

# Import centralized database connection
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.connection import SessionLocal

# ✅ MIGRATED: Import centralized configuration system
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from shared.config import get_settings

# Load configuration (validated and type-safe)
_config = get_settings()

logger = logging.getLogger(__name__)

# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
tenant_header = APIKeyHeader(name="X-Tenant-ID", auto_error=False)

# ============================================================================
# AUTHENTICATION DEPENDENCIES
# ============================================================================


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> TokenData:
    """Dependency to get current authenticated user"""

    if not credentials:
        logger.warning("Authentication attempt without credentials")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = verify_token(credentials.credentials)
    if not token_data:
        logger.warning("Authentication failed: invalid or expired token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    logger.debug(
        "User authenticated successfully",
        extra={"user_id": token_data.sub, "tenant_id": token_data.tenant_id, "role": token_data.role},
    )

    return token_data


async def get_current_active_user(current_user: TokenData = Depends(get_current_user)) -> TokenData:
    """Dependency to ensure user is active"""

    # In production, check against database for user status
    # For now, return the token data
    return current_user


async def require_admin(current_user: TokenData = Depends(get_current_active_user)) -> TokenData:
    """Dependency to require admin role"""

    if current_user.role not in ["owner", "admin"]:
        logger.warning(
            "Admin access denied",
            extra={
                "user_id": current_user.sub,
                "tenant_id": current_user.tenant_id,
                "role": current_user.role,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required"
        )

    logger.debug(
        "Admin access granted",
        extra={"user_id": current_user.sub, "tenant_id": current_user.tenant_id, "role": current_user.role},
    )

    return current_user


async def get_tenant_id(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    api_key: Optional[str] = Depends(api_key_header),
    tenant_id: Optional[str] = Depends(tenant_header),
) -> str:
    """Dependency to extract tenant ID from request"""

    # Try to get from JWT token first
    if credentials:
        token_data = verify_token(credentials.credentials)
        if token_data:
            logger.debug(
                "Tenant ID extracted from JWT token",
                extra={"tenant_id": token_data.tenant_id, "path": request.url.path},
            )
            return token_data.tenant_id

    # Try API key
    if api_key:
        key_data = verify_api_key(api_key)
        if key_data:
            logger.debug(
                "Tenant ID extracted from API key",
                extra={"tenant_id": key_data.get("tenant_id"), "path": request.url.path},
            )
            return key_data.get("tenant_id")

    # Try tenant header
    if tenant_id:
        logger.debug(
            "Tenant ID extracted from header",
            extra={"tenant_id": tenant_id, "path": request.url.path},
        )
        return tenant_id

    # Check if stored in request state (from middleware)
    if hasattr(request.state, "tenant_id"):
        return request.state.tenant_id

    logger.warning("Tenant identification failed", extra={"path": request.url.path})
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail="Tenant identification required"
    )


# ============================================================================
# MIDDLEWARE CLASSES
# ============================================================================


class TenantIsolationMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce tenant isolation"""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Extract tenant from request
        authorization = request.headers.get("Authorization")
        api_key = request.headers.get("X-API-Key")
        tenant_header = request.headers.get("X-Tenant-ID")

        tenant_id = extract_tenant_from_request(
            authorization=authorization, api_key=api_key, tenant_header=tenant_header
        )

        # Store in request state for easy access
        if tenant_id:
            request.state.tenant_id = tenant_id
            request.state.has_tenant = True

            logger.debug(
                "Tenant isolation enforced",
                extra={
                    "tenant_id": tenant_id,
                    "path": request.url.path,
                    "method": request.method,
                },
            )

            # Set tenant context for database operations
            with TenantContext(tenant_id):
                response = await call_next(request)
        else:
            request.state.has_tenant = False
            logger.debug(
                "Request without tenant context",
                extra={"path": request.url.path, "method": request.method},
            )
            response = await call_next(request)

        return response


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Middleware to handle authentication"""

    def __init__(self, app, exclude_paths: list = None):
        super().__init__(app)
        self.exclude_paths = exclude_paths or [
            "/",
            "/health",
            "/docs",
            "/openapi.json",
            "/auth/login",
            "/auth/register",
            "/auth/refresh",
        ]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip authentication for excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)

        # Check for authentication
        authorization = request.headers.get("Authorization")
        api_key = request.headers.get("X-API-Key")

        authenticated = False
        auth_type = None

        if authorization and authorization.startswith("Bearer "):
            token = authorization.replace("Bearer ", "")
            token_data = verify_token(token)
            if token_data:
                authenticated = True
                auth_type = "jwt"
                request.state.user_id = token_data.sub
                request.state.user_email = token_data.email
                request.state.user_role = token_data.role

                logger.info(
                    "Authentication successful",
                    extra={
                        "auth_type": "jwt",
                        "user_id": token_data.sub,
                        "tenant_id": token_data.tenant_id,
                        "path": request.url.path,
                        "method": request.method,
                    },
                )
            else:
                logger.warning(
                    "JWT authentication failed",
                    extra={"path": request.url.path, "method": request.method},
                )

        elif api_key:
            # Get database session for API key verification
            # Using centralized connection (no engine creation per-request)
            db = SessionLocal()

            try:
                key_data = verify_api_key(api_key, db_session=db)
                if key_data:
                    authenticated = True
                    auth_type = "api_key"
                    request.state.api_key_id = key_data.get("id")
                    request.state.api_key_name = key_data.get("name")
                    request.state.api_key_permissions = key_data.get("permissions", [])

                    logger.info(
                        "Authentication successful",
                        extra={
                            "auth_type": "api_key",
                            "api_key_name": key_data.get("name"),
                            "tenant_id": key_data.get("tenant_id"),
                            "path": request.url.path,
                            "method": request.method,
                        },
                    )
                else:
                    logger.warning(
                        "API key authentication failed",
                        extra={"path": request.url.path, "method": request.method},
                    )
            finally:
                db.close()

        if not authenticated:
            # Return 401 for API routes
            if request.url.path.startswith("/api/"):
                logger.warning(
                    "Unauthenticated API access attempt",
                    extra={
                        "path": request.url.path,
                        "method": request.method,
                        "client_ip": request.client.host if request.client else "unknown",
                    },
                )
                return Response(
                    content='{"detail": "Authentication required"}',
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )

        request.state.authenticated = authenticated
        request.state.auth_type = auth_type

        response = await call_next(request)
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware for rate limiting based on tenant/user

    SECURITY (SEC-008 Fix): Redis-based distributed rate limiting
    """

    def __init__(self, app, redis_client=None, default_limit: int = 100, window_seconds: int = 60):
        super().__init__(app)
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self.redis_client = redis_client
        # Fallback to in-memory for backwards compatibility (not recommended)
        self.request_counts = {}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Get identifier (tenant_id or IP)
        identifier = None
        if hasattr(request.state, "tenant_id"):
            identifier = f"tenant:{request.state.tenant_id}"
        elif hasattr(request.state, "user_id"):
            identifier = f"user:{request.state.user_id}"
        else:
            # Fall back to IP
            identifier = f"ip:{request.client.host}"

        # ============================================================================
        # SECURITY (SEC-008 Fix): Use Redis for distributed rate limiting
        # ============================================================================
        # Benefits:
        # - Survives server restarts
        # - Works across multiple workers/instances
        # - Atomic operations prevent race conditions
        # - Automatic expiration with TTL

        if self.redis_client:
            # Redis-based sliding window rate limiting (production-ready)
            key = f"ratelimit:{identifier}"
            current_time = time.time()

            try:
                # Use Redis sorted set for sliding window algorithm
                # Score = timestamp, Value = unique request ID
                pipe = self.redis_client.pipeline()

                # Remove entries older than window
                pipe.zremrangebyscore(key, 0, current_time - self.window_seconds)

                # Add current request
                pipe.zadd(key, {f"{current_time}": current_time})

                # Get count in window
                pipe.zcard(key)

                # Set expiration to prevent memory leak
                pipe.expire(key, self.window_seconds + 1)

                # Execute pipeline atomically
                results = pipe.execute()
                request_count = results[2]  # Result from zcard

                if request_count > self.default_limit:
                    retry_after = self.window_seconds
                    logger.warning(
                        "Rate limit exceeded (Redis)",
                        extra={
                            "identifier": identifier,
                            "count": request_count,
                            "limit": self.default_limit,
                            "window": self.window_seconds,
                        },
                    )
                    return Response(
                        content=f'{{"detail": "Rate limit exceeded. Try again in {retry_after} seconds."}}',
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        headers={"Retry-After": str(retry_after)},
                        media_type="application/json",
                    )

                # Continue processing
                response = await call_next(request)
                return response

            except Exception as redis_error:
                logger.error(
                    f"Redis rate limiting error: {redis_error}. Falling back to in-memory.",
                    exc_info=True
                )
                # Fallback to in-memory on Redis failure

        # ============================================================================
        # FALLBACK: In-memory rate limiting (for development/testing only)
        # ============================================================================
        # WARNING: This is NOT production-ready:
        # - Lost on server restart
        # - Doesn't work across multiple workers
        # - Can be bypassed by restarting server

        logger.warning(
            f"Using in-memory rate limiting for {identifier}. "
            "Configure Redis for production-grade rate limiting."
        )

        current_time = time.time()
        window_start = current_time - self.window_seconds

        # Clean old entries
        if identifier in self.request_counts:
            self.request_counts[identifier] = [
                t for t in self.request_counts[identifier] if t > window_start
            ]

        # Check limit
        request_times = self.request_counts.get(identifier, [])
        if len(request_times) >= self.default_limit:
            retry_after = int(self.window_seconds - (current_time - request_times[0]))

            logger.warning(
                "Rate limit exceeded",
                extra={
                    "identifier": identifier,
                    "path": request.url.path,
                    "method": request.method,
                    "limit": self.default_limit,
                    "window_seconds": self.window_seconds,
                    "retry_after": retry_after,
                },
            )

            return Response(
                content=f'{{"detail": "Rate limit exceeded. Try again in {retry_after} seconds"}}',
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )

        # Add current request
        if identifier not in self.request_counts:
            self.request_counts[identifier] = []
        self.request_counts[identifier].append(current_time)

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.default_limit)
        response.headers["X-RateLimit-Remaining"] = str(
            self.default_limit - len(self.request_counts[identifier])
        )
        response.headers["X-RateLimit-Reset"] = str(int(window_start + self.window_seconds))

        return response


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for request/response logging"""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Log request
        start_time = time.time()

        # Get request details
        request_id = request.headers.get("X-Request-ID", "")
        method = request.method
        path = request.url.path
        client_host = request.client.host if request.client else "unknown"

        logger.info(
            f"Request started: {method} {path} from {client_host} [Request-ID: {request_id}]"
        )

        # Process request
        response = await call_next(request)

        # Calculate response time
        process_time = (time.time() - start_time) * 1000  # ms

        # Log response
        logger.info(
            f"Request completed: {method} {path} - "
            f"Status: {response.status_code} - "
            f"Time: {process_time:.2f}ms "
            f"[Request-ID: {request_id}]"
        )

        # Add response headers
        response.headers["X-Process-Time"] = str(process_time)
        if request_id:
            response.headers["X-Request-ID"] = request_id

        return response


# ============================================================================
# PERMISSION CHECKING
# ============================================================================


class PermissionChecker:
    """Dependency class for checking permissions"""

    def __init__(self, required_permissions: list):
        self.required_permissions = required_permissions

    async def __call__(
        self, request: Request, current_user: Optional[TokenData] = Depends(get_current_active_user)
    ) -> bool:
        """Check if user has required permissions"""

        # Check JWT user permissions based on role
        if current_user:
            if current_user.role in ["owner", "admin"]:
                return True  # Admins have all permissions

            # Check specific permissions (would check against database)
            # For now, simple role-based check
            role_permissions = {"member": ["read", "write"], "viewer": ["read"]}

            user_permissions = role_permissions.get(current_user.role, [])
            return all(p in user_permissions for p in self.required_permissions)

        # Check API key permissions
        if hasattr(request.state, "api_key_permissions"):
            api_permissions = request.state.api_key_permissions
            return all(p in api_permissions for p in self.required_permissions)

        return False


# ============================================================================
# CORS CONFIGURATION
# ============================================================================


def get_cors_config():
    """Get CORS configuration for FastAPI"""
    # ✅ MIGRATED: Use centralized CORS configuration
    return {
        "allow_origins": _config.cors.allowed_origins,  # From Pydantic settings
        "allow_credentials": _config.cors.allow_credentials,
        "allow_methods": _config.cors.allow_methods,
        "allow_headers": [
            "Authorization",
            "Content-Type",
            "X-API-Key",
            "X-Tenant-ID",
            "X-Request-ID",
        ],
        "expose_headers": [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "X-Process-Time",
            "X-Request-ID",
        ],
        "max_age": _config.cors.max_age,
    }
