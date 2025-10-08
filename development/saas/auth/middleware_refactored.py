"""
Refactored Authentication Middleware with Composability
Clean separation of concerns and better error handling
"""

from typing import Optional, Callable, List, Set
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse
import time
import logging
import os

from .jwt_auth import (
    verify_token,
    verify_api_key,
    extract_tenant_from_request,
    TenantContext,
    redis_client,
)

logger = logging.getLogger(__name__)


# ============================================================================
# BASE MIDDLEWARE COMPONENTS
# ============================================================================


class RequestContextMiddleware(BaseHTTPMiddleware):
    """
    Sets up request context with common attributes.

    This middleware runs first and prepares the request state
    for other middleware to use.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Initialize request state
        request.state.request_id = request.headers.get("X-Request-ID", "")
        request.state.start_time = time.time()
        request.state.authenticated = False
        request.state.auth_type = None

        # Process request
        response = await call_next(request)

        return response


class TenantIsolationMiddleware(BaseHTTPMiddleware):
    """
    Enforces tenant isolation by extracting and validating tenant context.

    Features:
    - Extracts tenant from various sources (JWT, API key, header)
    - Sets up tenant context for database operations
    - Stores tenant info in request state
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Extract tenant from request
        authorization = request.headers.get("Authorization")
        api_key = request.headers.get("X-API-Key")
        tenant_header = request.headers.get("X-Tenant-ID")

        tenant_id = extract_tenant_from_request(
            authorization=authorization, api_key=api_key, tenant_header=tenant_header
        )

        # Store in request state
        request.state.tenant_id = tenant_id
        request.state.has_tenant = tenant_id is not None

        # Set tenant context for database operations
        if tenant_id:
            with TenantContext(tenant_id):
                response = await call_next(request)
        else:
            response = await call_next(request)

        return response


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Handles authentication with flexible path exclusion.

    Improvements over original:
    - Pattern-based path exclusion (supports wildcards)
    - No inline database connection creation
    - Clear separation of JWT and API key validation
    - Better error responses
    """

    def __init__(
        self,
        app,
        exclude_paths: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
    ):
        super().__init__(app)

        # Exact path matches
        self.exclude_paths: Set[str] = set(
            exclude_paths
            or [
                "/",
                "/health",
                "/docs",
                "/redoc",
                "/openapi.json",
                "/auth/login",
                "/auth/register",
                "/auth/refresh",
            ]
        )

        # Pattern-based exclusions (prefix matching)
        self.exclude_patterns = exclude_patterns or [
            "/static/",
            "/public/",
            "/.well-known/",
        ]

    def _should_skip_auth(self, path: str) -> bool:
        """Check if path should skip authentication"""

        # Check exact matches
        if path in self.exclude_paths:
            return True

        # Check patterns
        for pattern in self.exclude_patterns:
            if path.startswith(pattern):
                return True

        return False

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip authentication for excluded paths
        if self._should_skip_auth(request.url.path):
            return await call_next(request)

        # Try JWT authentication
        authorization = request.headers.get("Authorization")
        if authorization and authorization.startswith("Bearer "):
            token = authorization.replace("Bearer ", "")
            token_data = verify_token(token)

            if token_data:
                request.state.authenticated = True
                request.state.auth_type = "jwt"
                request.state.user_id = token_data.sub
                request.state.user_email = token_data.email
                request.state.user_role = token_data.role
                request.state.tenant_id = token_data.tenant_id

                logger.debug(f"JWT authenticated: {token_data.email}")
                return await call_next(request)

        # Try API key authentication
        api_key = request.headers.get("X-API-Key")
        if api_key:
            key_data = verify_api_key(api_key)

            if key_data:
                request.state.authenticated = True
                request.state.auth_type = "api_key"
                request.state.api_key_name = key_data.get("name")
                request.state.api_key_permissions = key_data.get("permissions", [])
                request.state.tenant_id = key_data.get("tenant_id")

                logger.debug(f"API key authenticated: {key_data.get('name')}")
                return await call_next(request)

        # No valid authentication found
        # Only enforce for API routes
        if request.url.path.startswith("/api/"):
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        # For other routes, let them through (they can use dependencies)
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware with Redis backend.

    Features:
    - Redis-backed (distributed rate limiting)
    - Fallback to in-memory if Redis unavailable
    - Per-tenant/user/IP rate limiting
    - Configurable limits and windows
    """

    def __init__(
        self,
        app,
        default_limit: int = 100,
        window_seconds: int = 60,
        use_redis: bool = True,
    ):
        super().__init__(app)
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self.use_redis = use_redis and (redis_client is not None)

        # In-memory fallback
        self._memory_store = {}

    def _get_identifier(self, request: Request) -> str:
        """Get rate limit identifier for request"""
        if hasattr(request.state, "tenant_id") and request.state.tenant_id:
            return f"tenant:{request.state.tenant_id}"
        elif hasattr(request.state, "user_id") and request.state.user_id:
            return f"user:{request.state.user_id}"
        else:
            # Fallback to IP
            client_host = request.client.host if request.client else "unknown"
            return f"ip:{client_host}"

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        identifier = self._get_identifier(request)
        current_time = int(time.time())
        window_start = current_time - self.window_seconds

        # Check rate limit
        if self.use_redis:
            request_count = self._check_redis_rate_limit(identifier, current_time, window_start)
        else:
            request_count = self._check_memory_rate_limit(identifier, current_time, window_start)

        # Check if limit exceeded
        if request_count >= self.default_limit:
            retry_after = self.window_seconds
            return JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded. Try again in {retry_after} seconds"},
                headers={"Retry-After": str(retry_after)},
            )

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        remaining = max(0, self.default_limit - request_count - 1)
        response.headers["X-RateLimit-Limit"] = str(self.default_limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(current_time + self.window_seconds)

        return response

    def _check_redis_rate_limit(self, identifier: str, current_time: int, window_start: int) -> int:
        """Check rate limit using Redis"""
        key = f"ratelimit:{identifier}"

        try:
            # Use Redis sorted set for time-based rate limiting
            # Remove old entries
            redis_client.zremrangebyscore(key, 0, window_start)

            # Count requests in window
            count = redis_client.zcard(key)

            # Add current request
            redis_client.zadd(key, {str(current_time): current_time})

            # Set expiry
            redis_client.expire(key, self.window_seconds + 10)

            return count

        except Exception as e:
            logger.error(f"Redis rate limit error: {e}, falling back to memory")
            # Fallback to memory
            return self._check_memory_rate_limit(identifier, current_time, window_start)

    def _check_memory_rate_limit(
        self, identifier: str, current_time: int, window_start: int
    ) -> int:
        """Check rate limit using in-memory storage (fallback)"""

        # Clean old entries
        if identifier in self._memory_store:
            self._memory_store[identifier] = [
                t for t in self._memory_store[identifier] if t > window_start
            ]

        # Get count
        request_times = self._memory_store.get(identifier, [])
        count = len(request_times)

        # Add current request
        if identifier not in self._memory_store:
            self._memory_store[identifier] = []
        self._memory_store[identifier].append(current_time)

        return count


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Request/response logging middleware.

    Features:
    - Structured logging
    - Performance timing
    - Correlation IDs
    - Optional sensitive data filtering
    """

    def __init__(
        self,
        app,
        log_headers: bool = False,
        log_body: bool = False,
    ):
        super().__init__(app)
        self.log_headers = log_headers
        self.log_body = log_body

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Get request details
        start_time = time.time()
        request_id = request.headers.get("X-Request-ID", "")
        method = request.method
        path = request.url.path
        client_host = request.client.host if request.client else "unknown"

        # Log request
        log_data = {
            "method": method,
            "path": path,
            "client": client_host,
            "request_id": request_id,
        }

        if self.log_headers:
            # Filter sensitive headers
            safe_headers = {
                k: v
                for k, v in request.headers.items()
                if k.lower() not in ["authorization", "x-api-key", "cookie"]
            }
            log_data["headers"] = safe_headers

        logger.info(f"Request started: {log_data}")

        # Process request
        response = await call_next(request)

        # Calculate process time
        process_time = (time.time() - start_time) * 1000  # ms

        # Log response
        logger.info(
            f"Request completed: {method} {path} - "
            f"Status: {response.status_code} - "
            f"Time: {process_time:.2f}ms "
            f"[Request-ID: {request_id}]"
        )

        # Add response headers
        response.headers["X-Process-Time"] = f"{process_time:.2f}"
        if request_id:
            response.headers["X-Request-ID"] = request_id

        return response


# ============================================================================
# CORS CONFIGURATION
# ============================================================================


def get_cors_config() -> dict:
    """
    Get production-safe CORS configuration.

    Returns:
        CORS configuration dict for FastAPI CORSMiddleware
    """
    # Read from environment (NO WILDCARDS)
    allowed_origins = os.getenv(
        "CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:3001"
    ).split(",")

    return {
        "allow_origins": [origin.strip() for origin in allowed_origins],
        "allow_credentials": True,
        "allow_methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        "allow_headers": [
            "Authorization",
            "Content-Type",
            "X-API-Key",
            "X-Tenant-ID",
            "X-Request-ID",
            "Accept",
        ],
        "expose_headers": [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "X-Process-Time",
            "X-Request-ID",
        ],
        "max_age": 600,  # Cache preflight requests for 10 minutes
    }


# ============================================================================
# MIDDLEWARE STACK BUILDER
# ============================================================================


class MiddlewareStackBuilder:
    """
    Helper to build middleware stack with correct ordering.

    Middleware execution order matters:
    1. RequestContext (setup)
    2. RequestLogging (log everything)
    3. CORS (handle preflight)
    4. RateLimit (before expensive operations)
    5. Authentication (identify user)
    6. TenantIsolation (set context)
    """

    @staticmethod
    def build_default_stack(app, **config):
        """
        Build default middleware stack.

        Args:
            app: FastAPI application
            **config: Configuration overrides

        Returns:
            Configured app
        """
        # Add middleware in reverse order (last added = first executed)

        # 6. Tenant isolation (after auth)
        app.add_middleware(TenantIsolationMiddleware)

        # 5. Authentication
        app.add_middleware(
            AuthenticationMiddleware,
            exclude_paths=config.get("auth_exclude_paths"),
            exclude_patterns=config.get("auth_exclude_patterns"),
        )

        # 4. Rate limiting
        app.add_middleware(
            RateLimitMiddleware,
            default_limit=config.get("rate_limit", 100),
            window_seconds=config.get("rate_window", 60),
            use_redis=config.get("rate_use_redis", True),
        )

        # 3. CORS (handled separately via CORSMiddleware usually)

        # 2. Request logging
        app.add_middleware(
            RequestLoggingMiddleware,
            log_headers=config.get("log_headers", False),
            log_body=config.get("log_body", False),
        )

        # 1. Request context (first to execute)
        app.add_middleware(RequestContextMiddleware)

        return app
