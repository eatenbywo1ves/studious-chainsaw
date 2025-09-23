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

from .jwt_auth import (
    verify_token, verify_api_key, extract_tenant_from_request,
    TenantContext, TokenData
)

logger = logging.getLogger(__name__)

# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
tenant_header = APIKeyHeader(name="X-Tenant-ID", auto_error=False)

# ============================================================================
# AUTHENTICATION DEPENDENCIES
# ============================================================================

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)
) -> TokenData:
    """Dependency to get current authenticated user"""

    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = verify_token(credentials.credentials)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token_data

async def get_current_active_user(
    current_user: TokenData = Depends(get_current_user)
) -> TokenData:
    """Dependency to ensure user is active"""

    # In production, check against database for user status
    # For now, return the token data
    return current_user

async def require_admin(
    current_user: TokenData = Depends(get_current_active_user)
) -> TokenData:
    """Dependency to require admin role"""

    if current_user.role not in ["owner", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )

    return current_user

async def get_tenant_id(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    api_key: Optional[str] = Depends(api_key_header),
    tenant_id: Optional[str] = Depends(tenant_header)
) -> str:
    """Dependency to extract tenant ID from request"""

    # Try to get from JWT token first
    if credentials:
        token_data = verify_token(credentials.credentials)
        if token_data:
            return token_data.tenant_id

    # Try API key
    if api_key:
        key_data = verify_api_key(api_key)
        if key_data:
            return key_data.get("tenant_id")

    # Try tenant header
    if tenant_id:
        return tenant_id

    # Check if stored in request state (from middleware)
    if hasattr(request.state, "tenant_id"):
        return request.state.tenant_id

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Tenant identification required"
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
            authorization=authorization,
            api_key=api_key,
            tenant_header=tenant_header
        )

        # Store in request state for easy access
        if tenant_id:
            request.state.tenant_id = tenant_id
            request.state.has_tenant = True

            # Set tenant context for database operations
            with TenantContext(tenant_id):
                response = await call_next(request)
        else:
            request.state.has_tenant = False
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
            "/auth/refresh"
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

        elif api_key:
            key_data = verify_api_key(api_key)
            if key_data:
                authenticated = True
                auth_type = "api_key"
                request.state.api_key_name = key_data.get("name")
                request.state.api_key_permissions = key_data.get("permissions", [])

        if not authenticated:
            # Return 401 for API routes
            if request.url.path.startswith("/api/"):
                return Response(
                    content='{"detail": "Authentication required"}',
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"}
                )

        request.state.authenticated = authenticated
        request.state.auth_type = auth_type

        response = await call_next(request)
        return response

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware for rate limiting based on tenant/user"""

    def __init__(self, app, default_limit: int = 100, window_seconds: int = 60):
        super().__init__(app)
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self.request_counts = {}  # Simple in-memory storage

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

        # Check rate limit
        current_time = time.time()
        window_start = current_time - self.window_seconds

        # Clean old entries
        if identifier in self.request_counts:
            self.request_counts[identifier] = [
                t for t in self.request_counts[identifier]
                if t > window_start
            ]

        # Check limit
        request_times = self.request_counts.get(identifier, [])
        if len(request_times) >= self.default_limit:
            retry_after = int(self.window_seconds - (current_time - request_times[0]))
            return Response(
                content=f'{{"detail": "Rate limit exceeded. Try again in {retry_after} seconds"}}',
                status_code=429,
                headers={"Retry-After": str(retry_after)}
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
        response.headers["X-RateLimit-Reset"] = str(
            int(window_start + self.window_seconds)
        )

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
            f"Request started: {method} {path} from {client_host} "
            f"[Request-ID: {request_id}]"
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
        self,
        request: Request,
        current_user: Optional[TokenData] = Depends(get_current_active_user)
    ) -> bool:
        """Check if user has required permissions"""

        # Check JWT user permissions based on role
        if current_user:
            if current_user.role in ["owner", "admin"]:
                return True  # Admins have all permissions

            # Check specific permissions (would check against database)
            # For now, simple role-based check
            role_permissions = {
                "member": ["read", "write"],
                "viewer": ["read"]
            }

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
    return {
        "allow_origins": ["*"],  # Configure based on environment
        "allow_credentials": True,
        "allow_methods": ["*"],
        "allow_headers": [
            "Authorization",
            "Content-Type",
            "X-API-Key",
            "X-Tenant-ID",
            "X-Request-ID"
        ],
        "expose_headers": [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "X-Process-Time",
            "X-Request-ID"
        ]
    }