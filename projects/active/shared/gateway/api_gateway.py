"""
API Gateway for MCP Servers and Agents
Provides unified access, rate limiting, authentication, and load balancing
"""

from utilities.logging_utils import setup_service_logging, LogLevel, set_correlation_id
from libraries.authentication import get_auth_manager, AuthMethod, UserRole
from libraries.circuit_breaker import (
    get_circuit_breaker_registry,
    ServiceCircuitBreakers,
)
from libraries.config_manager import get_config_manager
from libraries.service_discovery import (
    get_service_discovery,
    ServiceType,
    ServiceStatus,
    discover_services,
)
import asyncio
import time
import uuid
import os
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict, deque
import aiohttp
from aiohttp import web, ClientSession, ClientTimeout
from aiohttp.web import middleware
import sys
from pathlib import Path

# Add shared libraries to path
sys.path.append(str(Path(__file__).parent.parent))


@dataclass
class RateLimitRule:
    """Rate limiting rule"""

    requests_per_minute: int = 100
    burst_size: int = 20
    window_size: int = 60  # seconds
    enumeration_limit: int = 10  # Special limit for enumeration endpoints
    enumeration_window: int = 300  # 5-minute window for enumeration


@dataclass
class ClientRateLimit:
    """Client rate limit tracking"""

    requests: deque = field(default_factory=deque)
    enumeration_requests: deque = field(default_factory=deque)
    blocked_until: Optional[datetime] = None
    enumeration_blocked_until: Optional[datetime] = None

    def __post_init__(self):
        if not isinstance(self.requests, deque):
            self.requests = deque()
        if not isinstance(self.enumeration_requests, deque):
            self.enumeration_requests = deque()


@dataclass
class CircuitBreakerState:
    """Circuit breaker state for service protection"""

    failure_count: int = 0
    last_failure_time: Optional[datetime] = None
    state: str = "closed"  # closed, open, half_open
    success_count: int = 0
    failure_threshold: int = 5
    timeout_seconds: int = 60
    recovery_timeout: int = 30


class APIGateway:
    """API Gateway for unified service access"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._get_default_config()
        self.logger = setup_service_logging("api-gateway", LogLevel.INFO)
        self.config_manager = get_config_manager()

        # Rate limiting
        self.rate_limits: Dict[str, ClientRateLimit] = defaultdict(ClientRateLimit)
        rate_config = self.config.get("rate_limiting", {})
        self.rate_limit_rule = RateLimitRule(
            requests_per_minute=rate_config.get("requests_per_minute", 100),
            burst_size=rate_config.get("burst_size", 20),
            enumeration_limit=rate_config.get("enumeration_limit", 10),
            enumeration_window=rate_config.get("enumeration_window", 300),
        )

        # Circuit breakers for services
        self.circuit_breaker_registry = get_circuit_breaker_registry()
        self.service_circuit_breakers = ServiceCircuitBreakers(
            self.circuit_breaker_registry
        )

        # Authentication
        self.auth_manager = get_auth_manager()

        # Service discovery
        self.service_discovery = get_service_discovery()

        # HTTP session for proxying
        self.session: Optional[ClientSession] = None

        # Statistics
        self.stats = {
            "requests_total": 0,
            "requests_success": 0,
            "requests_error": 0,
            "rate_limited": 0,
            "circuit_breaker_trips": 0,
            "start_time": datetime.now(),
        }

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default gateway configuration"""
        return {
            "port": 9000,
            "cors": {
                "enabled": True,
                "origins": ["*"],
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "headers": ["*"],
            },
            "rate_limiting": {
                "enabled": True,
                "requests_per_minute": 100,
                "burst_size": 20,
            },
            "authentication": {
                "enabled": True,
                "type": "api_key",
                "header": "X-API-Key",
            },
            "circuit_breaker": {
                "enabled": True,
                "failure_threshold": 5,
                "timeout_seconds": 60,
                "recovery_timeout": 30,
            },
        }

    async def start(self):
        """Start the API gateway"""
        self.logger.info("Starting API Gateway")

        # Initialize HTTP session
        self.session = ClientSession(
            timeout=ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=100, limit_per_host=20),
        )

        # Create web application
        app = web.Application(
            middlewares=[
                self._cors_middleware,
                self._logging_middleware,
                self._authentication_middleware,
                self._rate_limiting_middleware,
                self._error_middleware,
            ]
        )

        # Setup routes
        self._setup_routes(app)

        # Start server
        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(runner, "localhost", self.config["port"])
        await site.start()

        self.logger.info(f"API Gateway started on port {self.config['port']}")

        # Keep running
        try:
            await asyncio.Future()  # Run forever
        finally:
            await self.shutdown()

    def _setup_routes(self, app: web.Application):
        """Setup API routes"""
        # Health and status endpoints
        app.router.add_get("/health", self._health_check)
        app.router.add_get("/status", self._gateway_status)
        app.router.add_get("/stats", self._gateway_stats)

        # Authentication endpoints
        app.router.add_post("/auth/login", self._auth_login)
        app.router.add_post("/auth/logout", self._auth_logout)
        app.router.add_post("/auth/register", self._auth_register)
        app.router.add_post("/auth/refresh", self._auth_refresh)
        app.router.add_post("/auth/api-key", self._auth_create_api_key)
        app.router.add_delete("/auth/api-key/{key_id}", self._auth_revoke_api_key)

        # Service discovery endpoints
        app.router.add_get("/services", self._list_services)
        app.router.add_get("/services/{service_name}", self._get_service)

        # MCP server proxy endpoints
        app.router.add_post(
            "/mcp/{server_name}/tools/{tool_name}", self._mcp_tool_proxy
        )
        app.router.add_get("/mcp/{server_name}/health", self._mcp_health_proxy)

        # Agent proxy endpoints
        app.router.add_post("/agents/{agent_name}/task", self._agent_task_proxy)
        app.router.add_get("/agents/{agent_name}/status", self._agent_status_proxy)
        app.router.add_get("/agents/{agent_name}/health", self._agent_health_proxy)

        # Generic service proxy
        app.router.add_route("*", "/proxy/{service_name}{path:.*}", self._generic_proxy)

    @middleware
    async def _cors_middleware(self, request: web.Request, handler):
        """CORS middleware"""
        if not self.config.get("cors", {}).get("enabled", True):
            return await handler(request)

        # Handle preflight requests
        if request.method == "OPTIONS":
            response = web.Response()
        else:
            response = await handler(request)

        # Add CORS headers
        cors_config = self.config.get("cors", {})
        origin = request.headers.get("Origin")
        allowed_origins = cors_config.get("origins", ["*"])

        # Validate origin against allowed list
        if "*" in allowed_origins or (origin and origin in allowed_origins):
            response.headers["Access-Control-Allow-Origin"] = origin or "*"
        else:
            response.headers["Access-Control-Allow-Origin"] = "null"

        response.headers["Access-Control-Allow-Methods"] = ", ".join(
            cors_config.get("methods", ["GET", "POST"])
        )
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization, X-API-Key, X-Correlation-ID"
        )
        response.headers["Access-Control-Max-Age"] = (
            "300"  # Reduced from 24h to 5 minutes
        )
        response.headers["Access-Control-Allow-Credentials"] = "true"

        # Add security headers
        self._add_security_headers(response)

        return response

    @middleware
    async def _logging_middleware(self, request: web.Request, handler):
        """Request logging middleware"""
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        set_correlation_id(correlation_id)

        start_time = time.time()

        # Sanitize request data for logging
        sanitized_path = self._sanitize_path_for_logging(request.path)
        sanitized_headers = self._sanitize_headers_for_logging(dict(request.headers))

        self.logger.info(
            f"Request: {request.method} {sanitized_path}",
            extra={
                "correlation_id": correlation_id,
                "method": request.method,
                "path": sanitized_path,
                "remote": self._sanitize_ip_for_logging(request.remote),
                "user_agent": sanitized_headers.get("User-Agent", "Unknown"),
            },
        )

        try:
            response = await handler(request)

            duration = time.time() - start_time
            self.logger.info(
                f"Response: {response.status}",
                extra={
                    "correlation_id": correlation_id,
                    "status": response.status,
                    "duration": duration,
                },
            )

            # Add correlation ID to response
            response.headers["X-Correlation-ID"] = correlation_id

            return response

        except Exception as e:
            duration = time.time() - start_time
            self.logger.error(
                f"Request error: {e}",
                extra={
                    "correlation_id": correlation_id,
                    "error": str(e),
                    "duration": duration,
                },
            )
            raise

    @middleware
    async def _authentication_middleware(self, request: web.Request, handler):
        """Authentication middleware"""
        # Skip authentication for public endpoints
        public_endpoints = ["/health", "/auth/login", "/auth/register"]
        if request.path in public_endpoints:
            return await handler(request)

        # Require admin role for sensitive endpoints
        admin_endpoints = ["/services", "/status", "/stats"]
        if any(request.path.startswith(endpoint) for endpoint in admin_endpoints):
            # Continue with authentication check - admin verification happens later
            pass

        # Check if authentication is enabled
        if not self.config.get("authentication", {}).get("enabled", True):
            return await handler(request)

        user = None

        # Try JWT token authentication
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            user = await self.auth_manager.validate_jwt(token)

        # Try API key authentication
        if not user:
            api_key = request.headers.get("X-API-Key")
            if api_key:
                user = await self.auth_manager.validate_api_key(api_key)

        # Try basic authentication
        if not user and "Authorization" in request.headers:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Basic "):
                import base64

                try:
                    encoded = auth_header[6:]  # Remove 'Basic ' prefix
                    decoded = base64.b64decode(encoded).decode("utf-8")
                    username, password = decoded.split(":", 1)
                    user = await self.auth_manager.authenticate(
                        AuthMethod.BASIC_AUTH,
                        {"username": username, "password": password},
                    )
                except (ValueError, UnicodeDecodeError):
                    pass

        if not user:
            self.logger.warning(f"Unauthorized request to {request.path}")
            raise web.HTTPUnauthorized(
                text="Authentication required",
                headers={"WWW-Authenticate": "Bearer, API-Key, Basic"},
            )

        # Store user in request for later use
        request["user"] = user
        request["user_permissions"] = user.permissions

        # Check admin requirements for sensitive endpoints
        admin_endpoints = ["/services", "/status", "/stats"]
        if any(request.path.startswith(endpoint) for endpoint in admin_endpoints):
            if UserRole.ADMIN not in user.roles:
                self.logger.warning(
                    f"Admin access denied for user {user.username} to {request.path}"
                )
                raise web.HTTPForbidden(text="Admin access required")

        # Log authenticated request
        self.logger.info(f"Authenticated request: {user.username} -> {request.path}")

        return await handler(request)

    @middleware
    async def _rate_limiting_middleware(self, request: web.Request, handler):
        """Rate limiting middleware"""
        if not self.config.get("rate_limiting", {}).get("enabled", True):
            return await handler(request)

        # Skip rate limiting for health checks
        if request.path in ["/health", "/status"]:
            return await handler(request)

        client_id = self._get_client_id(request)

        # Check for enumeration-specific rate limiting
        enumeration_endpoints = ["/services", "/status", "/stats"]
        is_enumeration_request = any(
            request.path.startswith(endpoint) for endpoint in enumeration_endpoints
        )

        if is_enumeration_request:
            if await self._is_enumeration_rate_limited(client_id):
                self.stats["rate_limited"] += 1
                self.logger.warning(
                    f"Enumeration rate limit exceeded for client: {client_id} on {request.path}"
                )
                raise web.HTTPTooManyRequests(text="Enumeration rate limit exceeded")

        if await self._is_rate_limited(client_id):
            self.stats["rate_limited"] += 1
            self.logger.warning(f"Rate limit exceeded for client: {client_id}")
            raise web.HTTPTooManyRequests(text="Rate limit exceeded")

        return await handler(request)

    @middleware
    async def _error_middleware(self, request: web.Request, handler):
        """Error handling middleware with sanitized error messages"""
        try:
            return await handler(request)
        except web.HTTPException as e:
            # Sanitize error messages to prevent information disclosure
            sanitized_text = self._sanitize_error_message(e.text, request.path)
            if e.text != sanitized_text:
                self.logger.warning(
                    f"Sanitized error message for {request.path}: original='{e.text}' sanitized='{sanitized_text}'"
                )
            e.text = sanitized_text
            raise
        except Exception as e:
            self.stats["requests_error"] += 1
            # Log detailed error for debugging but return generic message
            self.logger.error(f"Unhandled error on {request.path}: {e}", exc_info=True)
            raise web.HTTPInternalServerError(text="Service temporarily unavailable")

    def _sanitize_error_message(self, message: str, request_path: str) -> str:
        """Sanitize error messages to prevent information disclosure"""
        if not message:
            return "Request failed"

        message_lower = message.lower()

        # Generic replacements for common information disclosure patterns
        sensitive_patterns = {
            # Database errors
            "connection refused": "Service temporarily unavailable",
            "database": "Service temporarily unavailable",
            "sql": "Service temporarily unavailable",
            "sqlite": "Service temporarily unavailable",
            "postgresql": "Service temporarily unavailable",
            "mysql": "Service temporarily unavailable",
            # File system errors
            "file not found": "Resource not found",
            "permission denied": "Access denied",
            "no such file": "Resource not found",
            "directory": "Resource not found",
            # Network errors
            "connection timeout": "Service temporarily unavailable",
            "network unreachable": "Service temporarily unavailable",
            "connection reset": "Service temporarily unavailable",
            # Internal paths and system info
            "c:\\users": "Internal path",
            "/usr/": "Internal path",
            "/var/": "Internal path",
            "/opt/": "Internal path",
            "/home/": "Internal path",
            # Service names and internal details
            "mcp server": "service",
            "agent": "service",
            "redis": "cache service",
            "circuit breaker": "service protection",
        }

        # Check for sensitive patterns and replace
        sanitized = message
        for pattern, replacement in sensitive_patterns.items():
            if pattern in message_lower:
                sanitized = replacement
                break

        # Remove specific internal service names from error messages
        service_names = [
            "financial-stochastic",
            "financial-localization",
            "multidimensional-stochastic",
            "random-walk",
            "director",
            "observatory",
            "von-neumann",
        ]

        for service_name in service_names:
            if service_name in sanitized.lower():
                sanitized = sanitized.replace(service_name, "service")

        # Additional sanitization for specific endpoints
        if "/services" in request_path:
            if "not found" in sanitized.lower():
                sanitized = "Service access denied"
        elif "/mcp/" in request_path or "/agents/" in request_path:
            if "not found" in sanitized.lower():
                sanitized = "Service not available"

        return sanitized

    def _sanitize_path_for_logging(self, path: str) -> str:
        """Sanitize request paths for logging"""
        # Remove sensitive parameters from query strings
        if "?" in path:
            base_path, query = path.split("?", 1)
            # Remove sensitive query parameters
            sensitive_params = ["password", "token", "key", "secret", "auth"]
            query_parts = []
            for param in query.split("&"):
                if "=" in param:
                    param_name = param.split("=")[0].lower()
                    if any(sensitive in param_name for sensitive in sensitive_params):
                        query_parts.append(f"{param.split('=')[0]}=[REDACTED]")
                    else:
                        query_parts.append(param)
                else:
                    query_parts.append(param)
            return f"{base_path}?{'&'.join(query_parts)}"
        return path

    def _sanitize_headers_for_logging(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Sanitize headers for logging"""
        sanitized = {}
        sensitive_headers = {
            "authorization",
            "x-api-key",
            "cookie",
            "set-cookie",
            "x-auth-token",
            "x-access-token",
            "authentication",
        }

        for key, value in headers.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_headers):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = value

        return sanitized

    def _sanitize_ip_for_logging(self, ip: str) -> str:
        """Sanitize IP addresses for logging (optional privacy protection)"""
        if not ip:
            return "unknown"

        # For development, log full IP. In production, consider masking
        environment = os.getenv("ENVIRONMENT", "development")
        if environment == "production":
            # Mask last octet of IPv4 for privacy
            if "." in ip and ip.count(".") == 3:
                parts = ip.split(".")
                return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"

        return ip

    def _add_security_headers(self, response: web.Response) -> None:
        """Add security headers to response"""
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # XSS protection (legacy but still useful)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Content Security Policy - restrictive for API
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "script-src 'none'; "
            "style-src 'none'; "
            "img-src 'none'; "
            "connect-src 'self'; "
            "font-src 'none'; "
            "object-src 'none'; "
            "media-src 'none'; "
            "frame-src 'none';"
        )

        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions policy (restrict features)
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=(), "
            "magnetometer=(), "
            "gyroscope=(), "
            "speaker=()"
        )

        # HSTS header (only if HTTPS is enabled)
        require_https = self.config.get("authentication", {}).get(
            "require_https", False
        )
        if require_https:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # Prevent information disclosure
        response.headers["Server"] = "Gateway"

        # Cache control for sensitive endpoints
        if hasattr(response, "_request_path"):
            sensitive_paths = ["/services", "/status", "/stats", "/auth"]
            if any(response._request_path.startswith(path) for path in sensitive_paths):
                response.headers["Cache-Control"] = (
                    "no-store, no-cache, must-revalidate, private"
                )
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"

    def _get_client_id(self, request: web.Request) -> str:
        """Get client identifier for rate limiting"""
        # Try API key first
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return f"key:{api_key}"

        # Fall back to IP address
        return f"ip:{request.remote}"

    async def _is_rate_limited(self, client_id: str) -> bool:
        """Check if client is rate limited"""
        now = datetime.now()
        client_limit = self.rate_limits[client_id]

        # Check if client is currently blocked
        if client_limit.blocked_until and now < client_limit.blocked_until:
            return True

        # Remove old requests outside the time window
        window_start = now - timedelta(seconds=self.rate_limit_rule.window_size)
        while client_limit.requests and client_limit.requests[0] < window_start:
            client_limit.requests.popleft()

        # Check if within rate limit
        if len(client_limit.requests) >= self.rate_limit_rule.requests_per_minute:
            # Block client for a short period
            client_limit.blocked_until = now + timedelta(seconds=60)
            return True

        # Check burst limit
        recent_requests = sum(
            1
            for req_time in client_limit.requests
            if req_time > now - timedelta(seconds=10)
        )

        if recent_requests >= self.rate_limit_rule.burst_size:
            client_limit.blocked_until = now + timedelta(seconds=30)
            return True

        # Add current request
        client_limit.requests.append(now)
        return False

    async def _is_enumeration_rate_limited(self, client_id: str) -> bool:
        """Check if client is rate limited for enumeration requests"""
        now = datetime.now()
        client_limit = self.rate_limits[client_id]

        # Check if client is currently blocked for enumeration
        if (
            client_limit.enumeration_blocked_until
            and now < client_limit.enumeration_blocked_until
        ):
            return True

        # Remove old enumeration requests outside the time window
        window_start = now - timedelta(seconds=self.rate_limit_rule.enumeration_window)
        while (
            client_limit.enumeration_requests
            and client_limit.enumeration_requests[0] < window_start
        ):
            client_limit.enumeration_requests.popleft()

        # Check enumeration limit
        if (
            len(client_limit.enumeration_requests)
            >= self.rate_limit_rule.enumeration_limit
        ):
            # Block client for enumeration for extended period (1 hour)
            client_limit.enumeration_blocked_until = now + timedelta(hours=1)
            self.logger.warning(
                f"Client {client_id} blocked for enumeration attempts: {len(client_limit.enumeration_requests)} requests"
            )
            return True

        # Add current enumeration request
        client_limit.enumeration_requests.append(now)
        return False

    def _get_circuit_breaker(self, service_name: str) -> CircuitBreakerState:
        """Get circuit breaker state for service"""
        return self.circuit_breakers[service_name]

    async def _check_circuit_breaker(self, service_name: str) -> bool:
        """Check if circuit breaker allows requests"""
        if not self.config.get("circuit_breaker", {}).get("enabled", True):
            return True

        breaker = self._get_circuit_breaker(service_name)
        now = datetime.now()

        if breaker.state == "open":
            # Check if we should try recovery
            if (
                breaker.last_failure_time
                and now - breaker.last_failure_time
                > timedelta(seconds=breaker.recovery_timeout)
            ):
                breaker.state = "half_open"
                breaker.success_count = 0
                self.logger.info(f"Circuit breaker half-open for {service_name}")
                return True
            return False

        return True

    async def _record_success(self, service_name: str):
        """Record successful request"""
        breaker = self._get_circuit_breaker(service_name)

        if breaker.state == "half_open":
            breaker.success_count += 1
            if breaker.success_count >= 3:  # Require 3 successes to close
                breaker.state = "closed"
                breaker.failure_count = 0
                self.logger.info(f"Circuit breaker closed for {service_name}")
        elif breaker.state == "closed":
            breaker.failure_count = 0

    async def _record_failure(self, service_name: str):
        """Record failed request"""
        breaker = self._get_circuit_breaker(service_name)
        breaker.failure_count += 1
        breaker.last_failure_time = datetime.now()

        if breaker.failure_count >= breaker.failure_threshold:
            if breaker.state != "open":
                breaker.state = "open"
                self.stats["circuit_breaker_trips"] += 1
                self.logger.warning(f"Circuit breaker opened for {service_name}")

    # Authentication endpoints
    async def _auth_login(self, request: web.Request) -> web.Response:
        """User login endpoint"""
        try:
            data = await request.json()
            username = data.get("username")
            password = data.get("password")

            if not username or not password:
                raise web.HTTPBadRequest(text="Username and password required")

            user = await self.auth_manager.authenticate(
                AuthMethod.BASIC_AUTH, {"username": username, "password": password}
            )

            if not user:
                raise web.HTTPUnauthorized(text="Invalid credentials")

            # Generate JWT token
            token = await self.auth_manager.generate_jwt(user)

            return web.json_response(
                {
                    "token": token,
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "roles": [role.value for role in user.roles],
                        "permissions": [perm.value for perm in user.permissions],
                    },
                }
            )

        except web.HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Login error: {e}")
            raise web.HTTPInternalServerError(text="Login failed")

    async def _auth_logout(self, request: web.Request) -> web.Response:
        """User logout endpoint"""
        try:
            # Get token from header
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                raise web.HTTPBadRequest(text="Bearer token required")

            token = auth_header[7:]
            await self.auth_manager.revoke_jwt(token)

            return web.json_response({"message": "Logged out successfully"})

        except web.HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Logout error: {e}")
            raise web.HTTPInternalServerError(text="Logout failed")

    async def _auth_register(self, request: web.Request) -> web.Response:
        """User registration endpoint"""
        try:
            data = await request.json()
            username = data.get("username")
            email = data.get("email")
            password = data.get("password")

            if not all([username, email, password]):
                raise web.HTTPBadRequest(text="Username, email, and password required")

            # Create user with default user role
            user = await self.auth_manager.create_user(
                username=username, email=email, password=password, roles={UserRole.USER}
            )

            # Generate JWT token
            token = await self.auth_manager.generate_jwt(user)

            return web.json_response(
                {
                    "message": "User registered successfully",
                    "token": token,
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "roles": [role.value for role in user.roles],
                    },
                }
            )

        except ValueError as e:
            raise web.HTTPBadRequest(text=str(e))
        except Exception as e:
            self.logger.error(f"Registration error: {e}")
            raise web.HTTPInternalServerError(text="Registration failed")

    async def _auth_refresh(self, request: web.Request) -> web.Response:
        """Refresh JWT token"""
        try:
            # Get current user from middleware
            user = request.get("user")
            if not user:
                raise web.HTTPUnauthorized(text="Authentication required")

            # Generate new token
            token = await self.auth_manager.generate_jwt(user)

            return web.json_response(
                {
                    "token": token,
                    "expires_in": self.auth_manager.config.jwt_expiry_hours * 3600,
                }
            )

        except web.HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Token refresh error: {e}")
            raise web.HTTPInternalServerError(text="Token refresh failed")

    async def _auth_create_api_key(self, request: web.Request) -> web.Response:
        """Create API key"""
        try:
            user = request.get("user")
            if not user:
                raise web.HTTPUnauthorized(text="Authentication required")

            data = await request.json()
            name = data.get("name")
            expires_days = data.get("expires_days")

            if not name:
                raise web.HTTPBadRequest(text="API key name required")

            # Create API key
            api_key = await self.auth_manager.create_api_key(
                user_id=user.id, name=name, expires_days=expires_days
            )

            return web.json_response(
                {
                    "api_key": api_key.key,
                    "name": api_key.name,
                    "expires_at": (
                        api_key.expires_at.isoformat() if api_key.expires_at else None
                    ),
                    "permissions": [perm.value for perm in api_key.permissions],
                }
            )

        except web.HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"API key creation error: {e}")
            raise web.HTTPInternalServerError(text="API key creation failed")

    async def _auth_revoke_api_key(self, request: web.Request) -> web.Response:
        """Revoke API key"""
        try:
            user = request.get("user")
            if not user:
                raise web.HTTPUnauthorized(text="Authentication required")

            key_id = request.match_info["key_id"]
            success = await self.auth_manager.revoke_api_key(key_id)

            if success:
                return web.json_response({"message": "API key revoked successfully"})
            else:
                raise web.HTTPNotFound(text="API key not found")

        except web.HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"API key revocation error: {e}")
            raise web.HTTPInternalServerError(text="API key revocation failed")

    async def _health_check(self, request: web.Request) -> web.Response:
        """Gateway health check"""
        return web.json_response(
            {
                "status": "healthy",
                "uptime": (datetime.now() - self.stats["start_time"]).total_seconds(),
                "version": "1.0.0",
                "services": len(self.service_discovery.services),
            }
        )

    async def _gateway_status(self, request: web.Request) -> web.Response:
        """Gateway detailed status"""
        services = discover_services()

        service_status = {}
        for service in services:
            service_status[service.name] = {
                "status": service.status.value,
                "type": service.type.value,
                "last_seen": (
                    service.last_seen.isoformat() if service.last_seen else None
                ),
            }

        return web.json_response(
            {
                "gateway": {
                    "status": "healthy",
                    "uptime": (
                        datetime.now() - self.stats["start_time"]
                    ).total_seconds(),
                    "config": self.config,
                },
                "services": service_status,
                "circuit_breakers": {
                    name: {"state": cb.state, "failure_count": cb.failure_count}
                    for name, cb in self.circuit_breakers.items()
                },
            }
        )

    async def _gateway_stats(self, request: web.Request) -> web.Response:
        """Gateway statistics"""
        # Create a serializable version of stats
        serializable_stats = {}
        for key, value in self.stats.items():
            if isinstance(value, datetime):
                serializable_stats[key] = value.isoformat()
            else:
                serializable_stats[key] = value

        # Add calculated uptime
        serializable_stats["uptime_seconds"] = (
            datetime.now() - self.stats["start_time"]
        ).total_seconds()

        return web.json_response(serializable_stats)

    async def _list_services(self, request: web.Request) -> web.Response:
        """List all registered services"""
        service_type = request.query.get("type")
        status = request.query.get("status")

        # Convert query parameters to enums if provided
        filter_type = None
        filter_status = None

        if service_type:
            try:
                filter_type = ServiceType(service_type)
            except ValueError:
                raise web.HTTPBadRequest(text=f"Invalid service type: {service_type}")

        if status:
            try:
                filter_status = ServiceStatus(status)
            except ValueError:
                raise web.HTTPBadRequest(text=f"Invalid status: {status}")

        services = discover_services(service_type=filter_type, status=filter_status)

        return web.json_response(
            [
                {
                    "id": service.id,
                    "name": service.name,
                    "type": service.type.value,
                    "status": service.status.value,
                    "capabilities": service.capabilities,
                    "endpoint": (
                        service.endpoint.get_url() if service.endpoint.port else None
                    ),
                    "last_seen": (
                        service.last_seen.isoformat() if service.last_seen else None
                    ),
                }
                for service in services
            ]
        )

    async def _get_service(self, request: web.Request) -> web.Response:
        """Get specific service information"""
        service_name = request.match_info["service_name"]

        services = discover_services()
        service = next((s for s in services if s.name == service_name), None)

        if not service:
            raise web.HTTPNotFound(text=f"Service not found: {service_name}")

        return web.json_response(
            {
                "id": service.id,
                "name": service.name,
                "type": service.type.value,
                "status": service.status.value,
                "capabilities": service.capabilities,
                "endpoint": (
                    service.endpoint.get_url() if service.endpoint.port else None
                ),
                "last_seen": (
                    service.last_seen.isoformat() if service.last_seen else None
                ),
                "metadata": service.metadata,
            }
        )

    async def _mcp_tool_proxy(self, request: web.Request) -> web.Response:
        """Proxy MCP tool calls"""
        server_name = request.match_info["server_name"]
        tool_name = request.match_info["tool_name"]

        # Find MCP server
        services = discover_services(service_type=ServiceType.MCP_SERVER)
        service = next((s for s in services if s.name == server_name), None)

        if not service:
            raise web.HTTPNotFound(text=f"MCP server not found: {server_name}")

        if not await self._check_circuit_breaker(service.name):
            raise web.HTTPServiceUnavailable(
                text=f"Service {service.name} temporarily unavailable"
            )

        try:
            # Get request data
            request_data = await request.json() if request.can_read_body else {}

            # Proxy to MCP server
            url = f"{service.endpoint.get_url()}/tools/{tool_name}"

            async with self.session.post(url, json=request_data) as response:
                result = await response.json()

                await self._record_success(service.name)
                self.stats["requests_success"] += 1

                return web.json_response(result, status=response.status)

        except Exception as e:
            await self._record_failure(service.name)
            self.stats["requests_error"] += 1
            self.logger.error(f"MCP proxy error for {server_name}/{tool_name}: {e}")
            raise web.HTTPBadGateway(text=f"MCP server error: {e}")
        finally:
            self.stats["requests_total"] += 1

    async def _agent_task_proxy(self, request: web.Request) -> web.Response:
        """Proxy agent task requests"""
        agent_name = request.match_info["agent_name"]

        # Find agent
        services = discover_services(service_type=ServiceType.AGENT)
        service = next((s for s in services if s.name == agent_name), None)

        if not service:
            raise web.HTTPNotFound(text=f"Agent not found: {agent_name}")

        if not await self._check_circuit_breaker(service.name):
            raise web.HTTPServiceUnavailable(
                text=f"Agent {service.name} temporarily unavailable"
            )

        try:
            # Get task data
            task_data = await request.json()

            # Proxy to agent
            url = f"{service.endpoint.get_url()}/task"

            async with self.session.post(url, json=task_data) as response:
                result = await response.json()

                await self._record_success(service.name)
                self.stats["requests_success"] += 1

                return web.json_response(result, status=response.status)

        except Exception as e:
            await self._record_failure(service.name)
            self.stats["requests_error"] += 1
            self.logger.error(f"Agent proxy error for {agent_name}: {e}")
            raise web.HTTPBadGateway(text=f"Agent error: {e}")
        finally:
            self.stats["requests_total"] += 1

    async def _generic_proxy(self, request: web.Request) -> web.Response:
        """Generic service proxy"""
        service_name = request.match_info["service_name"]
        path = request.match_info.get("path", "/")

        # Find service
        services = discover_services()
        service = next((s for s in services if s.name == service_name), None)

        if not service:
            raise web.HTTPNotFound(text=f"Service not found: {service_name}")

        if not await self._check_circuit_breaker(service.name):
            raise web.HTTPServiceUnavailable(
                text=f"Service {service.name} temporarily unavailable"
            )

        try:
            # Build target URL
            url = f"{service.endpoint.get_url()}{path}"

            # Get request data
            data = None
            if request.can_read_body:
                if request.content_type == "application/json":
                    data = await request.json()
                else:
                    data = await request.read()

            # Proxy request
            async with self.session.request(
                request.method,
                url,
                json=data if isinstance(data, dict) else None,
                data=data if not isinstance(data, dict) else None,
                headers=dict(request.headers),
                params=dict(request.query),
            ) as response:
                result = await response.read()

                await self._record_success(service.name)
                self.stats["requests_success"] += 1

                return web.Response(
                    body=result, status=response.status, headers=dict(response.headers)
                )

        except Exception as e:
            await self._record_failure(service.name)
            self.stats["requests_error"] += 1
            self.logger.error(f"Proxy error for {service_name}: {e}")
            raise web.HTTPBadGateway(text=f"Service error: {e}")
        finally:
            self.stats["requests_total"] += 1

    async def _mcp_health_proxy(self, request: web.Request) -> web.Response:
        """Proxy MCP health checks"""
        return await self._health_proxy(request, ServiceType.MCP_SERVER)

    async def _agent_status_proxy(self, request: web.Request) -> web.Response:
        """Proxy agent status requests"""
        return await self._health_proxy(request, ServiceType.AGENT, "/status")

    async def _agent_health_proxy(self, request: web.Request) -> web.Response:
        """Proxy agent health checks"""
        return await self._health_proxy(request, ServiceType.AGENT)

    async def _health_proxy(
        self, request: web.Request, service_type: ServiceType, endpoint: str = "/health"
    ) -> web.Response:
        """Generic health check proxy"""
        service_name = request.match_info.get("server_name") or request.match_info.get(
            "agent_name"
        )

        services = discover_services(service_type=service_type)
        service = next((s for s in services if s.name == service_name), None)

        if not service:
            raise web.HTTPNotFound(text=f"Service not found: {service_name}")

        try:
            url = f"{service.endpoint.get_url()}{endpoint}"

            async with self.session.get(url) as response:
                result = await response.json()
                return web.json_response(result, status=response.status)

        except Exception as e:
            self.logger.error(f"Health check error for {service_name}: {e}")
            return web.json_response(
                {"status": "unhealthy", "error": str(e)}, status=503
            )

    async def shutdown(self):
        """Shutdown the gateway"""
        self.logger.info("Shutting down API Gateway")

        if self.session:
            await self.session.close()


# Main entry point
async def main():
    """Main entry point"""
    gateway = APIGateway()

    try:
        await gateway.start()
    except KeyboardInterrupt:
        print("Received keyboard interrupt")
    except Exception as e:
        gateway.logger.error(f"Gateway failed: {e}", exc_info=True)
    finally:
        await gateway.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
