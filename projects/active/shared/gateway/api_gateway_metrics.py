"""
Enhanced API Gateway with Prometheus Metrics Integration
Extends the existing API Gateway with comprehensive metrics collection
"""

from utilities.prometheus_metrics import get_metrics, MetricsConfig
from utilities.logging_utils import setup_service_logging, LogLevel, set_correlation_id
from libraries.authentication import get_auth_manager, AuthMethod
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


@dataclass
class ClientRateLimit:
    """Client rate limit tracking"""

    requests: deque = field(default_factory=deque)
    blocked_until: Optional[datetime] = None

    def __post_init__(self):
        if not isinstance(self.requests, deque):
            self.requests = deque()


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


class EnhancedAPIGateway:
    """Enhanced API Gateway with Prometheus metrics"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._get_default_config()
        self.logger = setup_service_logging("api-gateway", LogLevel.INFO)
        self.config_manager = get_config_manager()

        # Initialize Prometheus metrics
        metrics_config = MetricsConfig(
            service_name="api-gateway",
            namespace="enterprise_ai",
            enable_system_metrics=True,
            collection_interval=15.0,
        )
        self.metrics = get_metrics("api-gateway", metrics_config)

        # Set up custom metrics
        self._setup_custom_metrics()

        # Rate limiting
        self.rate_limits: Dict[str, ClientRateLimit] = defaultdict(ClientRateLimit)
        self.rate_limit_rule = RateLimitRule(
            requests_per_minute=self.config.get("rate_limiting", {}).get(
                "requests_per_minute", 100
            ),
            burst_size=self.config.get("rate_limiting", {}).get("burst_size", 20),
        )

        # Circuit breakers for services
        self.circuit_breaker_registry = get_circuit_breaker_registry()
        self.service_circuit_breakers = ServiceCircuitBreakers(
            self.circuit_breaker_registry
        )
        self.circuit_breakers: Dict[str, CircuitBreakerState] = defaultdict(
            CircuitBreakerState
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

    def _setup_custom_metrics(self):
        """Set up custom Prometheus metrics for API Gateway"""
        # Rate limiting metrics
        self.rate_limit_blocked = self.metrics.get_counter(
            "api_gateway_rate_limit_blocked_total",
            "Total number of requests blocked by rate limiting",
            ["client_type"],
        )

        # Circuit breaker metrics
        self.circuit_breaker_state = self.metrics.get_gauge(
            "api_gateway_circuit_breaker_state",
            "Circuit breaker state (0=closed, 1=open, 2=half_open)",
            ["service_name"],
        )

        self.circuit_breaker_failures = self.metrics.get_counter(
            "api_gateway_circuit_breaker_failures_total",
            "Total circuit breaker failures",
            ["service_name"],
        )

        # Proxy metrics
        self.proxy_requests = self.metrics.get_counter(
            "api_gateway_proxy_requests_total",
            "Total proxy requests",
            ["service_name", "service_type", "status"],
        )

        self.proxy_duration = self.metrics.get_histogram(
            "api_gateway_proxy_duration_seconds",
            "Proxy request duration",
            ["service_name", "service_type"],
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
        )

        # Authentication metrics
        self.auth_attempts = self.metrics.get_counter(
            "api_gateway_auth_attempts_total",
            "Authentication attempts",
            ["method", "result"],
        )

        # Service discovery metrics
        self.discovered_services = self.metrics.get_gauge(
            "api_gateway_discovered_services",
            "Number of discovered services",
            ["service_type", "status"],
        )

        # Set initial service health
        self.metrics.set_service_health("gateway", True)
        self.metrics.set_service_health("authentication", True)
        self.metrics.set_service_health("rate_limiting", True)

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
                "enabled": False,
                "type": "api_key",
                "header": "X-API-Key",
            },
            "metrics": {
                "require_auth": False,  # Set to True for production
                "allowed_ips": ["127.0.0.1", "::1"],  # Localhost only by default
                "rate_limit": True,
            },
            "circuit_breaker": {
                "enabled": True,
                "failure_threshold": 5,
                "timeout_seconds": 60,
                "recovery_timeout": 30,
            },
        }

    async def start(self):
        """Start the enhanced API gateway"""
        self.logger.info("Starting Enhanced API Gateway with Prometheus Metrics")

        # Initialize HTTP session
        self.session = ClientSession(
            timeout=ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=100, limit_per_host=20),
        )

        # Create web application
        app = web.Application(
            middlewares=[
                self._cors_middleware,
                self._metrics_middleware,
                self._logging_middleware,
                self._authentication_middleware,
                self._rate_limiting_middleware,
                self._error_middleware,
            ]
        )

        # Store service name in app for metrics
        app["service_name"] = "api-gateway"

        # Setup routes
        self._setup_routes(app)

        # Start metrics collection
        self._start_metrics_collection()

        # Start server
        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(runner, "localhost", self.config["port"])
        await site.start()

        self.logger.info(f"Enhanced API Gateway started on port {self.config['port']}")
        self.logger.info(
            f"Prometheus metrics available at: http://localhost:{self.config['port']}/metrics"
        )

        # Keep running
        try:
            await asyncio.Future()  # Run forever
        finally:
            await self.shutdown()

    def _setup_routes(self, app: web.Application):
        """Setup API routes including metrics endpoint"""
        # Prometheus metrics endpoint
        app.router.add_get("/metrics", self._prometheus_metrics)

        # Prometheus service discovery endpoint for dynamic configuration
        app.router.add_get("/prometheus/targets", self._prometheus_targets)

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

        # Alert webhook endpoint for AlertManager
        app.router.add_post("/webhooks/alerts", self._alert_webhook)

    def _start_metrics_collection(self):
        """Start background metrics collection"""

        async def collect_metrics():
            while True:
                try:
                    # Update service discovery metrics
                    services = discover_services()
                    service_counts = {}

                    for service in services:
                        key = (service.type.value, service.status.value)
                        service_counts[key] = service_counts.get(key, 0) + 1

                    # Reset gauges
                    for service_type in ServiceType:
                        for status in ServiceStatus:
                            count = service_counts.get(
                                (service_type.value, status.value), 0
                            )
                            self.discovered_services.labels(
                                service_type=service_type.value, status=status.value
                            ).set(count)

                    # Update circuit breaker states
                    for service_name, breaker in self.circuit_breakers.items():
                        state_value = {"closed": 0, "open": 1, "half_open": 2}.get(
                            breaker.state, 0
                        )
                        self.circuit_breaker_state.labels(
                            service_name=service_name
                        ).set(state_value)

                    # Update active connections count
                    # This would need to be tracked based on your connection tracking
                    self.metrics.set_active_connections(len(self.rate_limits))

                except Exception as e:
                    self.logger.error(f"Error collecting metrics: {e}")

                await asyncio.sleep(15)  # Collect metrics every 15 seconds

        # Start background task
        asyncio.create_task(collect_metrics())

    @middleware
    async def _metrics_middleware(self, request: web.Request, handler):
        """Middleware for automatic metrics collection"""
        start_time = time.time()
        request_size = int(request.headers.get("Content-Length", 0))

        try:
            response = await handler(request)

            # Calculate metrics
            duration = time.time() - start_time
            response_size = (
                len(response.body) if hasattr(response, "body") and response.body else 0
            )

            # Record request metrics
            self.metrics.record_request(
                method=request.method,
                endpoint=self._normalize_endpoint(request.path),
                status_code=response.status,
                duration=duration,
                request_size=request_size if request_size > 0 else None,
                response_size=response_size if response_size > 0 else None,
            )

            return response

        except web.HTTPException as e:
            duration = time.time() - start_time
            self.metrics.record_request(
                method=request.method,
                endpoint=self._normalize_endpoint(request.path),
                status_code=e.status,
                duration=duration,
                request_size=request_size if request_size > 0 else None,
            )
            raise
        except Exception as e:
            duration = time.time() - start_time
            self.metrics.record_request(
                method=request.method,
                endpoint=self._normalize_endpoint(request.path),
                status_code=500,
                duration=duration,
                request_size=request_size if request_size > 0 else None,
            )
            raise

    def _normalize_endpoint(self, path: str) -> str:
        """Normalize endpoint path for metrics (remove IDs and params)"""
        # Replace common ID patterns to avoid high cardinality
        import re

        # Replace UUIDs
        path = re.sub(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "/{id}",
            path,
        )

        # Replace numeric IDs
        path = re.sub(r"/\d+(?=/|$)", "/{id}", path)

        # Replace agent/service names (keep first segment for context)
        path = re.sub(r"/(agents|mcp|services|proxy)/([^/]+)", r"/\1/{name}", path)

        return path

    async def _prometheus_metrics(self, request: web.Request) -> web.Response:
        """Prometheus metrics endpoint with security controls"""
        try:
            # Additional IP-based security check
            allowed_ips = self.config.get("metrics", {}).get(
                "allowed_ips", ["127.0.0.1", "::1"]
            )
            client_ip = request.remote

            if client_ip not in allowed_ips:
                self.logger.warning(f"Metrics access denied for IP: {client_ip}")
                raise web.HTTPForbidden(text="Access denied")

            # Log metrics access for security monitoring
            self.logger.info(
                f"Metrics accessed from {client_ip}",
                extra={
                    "event_type": "metrics_access",
                    "client_ip": client_ip,
                    "user_agent": request.headers.get("User-Agent", "Unknown"),
                },
            )

            metrics_data = self.metrics.generate_metrics()
            return web.Response(
                body=metrics_data,
                content_type="text/plain",
                headers={
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )
        except web.HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Error generating metrics: {e}")
            return web.Response(text="Error generating metrics", status=500)

    async def _prometheus_targets(self, request: web.Request) -> web.Response:
        """Prometheus service discovery endpoint"""
        try:
            services = discover_services()
            targets = []

            for service in services:
                if service.endpoint and service.endpoint.port:
                    # Only include services that have metrics endpoints
                    # This could be enhanced to check if /metrics endpoint actually exists
                    targets.append(
                        {
                            "targets": [
                                f"{service.endpoint.host}:{service.endpoint.port}"
                            ],
                            "labels": {
                                "__meta_service_name": service.name,
                                "__meta_service_type": service.type.value,
                                "__meta_service_status": service.status.value,
                                "__metrics_path__": "/metrics",
                            },
                        }
                    )

            return web.json_response(targets)

        except Exception as e:
            self.logger.error(f"Error generating Prometheus targets: {e}")
            return web.json_response([], status=500)

    async def _alert_webhook(self, request: web.Request) -> web.Response:
        """Webhook endpoint for AlertManager notifications"""
        try:
            alert_data = await request.json()

            # Log alert
            self.logger.warning(f"Received alert: {alert_data}")

            # You can add custom alert handling here
            # For example: send to Slack, update service status, etc.

            return web.json_response({"status": "received"})

        except Exception as e:
            self.logger.error(f"Error processing alert webhook: {e}")
            return web.json_response({"error": str(e)}, status=400)

    # Copy all the middleware methods from the original API Gateway
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
        response.headers["Access-Control-Allow-Origin"] = ", ".join(
            cors_config.get("origins", ["*"])
        )
        response.headers["Access-Control-Allow-Methods"] = ", ".join(
            cors_config.get("methods", ["*"])
        )
        response.headers["Access-Control-Allow-Headers"] = ", ".join(
            cors_config.get("headers", ["*"])
        )
        response.headers["Access-Control-Max-Age"] = "86400"

        return response

    @middleware
    async def _logging_middleware(self, request: web.Request, handler):
        """Request logging middleware"""
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        set_correlation_id(correlation_id)

        start_time = time.time()

        self.logger.info(
            f"Request: {request.method} {request.path}",
            extra={
                "correlation_id": correlation_id,
                "method": request.method,
                "path": request.path,
                "remote": request.remote,
                "user_agent": request.headers.get("User-Agent", "Unknown"),
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
        """Authentication middleware with metrics"""
        # Skip authentication for public endpoints (except metrics if configured)
        public_endpoints = [
            "/health",
            "/status",
            "/auth/login",
            "/auth/register",
        ]

        # Check if metrics requires authentication
        metrics_requires_auth = self.config.get("metrics", {}).get(
            "require_auth", False
        )
        if not metrics_requires_auth:
            public_endpoints.extend(["/metrics", "/prometheus/targets"])

        if request.path in public_endpoints:
            return await handler(request)

        # Special handling for metrics endpoint with IP restriction
        if request.path in ["/metrics", "/prometheus/targets"]:
            allowed_ips = self.config.get("metrics", {}).get(
                "allowed_ips", ["127.0.0.1", "::1"]
            )
            client_ip = request.remote
            if client_ip not in allowed_ips:
                self.logger.warning(f"Metrics access denied for IP: {client_ip}")
                raise web.HTTPForbidden(text="Access denied: IP not allowed")

        # Check if authentication is enabled
        if not self.config.get("authentication", {}).get("enabled", False):
            return await handler(request)

        user = None
        auth_method = None

        try:
            # Try JWT token authentication
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]  # Remove 'Bearer ' prefix
                user = await self.auth_manager.validate_jwt(token)
                auth_method = "jwt"

            # Try API key authentication
            if not user:
                api_key = request.headers.get("X-API-Key")
                if api_key:
                    user = await self.auth_manager.validate_api_key(api_key)
                    auth_method = "api_key"

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
                        auth_method = "basic"
                    except (ValueError, UnicodeDecodeError):
                        pass

            if user:
                # Record successful authentication
                self.auth_attempts.labels(
                    method=auth_method or "unknown", result="success"
                ).inc()

                # Store user in request for later use
                request["user"] = user
                request["user_permissions"] = user.permissions

                # Log authenticated request
                self.logger.info(
                    f"Authenticated request: {user.username} -> {request.path}"
                )

                return await handler(request)
            else:
                # Record failed authentication
                self.auth_attempts.labels(
                    method=auth_method or "unknown", result="failure"
                ).inc()

                self.logger.warning(f"Unauthorized request to {request.path}")
                raise web.HTTPUnauthorized(
                    text="Authentication required",
                    headers={"WWW-Authenticate": "Bearer, API-Key, Basic"},
                )

        except web.HTTPException:
            raise
        except Exception as e:
            self.auth_attempts.labels(
                method=auth_method or "unknown", result="error"
            ).inc()
            self.logger.error(f"Authentication error: {e}")
            raise web.HTTPInternalServerError(text="Authentication failed")

    @middleware
    async def _rate_limiting_middleware(self, request: web.Request, handler):
        """Rate limiting middleware with metrics"""
        if not self.config.get("rate_limiting", {}).get("enabled", True):
            return await handler(request)

        # Skip rate limiting for health checks and metrics
        if request.path in ["/health", "/status", "/metrics"]:
            return await handler(request)

        client_id = self._get_client_id(request)
        client_type = "api_key" if client_id.startswith("key:") else "ip"

        if await self._is_rate_limited(client_id):
            # Record rate limit block
            self.rate_limit_blocked.labels(client_type=client_type).inc()
            self.stats["rate_limited"] += 1

            self.logger.warning(f"Rate limit exceeded for client: {client_id}")
            raise web.HTTPTooManyRequests(text="Rate limit exceeded")

        return await handler(request)

    @middleware
    async def _error_middleware(self, request: web.Request, handler):
        """Error handling middleware"""
        try:
            return await handler(request)
        except web.HTTPException:
            raise
        except Exception as e:
            self.stats["requests_error"] += 1
            self.logger.error(f"Unhandled error: {e}", exc_info=True)
            raise web.HTTPInternalServerError(text="Internal server error")

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

    async def _record_success(self, service_name: str, service_type: str = "unknown"):
        """Record successful request with metrics"""
        breaker = self._get_circuit_breaker(service_name)

        # Update proxy metrics
        self.proxy_requests.labels(
            service_name=service_name, service_type=service_type, status="success"
        ).inc()

        if breaker.state == "half_open":
            breaker.success_count += 1
            if breaker.success_count >= 3:  # Require 3 successes to close
                breaker.state = "closed"
                breaker.failure_count = 0
                self.logger.info(f"Circuit breaker closed for {service_name}")
        elif breaker.state == "closed":
            breaker.failure_count = 0

    async def _record_failure(self, service_name: str, service_type: str = "unknown"):
        """Record failed request with metrics"""
        breaker = self._get_circuit_breaker(service_name)
        breaker.failure_count += 1
        breaker.last_failure_time = datetime.now()

        # Update proxy metrics
        self.proxy_requests.labels(
            service_name=service_name, service_type=service_type, status="failure"
        ).inc()

        # Update circuit breaker metrics
        self.circuit_breaker_failures.labels(service_name=service_name).inc()

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
        return web.json_response({"message": "Logged out successfully"})

    async def _auth_register(self, request: web.Request) -> web.Response:
        """User registration endpoint"""
        return web.json_response({"message": "Registration not implemented"})

    async def _auth_refresh(self, request: web.Request) -> web.Response:
        """Refresh JWT token"""
        return web.json_response({"message": "Token refresh not implemented"})

    async def _auth_create_api_key(self, request: web.Request) -> web.Response:
        """Create API key"""
        return web.json_response({"message": "API key creation not implemented"})

    async def _auth_revoke_api_key(self, request: web.Request) -> web.Response:
        """Revoke API key"""
        return web.json_response({"message": "API key revocation not implemented"})

    async def _health_check(self, request: web.Request) -> web.Response:
        """Gateway health check"""
        return web.json_response(
            {
                "status": "healthy",
                "uptime": (datetime.now() - self.stats["start_time"]).total_seconds(),
                "version": "1.0.0",
                "services": len(self.service_discovery.services),
                "metrics_enabled": True,
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
                    "metrics_enabled": True,
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

    # Proxy endpoints
    async def _mcp_tool_proxy(self, request: web.Request) -> web.Response:
        """Proxy MCP tool calls"""
        return web.json_response({"message": "MCP proxy not implemented"})

    async def _mcp_health_proxy(self, request: web.Request) -> web.Response:
        """Proxy MCP health checks"""
        return web.json_response({"status": "healthy"})

    async def _agent_task_proxy(self, request: web.Request) -> web.Response:
        """Proxy agent task requests"""
        return web.json_response({"message": "Agent proxy not implemented"})

    async def _agent_status_proxy(self, request: web.Request) -> web.Response:
        """Proxy agent status requests"""
        return web.json_response({"status": "healthy"})

    async def _agent_health_proxy(self, request: web.Request) -> web.Response:
        """Proxy agent health checks"""
        return web.json_response({"status": "healthy"})

    async def _generic_proxy(self, request: web.Request) -> web.Response:
        """Generic service proxy"""
        return web.json_response({"message": "Generic proxy not implemented"})

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

    async def shutdown(self):
        """Shutdown the gateway"""
        self.logger.info("Shutting down Enhanced API Gateway")

        if self.session:
            await self.session.close()


# Main entry point
async def main():
    """Main entry point"""
    gateway = EnhancedAPIGateway()

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
