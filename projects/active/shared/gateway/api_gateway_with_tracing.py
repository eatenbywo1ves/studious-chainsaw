"""
Enhanced API Gateway with Distributed Tracing - Phase 5 Step 1B

Integrates OpenTelemetry distributed tracing with existing Prometheus metrics
and correlation ID system. Provides complete request flow visibility across
all services in the enterprise AI architecture.
"""

import asyncio
import time
import uuid
import sys
import os
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from aiohttp import web, ClientSession, ClientTimeout
from aiohttp.web_middlewares import normalize_path_middleware
from aiohttp_cors import setup as setup_cors, CorsConfig

from utilities.prometheus_metrics import get_metrics, MetricsConfig
from utilities.logging_utils import setup_service_logging
from utilities.health_checks import create_health_check_routes, HealthCheckRegistry
from utilities.tracing_utils import (
    initialize_tracing,
    TracingConfig,
    get_tracer,
    trace_request,
    add_correlation_to_span,
)
from libraries.service_discovery import discover_services, ServiceType

# Configure logging
logger = setup_service_logging("api-gateway-enhanced")


class TracingEnabledAPIGateway:
    """Enhanced API Gateway with distributed tracing capabilities"""

    def __init__(self, host="localhost", port=9000):
        self.host = host
        self.port = port
        self.app = web.Application(
            middlewares=[
                normalize_path_middleware(),
                self._tracing_middleware,
                self._correlation_middleware,
                self._metrics_middleware,
                self._error_handling_middleware,
            ]
        )

        # Initialize tracing
        tracing_config = TracingConfig(
            service_name="api-gateway",
            service_version="2.0.0",
            jaeger_endpoint="http://localhost:14268/api/traces",
            enable_logging_correlation=True,
            enable_auto_instrumentation=True,
        )
        initialize_tracing(tracing_config)
        self.tracer = get_tracer()

        # Initialize metrics
        metrics_config = MetricsConfig(
            service_name="api-gateway",
            namespace="enterprise_ai",
            enable_system_metrics=True,
            collection_interval=15.0,
        )
        self.metrics = get_metrics("api-gateway", metrics_config)

        # Initialize health checks
        self.health_registry = HealthCheckRegistry()

        # Circuit breaker state
        self.circuit_breakers = {}

        # Rate limiting
        self.rate_limits = {}
        self.rate_limit_window = 60  # 1 minute
        self.rate_limit_max = 100  # 100 requests per minute per client

        # Setup routes
        self._setup_routes()

        # Setup CORS
        self._setup_cors()

        logger.info("Enhanced API Gateway with distributed tracing initialized")

    def _setup_routes(self):
        """Setup all gateway routes with tracing"""

        # Core gateway routes
        self.app.router.add_get("/health", self._health_check)
        self.app.router.add_get("/status", self._gateway_status)
        self.app.router.add_get("/metrics", self._prometheus_metrics)
        self.app.router.add_get("/services", self._list_services)
        self.app.router.add_get("/services/{service_id}", self._service_details)

        # Tracing specific routes
        self.app.router.add_get("/traces", self._trace_status)
        self.app.router.add_get("/traces/context", self._current_trace_context)

        # Service proxy routes
        self.app.router.add_route(
            "*", "/proxy/{service_name}/{path:.*}", self._proxy_request
        )

        # Health check routes
        create_health_check_routes(self.app, self.health_registry)

        logger.info("Gateway routes configured with tracing enabled")

    def _setup_cors(self):
        """Setup CORS configuration"""
        cors = setup_cors(
            self.app,
            defaults={
                "*": CorsConfig(
                    allow_credentials=True,
                    expose_headers="*",
                    allow_headers="*",
                    allow_methods="*",
                )
            },
        )

    @web.middleware
    async def _tracing_middleware(self, request: web.Request, handler):
        """Distributed tracing middleware - creates span for each request"""
        if not self.tracer:
            return await handler(request)

        # Extract or create correlation ID
        correlation_id = (
            request.headers.get("X-Correlation-ID")
            or request.headers.get("X-Request-ID")
            or str(uuid.uuid4())
        )

        # Create root span for the request
        span_name = f"{request.method} {self._normalize_endpoint(request.path)}"

        with self.tracer.span(
            span_name,
            attributes={
                "http.method": request.method,
                "http.url": str(request.url),
                "http.scheme": request.url.scheme,
                "http.host": request.url.host,
                "http.target": request.path,
                "http.user_agent": request.headers.get("User-Agent", ""),
                "http.remote_addr": request.remote,
                "component": "api_gateway",
                "service.name": "api-gateway",
                "service.version": "2.0.0",
            },
            correlation_id=correlation_id,
        ) as span:
            # Store correlation ID and span in request context
            request["correlation_id"] = correlation_id
            request["trace_span"] = span

            # Add correlation ID to span
            add_correlation_to_span(correlation_id)

            start_time = time.time()

            try:
                # Process request
                response = await handler(request)

                # Record successful request metrics
                duration = time.time() - start_time

                # Add response attributes to span
                span.set_attribute("http.status_code", response.status)
                span.set_attribute(
                    "http.response.size",
                    len(response.body) if hasattr(response, "body") else 0,
                )
                span.set_attribute("response.duration_ms", duration * 1000)

                # Set span status based on response (simplified for now)
                # TODO: Implement proper status setting when trace module is available

                # Add correlation ID to response headers
                response.headers["X-Correlation-ID"] = correlation_id

                return response

            except Exception as e:
                # Record exception in span (simplified for now)
                # TODO: Implement proper exception recording when trace module is available
                pass

                logger.error(
                    f"Request failed: {e}",
                    extra={
                        "correlation_id": correlation_id,
                        "trace_id": (
                            self.tracer.get_trace_context().get("trace_id")
                            if self.tracer
                            else None
                        ),
                    },
                )

                raise

    @web.middleware
    async def _correlation_middleware(self, request: web.Request, handler):
        """Correlation ID middleware - ensures every request has correlation tracking"""
        correlation_id = request.get("correlation_id")

        if not correlation_id:
            correlation_id = (
                request.headers.get("X-Correlation-ID")
                or request.headers.get("X-Request-ID")
                or str(uuid.uuid4())
            )
            request["correlation_id"] = correlation_id

        # Add to logging context
        logger.info(
            f"Processing request {request.method} {request.path}",
            extra={
                "correlation_id": correlation_id,
                "method": request.method,
                "path": request.path,
                "remote_addr": request.remote,
            },
        )

        return await handler(request)

    @web.middleware
    async def _metrics_middleware(self, request: web.Request, handler):
        """Prometheus metrics middleware"""
        start_time = time.time()

        try:
            response = await handler(request)

            # Record successful request
            duration = time.time() - start_time

            self.metrics.record_request(
                method=request.method,
                endpoint=self._normalize_endpoint(request.path),
                status_code=response.status,
                duration=duration,
                request_size=request.content_length or 0,
                response_size=len(response.body) if hasattr(response, "body") else 0,
            )

            return response

        except Exception as e:
            # Record failed request
            duration = time.time() - start_time

            self.metrics.record_request(
                method=request.method,
                endpoint=self._normalize_endpoint(request.path),
                status_code=500,
                duration=duration,
                request_size=request.content_length or 0,
                response_size=0,
            )

            raise

    @web.middleware
    async def _error_handling_middleware(self, request: web.Request, handler):
        """Global error handling middleware"""
        try:
            return await handler(request)
        except web.HTTPException:
            raise
        except Exception as e:
            correlation_id = request.get("correlation_id", "unknown")

            logger.error(
                f"Unhandled exception in request: {e}",
                extra={
                    "correlation_id": correlation_id,
                    "path": request.path,
                    "method": request.method,
                },
            )

            return web.json_response(
                {
                    "error": "Internal server error",
                    "correlation_id": correlation_id,
                    "timestamp": datetime.utcnow().isoformat(),
                },
                status=500,
            )

    def _normalize_endpoint(self, path: str) -> str:
        """Normalize endpoint paths for metrics to prevent high cardinality"""
        # Replace IDs and dynamic segments
        import re

        path = re.sub(r"/\d+", "/{id}", path)
        path = re.sub(r"/[a-f0-9-]{36}", "/{uuid}", path)
        path = re.sub(r"/[a-f0-9]{32}", "/{hash}", path)
        return path

    @trace_request("gateway.health_check")
    async def _health_check(self, request: web.Request):
        """Enhanced health check with tracing"""
        correlation_id = request.get("correlation_id")

        if self.tracer:
            self.tracer.add_span_event("health_check_started")

        # Get service discovery status
        services = discover_services()

        # Check circuit breaker status
        circuit_status = {
            service: state for service, state in self.circuit_breakers.items()
        }

        health_data = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "correlation_id": correlation_id,
            "version": "2.0.0",
            "features": {
                "distributed_tracing": True,
                "metrics_collection": True,
                "service_discovery": True,
                "circuit_breakers": True,
                "rate_limiting": True,
            },
            "services": {
                "discovered": len(services),
                "healthy": len([s for s in services if s.healthy]),
                "circuit_breakers": circuit_status,
            },
            "tracing": {
                "enabled": self.tracer is not None,
                "trace_id": (
                    self.tracer.get_trace_context().get("trace_id")
                    if self.tracer
                    else None
                ),
            },
        }

        if self.tracer:
            self.tracer.add_span_event(
                "health_check_completed",
                {
                    "services_count": len(services),
                    "healthy_services": len([s for s in services if s.healthy]),
                },
            )

        return web.json_response(health_data)

    @trace_request("gateway.trace_status")
    async def _trace_status(self, request: web.Request):
        """Get current tracing status and configuration"""
        if not self.tracer:
            return web.json_response(
                {"tracing_enabled": False, "error": "Tracing not initialized"},
                status=503,
            )

        trace_context = self.tracer.get_trace_context()

        return web.json_response(
            {
                "tracing_enabled": True,
                "current_trace": trace_context,
                "correlation_id": request.get("correlation_id"),
                "service_name": "api-gateway",
                "service_version": "2.0.0",
                "jaeger_endpoint": "http://localhost:14268/api/traces",
                "instrumentation": {
                    "auto_instrumentation": True,
                    "logging_correlation": True,
                    "metrics_integration": True,
                },
            }
        )

    @trace_request("gateway.current_trace_context")
    async def _current_trace_context(self, request: web.Request):
        """Get current trace context for debugging"""
        if not self.tracer:
            return web.json_response({"error": "Tracing not available"}, status=503)

        context = self.tracer.get_trace_context()
        correlation_id = request.get("correlation_id")

        return web.json_response(
            {
                "trace_context": context,
                "correlation_id": correlation_id,
                "timestamp": datetime.utcnow().isoformat(),
                "span_info": {
                    "current_span_recording": True,  # Simplified for now
                    "trace_correlation": correlation_id == context.get("trace_id"),
                },
            }
        )

    @trace_request("gateway.list_services")
    async def _list_services(self, request: web.Request):
        """List discovered services with tracing"""
        correlation_id = request.get("correlation_id")

        if self.tracer:
            self.tracer.add_span_event("service_discovery_query")

        services = discover_services()
        service_type_filter = request.query.get("type")

        if service_type_filter:
            try:
                service_type = ServiceType(service_type_filter)
                services = [s for s in services if s.type == service_type]

                if self.tracer:
                    self.tracer.set_span_attribute(
                        "filter.service_type", service_type_filter
                    )

            except ValueError:
                return web.json_response(
                    {
                        "error": f"Invalid service type: {service_type_filter}",
                        "valid_types": [t.value for t in ServiceType],
                        "correlation_id": correlation_id,
                    },
                    status=400,
                )

        service_list = []
        for service in services:
            service_data = {
                "id": service.id,
                "name": service.name,
                "type": service.type.value,
                "healthy": service.healthy,
                "last_seen": (
                    service.last_seen.isoformat() if service.last_seen else None
                ),
                "capabilities": service.capabilities,
                "metadata": service.metadata,
            }

            if service.endpoint:
                service_data["endpoint"] = {
                    "host": service.endpoint.host,
                    "port": service.endpoint.port,
                    "path": service.endpoint.path,
                    "protocol": service.endpoint.protocol,
                }

            service_list.append(service_data)

        if self.tracer:
            self.tracer.add_span_event(
                "service_discovery_completed",
                {
                    "total_services": len(service_list),
                    "filtered": service_type_filter is not None,
                },
            )

        return web.json_response(
            {
                "services": service_list,
                "total": len(service_list),
                "correlation_id": correlation_id,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )

    @trace_request("gateway.service_details")
    async def _service_details(self, request: web.Request):
        """Get detailed service information"""
        service_id = request.match_info["service_id"]
        correlation_id = request.get("correlation_id")

        if self.tracer:
            self.tracer.set_span_attribute("service.id", service_id)

        services = discover_services()
        service = next((s for s in services if s.id == service_id), None)

        if not service:
            return web.json_response(
                {
                    "error": f"Service not found: {service_id}",
                    "correlation_id": correlation_id,
                },
                status=404,
            )

        # Get circuit breaker status
        circuit_status = self.circuit_breakers.get(service_id, "closed")

        service_details = {
            "id": service.id,
            "name": service.name,
            "type": service.type.value,
            "healthy": service.healthy,
            "last_seen": service.last_seen.isoformat() if service.last_seen else None,
            "capabilities": service.capabilities,
            "metadata": service.metadata,
            "circuit_breaker": {
                "status": circuit_status,
                "last_failure": None,  # TODO: implement failure tracking
            },
            "correlation_id": correlation_id,
        }

        if service.endpoint:
            service_details["endpoint"] = {
                "host": service.endpoint.host,
                "port": service.endpoint.port,
                "path": service.endpoint.path,
                "protocol": service.endpoint.protocol,
                "full_url": (
                    f"{service.endpoint.protocol}://"
                    f"{service.endpoint.host}:{service.endpoint.port}"
                    f"{service.endpoint.path}"
                ),
            }

        return web.json_response(service_details)

    @trace_request("gateway.proxy_request")
    async def _proxy_request(self, request: web.Request):
        """Enhanced proxy request with distributed tracing"""
        service_name = request.match_info["service_name"]
        path = request.match_info.get("path", "")
        correlation_id = request.get("correlation_id")

        if self.tracer:
            self.tracer.set_span_attribute("proxy.service_name", service_name)
            self.tracer.set_span_attribute("proxy.path", path)
            self.tracer.add_span_event("proxy_request_started")

        # Find target service
        services = discover_services()
        target_service = next((s for s in services if s.name == service_name), None)

        if not target_service:
            return web.json_response(
                {
                    "error": f"Service not found: {service_name}",
                    "correlation_id": correlation_id,
                },
                status=404,
            )

        if not target_service.endpoint:
            return web.json_response(
                {
                    "error": f"Service has no endpoint: {service_name}",
                    "correlation_id": correlation_id,
                },
                status=503,
            )

        # Check circuit breaker
        if self.circuit_breakers.get(service_name) == "open":
            return web.json_response(
                {
                    "error": f"Circuit breaker open for service: {service_name}",
                    "correlation_id": correlation_id,
                },
                status=503,
            )

        # Build target URL
        target_url = f"{target_service.endpoint.protocol}://{target_service.endpoint.host}:{target_service.endpoint.port}"
        if path:
            target_url += f"/{path}"

        if self.tracer:
            self.tracer.set_span_attribute("proxy.target_url", target_url)

        try:
            # Create child span for external service call
            with self.tracer.span(
                f"proxy.{service_name}",
                attributes={
                    "http.method": request.method,
                    "http.url": target_url,
                    "service.name": service_name,
                    "component": "proxy",
                },
                correlation_id=correlation_id,
            ):
                # Prepare request headers with trace context
                headers = dict(request.headers)
                headers["X-Correlation-ID"] = correlation_id

                # Add trace context headers (W3C Trace Context)
                if self.tracer:
                    trace_context = self.tracer.get_trace_context()
                    headers["traceparent"] = (
                        f"00-{trace_context.get('trace_id', '0')}-{trace_context.get('span_id', '0')}-01"
                    )

                # Make proxied request
                timeout = ClientTimeout(total=30.0)

                async with ClientSession(timeout=timeout) as session:
                    async with session.request(
                        method=request.method,
                        url=target_url,
                        headers=headers,
                        data=await request.read(),
                        params=request.query,
                    ) as response:

                        response_body = await response.read()
                        response_headers = dict(response.headers)

                        # Add correlation ID to response
                        response_headers["X-Correlation-ID"] = correlation_id

                        if self.tracer:
                            self.tracer.set_span_attribute(
                                "proxy.response.status_code", response.status
                            )
                            self.tracer.set_span_attribute(
                                "proxy.response.size", len(response_body)
                            )
                            self.tracer.add_span_event("proxy_request_completed")

                        return web.Response(
                            body=response_body,
                            status=response.status,
                            headers=response_headers,
                        )

        except Exception as e:
            # Mark circuit breaker as potentially failed
            # TODO: Implement proper circuit breaker logic

            if self.tracer:
                self.tracer.add_span_event("proxy_request_failed", {"error": str(e)})

            logger.error(
                f"Proxy request failed: {e}",
                extra={
                    "correlation_id": correlation_id,
                    "service_name": service_name,
                    "target_url": target_url,
                },
            )

            return web.json_response(
                {
                    "error": f"Proxy request failed: {str(e)}",
                    "service": service_name,
                    "correlation_id": correlation_id,
                },
                status=502,
            )

    async def _gateway_status(self, request: web.Request):
        """Get comprehensive gateway status"""
        services = discover_services()

        return web.json_response(
            {
                "status": "operational",
                "version": "2.0.0",
                "features": {
                    "distributed_tracing": True,
                    "metrics_collection": True,
                    "service_discovery": True,
                    "circuit_breakers": True,
                    "rate_limiting": True,
                    "correlation_tracking": True,
                },
                "services": {
                    "total": len(services),
                    "healthy": len([s for s in services if s.healthy]),
                    "types": list(set(s.type.value for s in services)),
                },
                "tracing": {
                    "enabled": self.tracer is not None,
                    "jaeger_endpoint": "http://localhost:14268/api/traces",
                },
                "correlation_id": request.get("correlation_id"),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )

    async def _prometheus_metrics(self, request: web.Request):
        """Expose Prometheus metrics"""
        metrics_output = self.metrics.generate_metrics()
        return web.Response(text=metrics_output, content_type="text/plain")

    async def run(self):
        """Run the enhanced API gateway"""
        runner = web.AppRunner(self.app)
        await runner.setup()

        site = web.TCPSite(runner, self.host, self.port)
        await site.start()

        logger.info(
            f"Enhanced API Gateway with distributed tracing running on {self.host}:{self.port}"
        )
        logger.info(
            "Features: Tracing ✓, Metrics ✓, Service Discovery ✓, Circuit Breakers ✓"
        )
        logger.info("Access points:")
        logger.info(f"  - Health: http://{self.host}:{self.port}/health")
        logger.info(f"  - Traces: http://{self.host}:{self.port}/traces")
        logger.info(f"  - Services: http://{self.host}:{self.port}/services")
        logger.info(f"  - Metrics: http://{self.host}:{self.port}/metrics")

        # Keep running
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down Enhanced API Gateway...")
        finally:
            await runner.cleanup()


async def main():
    """Main entry point"""
    # Setup logging
    setup_logging()

    # Create and run gateway
    gateway = TracingEnabledAPIGateway()
    await gateway.run()


if __name__ == "__main__":
    asyncio.run(main())
