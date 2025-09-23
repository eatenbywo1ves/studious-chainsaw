"""
Enterprise Distributed Tracing Utilities for Phase 5 Step 1B

Integrates OpenTelemetry with existing correlation ID system and Prometheus metrics.
Provides automatic instrumentation and custom span management for multi-service tracing.
"""

import time
import logging
from typing import Dict, Any, Optional, Callable
from contextlib import contextmanager
from functools import wraps

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor

# Configure logging
logger = logging.getLogger(__name__)


class TracingConfig:
    """Configuration for distributed tracing setup"""

    def __init__(
        self,
        service_name: str,
        service_version: str = "1.0.0",
        jaeger_endpoint: str = "http://localhost:14268/api/traces",
        sample_rate: float = 1.0,
        enable_logging_correlation: bool = True,
        enable_auto_instrumentation: bool = True,
    ):
        self.service_name = service_name
        self.service_version = service_version
        self.jaeger_endpoint = jaeger_endpoint
        self.sample_rate = sample_rate
        self.enable_logging_correlation = enable_logging_correlation
        self.enable_auto_instrumentation = enable_auto_instrumentation


class EnterpriseTracer:
    """Enterprise-grade distributed tracing manager"""

    def __init__(self, config: TracingConfig):
        self.config = config
        self.tracer_provider = None
        self.tracer = None
        self._initialize_tracing()

    def _initialize_tracing(self):
        """Initialize OpenTelemetry tracing with console and Jaeger exporters"""
        try:
            # Create resource with service information
            resource = Resource.create(
                {
                    "service.name": self.config.service_name,
                    "service.version": self.config.service_version,
                    "service.namespace": "enterprise_ai",
                }
            )

            # Initialize tracer provider
            self.tracer_provider = TracerProvider(resource=resource)

            # Add console exporter for immediate visibility
            console_exporter = ConsoleSpanExporter()
            console_processor = BatchSpanProcessor(console_exporter)
            self.tracer_provider.add_span_processor(console_processor)

            # Try to add Jaeger exporter (fallback gracefully if not available)
            try:
                jaeger_exporter = JaegerExporter(
                    endpoint=self.config.jaeger_endpoint,
                )
                jaeger_processor = BatchSpanProcessor(jaeger_exporter)
                self.tracer_provider.add_span_processor(jaeger_processor)
                logger.info(
                    f"Jaeger exporter configured: {self.config.jaeger_endpoint}"
                )
            except Exception as jaeger_error:
                logger.warning(f"Jaeger exporter not available: {jaeger_error}")
                logger.info("Falling back to console-only tracing")

            # Set as global tracer provider
            trace.set_tracer_provider(self.tracer_provider)

            # Get tracer instance
            self.tracer = trace.get_tracer(
                self.config.service_name, self.config.service_version
            )

            # Enable automatic instrumentation
            if self.config.enable_auto_instrumentation:
                self._enable_auto_instrumentation()

            # Enable logging correlation
            if self.config.enable_logging_correlation:
                self._enable_logging_correlation()

            logger.info(
                f"Distributed tracing initialized for service: {self.config.service_name}"
            )

        except Exception as e:
            logger.error(f"Failed to initialize tracing: {e}")
            # Create no-op tracer as fallback
            self.tracer = trace.NoOpTracer()

    def _enable_auto_instrumentation(self):
        """Enable automatic instrumentation for common libraries"""
        try:
            # Instrument HTTP requests
            RequestsInstrumentor().instrument()
            AioHttpClientInstrumentor().instrument()

            logger.info("Automatic instrumentation enabled")

        except Exception as e:
            logger.warning(f"Failed to enable auto-instrumentation: {e}")

    def _enable_logging_correlation(self):
        """Enable trace-log correlation"""
        try:
            LoggingInstrumentor().instrument(set_logging_format=True)
            logger.info("Logging correlation enabled")

        except Exception as e:
            logger.warning(f"Failed to enable logging correlation: {e}")

    def start_span(
        self,
        name: str,
        attributes: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ):
        """Start a new span with optional correlation ID"""
        span = self.tracer.start_span(name)

        if attributes:
            for key, value in attributes.items():
                span.set_attribute(key, value)

        # Add correlation ID if provided
        if correlation_id:
            span.set_attribute("correlation.id", correlation_id)
            span.set_attribute("request.correlation_id", correlation_id)

        return span

    @contextmanager
    def span(
        self,
        name: str,
        attributes: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ):
        """Context manager for span lifecycle"""
        span = self.start_span(name, attributes, correlation_id)

        try:
            yield span
        except Exception as e:
            span.record_exception(e)
            span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
            raise
        finally:
            span.end()

    def trace_function(
        self,
        span_name: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ):
        """Decorator to automatically trace function execution"""

        def decorator(func: Callable):
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                name = span_name or f"{func.__module__}.{func.__name__}"
                span_attributes = attributes or {}
                span_attributes.update(
                    {
                        "function.name": func.__name__,
                        "function.module": func.__module__,
                    }
                )

                with self.span(name, span_attributes) as span:
                    # Add function arguments as attributes
                    if args:
                        span.set_attribute("function.args.count", len(args))
                    if kwargs:
                        span.set_attribute("function.kwargs.count", len(kwargs))
                        # Add non-sensitive kwargs
                        for key, value in kwargs.items():
                            if not key.startswith("_") and isinstance(
                                value, (str, int, float, bool)
                            ):
                                span.set_attribute(f"function.kwargs.{key}", str(value))

                    start_time = time.time()
                    result = func(*args, **kwargs)
                    duration = time.time() - start_time

                    span.set_attribute("function.duration_ms", duration * 1000)
                    span.set_attribute("function.success", True)

                    return result

            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                name = span_name or f"{func.__module__}.{func.__name__}"
                span_attributes = attributes or {}
                span_attributes.update(
                    {
                        "function.name": func.__name__,
                        "function.module": func.__module__,
                        "function.async": True,
                    }
                )

                with self.span(name, span_attributes) as span:
                    if args:
                        span.set_attribute("function.args.count", len(args))
                    if kwargs:
                        span.set_attribute("function.kwargs.count", len(kwargs))

                    start_time = time.time()
                    result = await func(*args, **kwargs)
                    duration = time.time() - start_time

                    span.set_attribute("function.duration_ms", duration * 1000)
                    span.set_attribute("function.success", True)

                    return result

            if (
                hasattr(func, "__code__") and func.__code__.co_flags & 0x80
            ):  # CO_COROUTINE
                return async_wrapper
            else:
                return sync_wrapper

        return decorator

    def add_span_event(self, name: str, attributes: Optional[Dict[str, Any]] = None):
        """Add an event to the current span"""
        current_span = trace.get_current_span()
        if current_span and current_span.is_recording():
            current_span.add_event(name, attributes or {})

    def set_span_attribute(self, key: str, value: Any):
        """Set an attribute on the current span"""
        current_span = trace.get_current_span()
        if current_span and current_span.is_recording():
            current_span.set_attribute(key, value)

    def get_trace_context(self) -> Dict[str, str]:
        """Get current trace context for propagation"""
        current_span = trace.get_current_span()
        if current_span and current_span.is_recording():
            span_context = current_span.get_span_context()
            return {
                "trace_id": f"{span_context.trace_id:032x}",
                "span_id": f"{span_context.span_id:016x}",
                "trace_flags": str(span_context.trace_flags),
            }
        return {}


# Global tracer instance
_global_tracer: Optional[EnterpriseTracer] = None


def initialize_tracing(config: TracingConfig) -> EnterpriseTracer:
    """Initialize global tracing configuration"""
    global _global_tracer
    _global_tracer = EnterpriseTracer(config)
    return _global_tracer


def get_tracer() -> Optional[EnterpriseTracer]:
    """Get the global tracer instance"""
    return _global_tracer


def trace_request(
    name: str,
    correlation_id: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
):
    """Decorator for tracing HTTP requests"""

    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            tracer = get_tracer()
            if not tracer:
                return await func(*args, **kwargs)

            span_attributes = attributes or {}
            span_attributes.update(
                {"http.handler": func.__name__, "component": "http_handler"}
            )

            with tracer.span(name, span_attributes, correlation_id) as span:
                try:
                    # Extract request information if available
                    if args and hasattr(args[0], "request"):
                        request = args[0].request
                        span.set_attribute("http.method", request.method)
                        span.set_attribute("http.url", str(request.url))
                        span.set_attribute("http.scheme", request.url.scheme)
                        span.set_attribute("http.host", request.url.host)
                        span.set_attribute("http.target", request.path)

                    result = await func(*args, **kwargs)

                    # Extract response information if available
                    if hasattr(result, "status"):
                        span.set_attribute("http.status_code", result.status)
                        if result.status >= 400:
                            span.set_status(trace.Status(trace.StatusCode.ERROR))

                    return result

                except Exception as e:
                    span.record_exception(e)
                    span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                    raise

        return wrapper

    return decorator


def create_child_span(
    name: str,
    parent_context: Optional[Dict[str, str]] = None,
    attributes: Optional[Dict[str, Any]] = None,
):
    """Create a child span with optional parent context"""
    tracer = get_tracer()
    if not tracer:
        return None

    # TODO: Implement parent context propagation
    # For now, create a regular span
    return tracer.start_span(name, attributes)


# Integration with existing correlation ID system
def get_correlation_from_trace() -> Optional[str]:
    """Extract correlation ID from current trace context"""
    tracer = get_tracer()
    if tracer:
        context = tracer.get_trace_context()
        return context.get("trace_id")
    return None


def add_correlation_to_span(correlation_id: str):
    """Add correlation ID to current span"""
    tracer = get_tracer()
    if tracer:
        tracer.set_span_attribute("correlation.id", correlation_id)
        tracer.set_span_attribute("request.correlation_id", correlation_id)


# Convenience functions for common tracing patterns
def trace_database_operation(operation: str, table: str = None):
    """Trace database operations"""

    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            tracer = get_tracer()
            if not tracer:
                return await func(*args, **kwargs)

            attributes = {"db.operation": operation, "component": "database"}
            if table:
                attributes["db.table"] = table

            with tracer.span(f"db.{operation}", attributes):
                return await func(*args, **kwargs)

        return wrapper

    return decorator


def trace_external_service(service_name: str):
    """Trace calls to external services"""

    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            tracer = get_tracer()
            if not tracer:
                return await func(*args, **kwargs)

            attributes = {"service.name": service_name, "component": "external_service"}

            with tracer.span(f"external.{service_name}", attributes):
                return await func(*args, **kwargs)

        return wrapper

    return decorator
