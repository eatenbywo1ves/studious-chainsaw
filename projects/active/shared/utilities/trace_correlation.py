"""
Trace-to-Log Correlation Utilities for Phase 5 Step 1B

Integrates OpenTelemetry distributed tracing with the existing structured logging
system, providing seamless correlation between traces and logs.
"""

import logging
from typing import Optional, Dict, Any
from contextlib import contextmanager

# Import tracing utilities
from .tracing_utils import get_tracer
from .logging_utils import (
    set_correlation_id,
    set_trace_id,
    set_span_id,
    get_correlation_id,
)

# Import OpenTelemetry
try:
    from opentelemetry.trace import get_current_span

    TRACING_AVAILABLE = True
except ImportError:
    TRACING_AVAILABLE = False

logger = logging.getLogger(__name__)


class TraceLogCorrelator:
    """Manages correlation between distributed traces and structured logs"""

    def __init__(self):
        self.tracer = get_tracer()

    def sync_trace_to_logging_context(self, correlation_id: Optional[str] = None):
        """Synchronize current trace context to logging context variables"""
        if not TRACING_AVAILABLE or not self.tracer:
            return

        try:
            current_span = get_current_span()
            if current_span and current_span.is_recording():
                span_context = current_span.get_span_context()

                # Convert trace and span IDs to hex strings
                trace_id_hex = f"{span_context.trace_id:032x}"
                span_id_hex = f"{span_context.span_id:016x}"

                # Set in logging context
                set_trace_id(trace_id_hex)
                set_span_id(span_id_hex)

                # Set correlation ID if provided, or use trace ID as correlation ID
                if correlation_id:
                    set_correlation_id(correlation_id)
                    # Also add to current span
                    current_span.set_attribute("correlation.id", correlation_id)
                elif not get_correlation_id():
                    # Use trace ID as correlation ID if none exists
                    set_correlation_id(trace_id_hex)

                logger.debug(
                    "Synced trace context to logging",
                    extra={
                        "trace_id": trace_id_hex,
                        "span_id": span_id_hex,
                        "correlation_id": correlation_id or trace_id_hex,
                    },
                )

        except Exception as e:
            logger.warning(f"Failed to sync trace context: {e}")

    def create_correlated_logger(
        self, logger_name: str, correlation_id: Optional[str] = None
    ) -> logging.Logger:
        """Create a logger with automatic trace correlation"""
        base_logger = logging.getLogger(logger_name)

        # Sync current trace context
        self.sync_trace_to_logging_context(correlation_id)

        return base_logger

    def add_trace_to_span(self, **attributes):
        """Add custom attributes to current span and log them"""
        if not TRACING_AVAILABLE or not self.tracer:
            return

        current_span = get_current_span()
        if current_span and current_span.is_recording():
            for key, value in attributes.items():
                current_span.set_attribute(key, value)

            logger.info("Added attributes to current span", extra=attributes)

    def log_span_event(
        self, event_name: str, attributes: Optional[Dict[str, Any]] = None
    ):
        """Log an event both to span and to structured logs"""
        if not TRACING_AVAILABLE or not self.tracer:
            # Just log normally
            logger.info(f"Event: {event_name}", extra=attributes or {})
            return

        current_span = get_current_span()
        if current_span and current_span.is_recording():
            # Add to span
            current_span.add_event(event_name, attributes or {})

        # Also log to structured logs
        logger.info(
            f"Span Event: {event_name}",
            extra={"event_name": event_name, "event_attributes": attributes or {}},
        )

    @contextmanager
    def trace_operation(
        self,
        operation_name: str,
        correlation_id: Optional[str] = None,
        **span_attributes,
    ):
        """Context manager that creates a span and syncs logging context"""
        if not self.tracer:
            # No-op context manager if tracing not available
            logger.info(
                f"Operation: {operation_name} (no tracing)", extra=span_attributes
            )
            yield
            return

        with self.tracer.span(operation_name, span_attributes, correlation_id) as span:
            # Sync trace context to logging
            self.sync_trace_to_logging_context(correlation_id)

            try:
                logger.info(
                    f"Starting operation: {operation_name}", extra=span_attributes
                )
                yield span
                logger.info(f"Completed operation: {operation_name}")

            except Exception as e:
                logger.error(
                    f"Operation failed: {operation_name}",
                    extra={"error": str(e), "error_type": type(e).__name__},
                )
                raise


# Global correlator instance
_correlator = TraceLogCorrelator()


def get_correlator() -> TraceLogCorrelator:
    """Get global trace-log correlator"""
    return _correlator


def sync_trace_to_logs(correlation_id: Optional[str] = None):
    """Convenience function to sync current trace to logging context"""
    _correlator.sync_trace_to_logging_context(correlation_id)


def get_correlated_logger(
    name: str, correlation_id: Optional[str] = None
) -> logging.Logger:
    """Get a logger with automatic trace correlation"""
    return _correlator.create_correlated_logger(name, correlation_id)


def trace_and_log(
    operation_name: str, correlation_id: Optional[str] = None, **attributes
):
    """Decorator/context manager for operations that need both tracing and logging"""
    return _correlator.trace_operation(operation_name, correlation_id, **attributes)


def log_with_trace(logger: logging.Logger, level: str, message: str, **extra):
    """Log a message with automatic trace correlation"""
    # Sync trace context first
    sync_trace_to_logs()

    # Log with extra context
    log_method = getattr(logger, level.lower())
    log_method(message, extra=extra)


def add_span_attributes(**attributes):
    """Add attributes to current span and log them"""
    _correlator.add_trace_to_span(**attributes)


def log_span_event(event_name: str, attributes: Optional[Dict[str, Any]] = None):
    """Log an event to both span and structured logs"""
    _correlator.log_span_event(event_name, attributes)


# Middleware integration helpers
def extract_trace_from_headers(headers: Dict[str, str]) -> Optional[Dict[str, str]]:
    """Extract trace context from HTTP headers (W3C Trace Context)"""
    traceparent = headers.get("traceparent")
    if not traceparent:
        return None

    try:
        # Parse W3C traceparent: version-trace_id-span_id-flags
        parts = traceparent.split("-")
        if len(parts) != 4:
            return None

        return {"trace_id": parts[1], "span_id": parts[2], "trace_flags": parts[3]}
    except Exception:
        return None


def inject_trace_to_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Inject current trace context into HTTP headers"""
    if not TRACING_AVAILABLE:
        return headers

    try:
        current_span = get_current_span()
        if current_span and current_span.is_recording():
            span_context = current_span.get_span_context()

            # Create W3C traceparent header
            traceparent = (
                f"00-{span_context.trace_id:032x}-{span_context.span_id:016x}-01"
            )
            headers["traceparent"] = traceparent

    except Exception as e:
        logger.debug(f"Failed to inject trace headers: {e}")

    return headers


# Request correlation helpers for web frameworks
def setup_request_correlation(request_data: Dict[str, Any]) -> str:
    """Setup correlation for a web request"""
    # Extract correlation ID from request
    correlation_id = (
        request_data.get("correlation_id")
        or request_data.get("headers", {}).get("X-Correlation-ID")
        or request_data.get("headers", {}).get("X-Request-ID")
    )

    # Extract trace context from headers if available
    headers = request_data.get("headers", {})
    trace_context = extract_trace_from_headers(headers)

    # Sync to logging context
    sync_trace_to_logs(correlation_id)

    return correlation_id or "generated"


def finalize_request_correlation(response_headers: Dict[str, str], correlation_id: str):
    """Finalize correlation for a web response"""
    # Add correlation ID to response
    response_headers["X-Correlation-ID"] = correlation_id

    # Inject trace context
    inject_trace_to_headers(response_headers)

    return response_headers


# Integration with existing systems
class CorrelatedLoggerAdapter(logging.LoggerAdapter):
    """Logger adapter that automatically includes trace correlation"""

    def process(self, msg, kwargs):
        # Sync trace context
        sync_trace_to_logs()

        # Let the structured formatter handle the rest
        return msg, kwargs


def wrap_logger_with_correlation(logger: logging.Logger) -> CorrelatedLoggerAdapter:
    """Wrap a logger to automatically include trace correlation"""
    return CorrelatedLoggerAdapter(logger, {})
