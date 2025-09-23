"""
Distributed Tracing System
Provides end-to-end request tracing across all services with correlation IDs
"""

import json
import time
import uuid
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum
from contextvars import ContextVar
import asyncio
from collections import defaultdict
import threading


class SpanKind(Enum):
    CLIENT = "client"  # Outgoing request
    SERVER = "server"  # Incoming request
    PRODUCER = "producer"  # Message producer
    CONSUMER = "consumer"  # Message consumer
    INTERNAL = "internal"  # Internal operation


class SpanStatus(Enum):
    UNSET = "unset"
    OK = "ok"
    ERROR = "error"


@dataclass
class TraceContext:
    """Context for distributed tracing"""

    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    parent_span_id: Optional[str] = None
    trace_flags: int = 0
    trace_state: Dict[str, str] = field(default_factory=dict)
    baggage: Dict[str, str] = field(default_factory=dict)

    def to_headers(self) -> Dict[str, str]:
        """Convert trace context to HTTP headers"""
        headers = {"X-Trace-Id": self.trace_id, "X-Trace-Flags": str(self.trace_flags)}

        if self.parent_span_id:
            headers["X-Parent-Span-Id"] = self.parent_span_id

        if self.trace_state:
            headers["X-Trace-State"] = json.dumps(self.trace_state)

        if self.baggage:
            headers["X-Trace-Baggage"] = json.dumps(self.baggage)

        return headers

    @classmethod
    def from_headers(cls, headers: Dict[str, str]) -> "TraceContext":
        """Create trace context from HTTP headers"""
        trace_id = headers.get("X-Trace-Id", uuid.uuid4().hex)
        parent_span_id = headers.get("X-Parent-Span-Id")
        trace_flags = int(headers.get("X-Trace-Flags", "0"))

        trace_state = {}
        if "X-Trace-State" in headers:
            try:
                trace_state = json.loads(headers["X-Trace-State"])
            except Exception:
                pass

        baggage = {}
        if "X-Trace-Baggage" in headers:
            try:
                baggage = json.loads(headers["X-Trace-Baggage"])
            except Exception:
                pass

        return cls(
            trace_id=trace_id,
            parent_span_id=parent_span_id,
            trace_flags=trace_flags,
            trace_state=trace_state,
            baggage=baggage,
        )


@dataclass
class Span:
    """Represents a span in a distributed trace"""

    span_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    trace_id: str = ""
    parent_span_id: Optional[str] = None
    operation_name: str = ""
    service_name: str = ""
    kind: SpanKind = SpanKind.INTERNAL
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    duration_ms: Optional[float] = None
    status: SpanStatus = SpanStatus.UNSET
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    links: List[Dict[str, Any]] = field(default_factory=list)

    def set_attribute(self, key: str, value: Any):
        """Set a span attribute"""
        self.attributes[key] = value

    def add_event(self, name: str, attributes: Optional[Dict[str, Any]] = None):
        """Add an event to the span"""
        event = {"name": name, "timestamp": time.time(), "attributes": attributes or {}}
        self.events.append(event)

    def set_status(self, status: SpanStatus, message: Optional[str] = None):
        """Set span status"""
        self.status = status
        if message:
            self.attributes["status.message"] = message

    def end(self, end_time: Optional[float] = None):
        """End the span"""
        self.end_time = end_time or time.time()
        self.duration_ms = (self.end_time - self.start_time) * 1000

    def to_dict(self) -> Dict[str, Any]:
        """Convert span to dictionary"""
        data = {
            "span_id": self.span_id,
            "trace_id": self.trace_id,
            "parent_span_id": self.parent_span_id,
            "operation_name": self.operation_name,
            "service_name": self.service_name,
            "kind": self.kind.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "status": self.status.value,
            "attributes": self.attributes,
            "events": self.events,
            "links": self.links,
        }
        return data


class Tracer:
    """Tracer for creating and managing spans"""

    def __init__(self, service_name: str):
        self.service_name = service_name
        self.spans: List[Span] = []
        self.active_spans: Dict[str, Span] = {}
        self._lock = threading.Lock()
        self.logger = self._setup_logging()

    def _setup_logging(self) -> logging.Logger:
        """Setup logging for tracer"""
        logger = logging.getLogger(f"Tracer.{self.service_name}")
        logger.setLevel(logging.DEBUG)
        return logger

    def start_span(
        self,
        operation_name: str,
        context: Optional[TraceContext] = None,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Span:
        """Start a new span"""
        # Create or use existing context
        if context:
            trace_id = context.trace_id
            parent_span_id = context.parent_span_id
        else:
            trace_id = uuid.uuid4().hex
            parent_span_id = None

        # Create span
        span = Span(
            trace_id=trace_id,
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            service_name=self.service_name,
            kind=kind,
            attributes=attributes or {},
        )

        # Store span
        with self._lock:
            self.spans.append(span)
            self.active_spans[span.span_id] = span

        self.logger.debug(
            f"Started span: {span.span_id} for operation: {operation_name}"
        )

        return span

    def end_span(self, span: Span):
        """End a span"""
        span.end()

        with self._lock:
            if span.span_id in self.active_spans:
                del self.active_spans[span.span_id]

        self.logger.debug(
            f"Ended span: {span.span_id} (duration: {span.duration_ms:.2f}ms)"
        )

    def get_current_trace_context(self, span: Span) -> TraceContext:
        """Get trace context for current span"""
        return TraceContext(trace_id=span.trace_id, parent_span_id=span.span_id)

    def inject_context(self, span: Span, carrier: Dict[str, str]):
        """Inject trace context into a carrier (e.g., HTTP headers)"""
        context = self.get_current_trace_context(span)
        carrier.update(context.to_headers())

    def extract_context(self, carrier: Dict[str, str]) -> TraceContext:
        """Extract trace context from a carrier"""
        return TraceContext.from_headers(carrier)


class SpanProcessor:
    """Processes completed spans"""

    def on_start(self, span: Span):
        """Called when a span starts"""

    def on_end(self, span: Span):
        """Called when a span ends"""

    def shutdown(self):
        """Shutdown the processor"""


class ConsoleSpanExporter(SpanProcessor):
    """Exports spans to console for debugging"""

    def on_end(self, span: Span):
        """Print span to console"""
        print(json.dumps(span.to_dict(), indent=2, default=str))


class BatchSpanProcessor(SpanProcessor):
    """Batches spans before exporting"""

    def __init__(
        self,
        exporter: SpanProcessor,
        max_batch_size: int = 100,
        max_delay_ms: int = 5000,
    ):
        self.exporter = exporter
        self.max_batch_size = max_batch_size
        self.max_delay_ms = max_delay_ms
        self.batch: List[Span] = []
        self._lock = threading.Lock()
        self._timer: Optional[threading.Timer] = None

    def on_end(self, span: Span):
        """Add span to batch"""
        with self._lock:
            self.batch.append(span)

            if len(self.batch) >= self.max_batch_size:
                self._export_batch()
            elif not self._timer:
                self._schedule_export()

    def _schedule_export(self):
        """Schedule batch export"""
        self._timer = threading.Timer(self.max_delay_ms / 1000, self._export_batch)
        self._timer.start()

    def _export_batch(self):
        """Export the current batch"""
        with self._lock:
            if self.batch:
                for span in self.batch:
                    self.exporter.on_end(span)
                self.batch.clear()

            if self._timer:
                self._timer.cancel()
                self._timer = None

    def shutdown(self):
        """Shutdown the processor"""
        self._export_batch()
        self.exporter.shutdown()


class TraceCollector:
    """Collects and stores traces from all services"""

    def __init__(self):
        self.traces: Dict[str, List[Span]] = defaultdict(list)
        self.span_index: Dict[str, Span] = {}
        self._lock = threading.Lock()
        self.logger = self._setup_logging()

    def _setup_logging(self) -> logging.Logger:
        """Setup logging for trace collector"""
        logger = logging.getLogger("TraceCollector")
        logger.setLevel(logging.INFO)
        return logger

    def add_span(self, span: Span):
        """Add a span to the collection"""
        with self._lock:
            self.traces[span.trace_id].append(span)
            self.span_index[span.span_id] = span

        self.logger.debug(f"Added span {span.span_id} to trace {span.trace_id}")

    def collect_span(self, span_data: Dict[str, Any]):
        """Collect span from raw data (for integration tests)"""
        # Convert raw data to Span object, mapping field names correctly
        span = Span(
            trace_id=span_data["trace_id"],
            span_id=span_data["span_id"],
            parent_span_id=span_data.get("parent_span_id"),
            operation_name=span_data["operation"],
            service_name=span_data["service"],
            start_time=span_data["start_time"],
            end_time=span_data["end_time"],
        )

        # Set duration manually since it's calculated
        if span.end_time:
            span.duration_ms = (span.end_time - span.start_time) * 1000

        # Set attributes from tags
        if "tags" in span_data:
            span.attributes.update(span_data["tags"])

        # Set status
        status_mapping = {"success": SpanStatus.OK, "error": SpanStatus.ERROR}
        span.status = status_mapping.get(
            span_data.get("status", "success"), SpanStatus.OK
        )

        self.add_span(span)

    def get_trace(self, trace_id: str) -> List[Span]:
        """Get all spans for a trace"""
        return self.traces.get(trace_id, [])

    def get_span(self, span_id: str) -> Optional[Span]:
        """Get a specific span"""
        return self.span_index.get(span_id)

    def get_trace_tree(self, trace_id: str) -> Dict[str, Any]:
        """Get trace as a tree structure"""
        spans = self.get_trace(trace_id)
        if not spans:
            return {}

        # Build tree
        span_dict = {span.span_id: span for span in spans}
        root_spans = []

        for span in spans:
            if not span.parent_span_id or span.parent_span_id not in span_dict:
                root_spans.append(span)

        def build_tree(span: Span) -> Dict[str, Any]:
            children = [
                build_tree(child)
                for child in spans
                if child.parent_span_id == span.span_id
            ]

            result = span.to_dict()
            if children:
                result["children"] = children

            return result

        if len(root_spans) == 1:
            return build_tree(root_spans[0])
        else:
            return {
                "trace_id": trace_id,
                "roots": [build_tree(root) for root in root_spans],
            }

    def get_trace_summary(self, trace_id: str) -> Dict[str, Any]:
        """Get summary of a trace"""
        spans = self.get_trace(trace_id)
        if not spans:
            return {}

        # Calculate statistics
        total_duration = 0
        service_durations = defaultdict(float)
        operation_counts = defaultdict(int)
        error_count = 0

        for span in spans:
            if span.duration_ms:
                total_duration = max(
                    total_duration,
                    (span.end_time or span.start_time)
                    - min(s.start_time for s in spans),
                )
                service_durations[span.service_name] += span.duration_ms

            operation_counts[span.operation_name] += 1

            if span.status == SpanStatus.ERROR:
                error_count += 1

        return {
            "trace_id": trace_id,
            "span_count": len(spans),
            "total_duration_ms": total_duration * 1000,
            "service_durations": dict(service_durations),
            "operation_counts": dict(operation_counts),
            "error_count": error_count,
            "services": list(set(span.service_name for span in spans)),
            "has_errors": error_count > 0,
        }

    def search_traces(
        self,
        service_name: Optional[str] = None,
        operation_name: Optional[str] = None,
        min_duration_ms: Optional[float] = None,
        max_duration_ms: Optional[float] = None,
        has_errors: Optional[bool] = None,
        limit: int = 100,
    ) -> List[str]:
        """Search for traces matching criteria"""
        matching_traces = []

        for trace_id, spans in self.traces.items():
            # Check criteria
            if service_name and not any(s.service_name == service_name for s in spans):
                continue

            if operation_name and not any(
                s.operation_name == operation_name for s in spans
            ):
                continue

            if has_errors is not None:
                trace_has_errors = any(s.status == SpanStatus.ERROR for s in spans)
                if trace_has_errors != has_errors:
                    continue

            if min_duration_ms or max_duration_ms:
                total_duration = max((s.end_time or s.start_time) for s in spans) - min(
                    s.start_time for s in spans
                )
                total_duration_ms = total_duration * 1000

                if min_duration_ms and total_duration_ms < min_duration_ms:
                    continue

                if max_duration_ms and total_duration_ms > max_duration_ms:
                    continue

            matching_traces.append(trace_id)

            if len(matching_traces) >= limit:
                break

        return matching_traces

    def get_statistics(self) -> Dict[str, Any]:
        """Get tracing statistics"""
        total_spans = sum(len(spans) for spans in self.traces.values())
        total_traces = len(self.traces)

        # Count spans by status
        status_counts = {"ok": 0, "error": 0, "unset": 0}
        service_counts = defaultdict(int)
        operation_counts = defaultdict(int)

        for spans in self.traces.values():
            for span in spans:
                status_key = (
                    span.status.value
                    if hasattr(span.status, "value")
                    else str(span.status)
                )
                if status_key in status_counts:
                    status_counts[status_key] += 1
                else:
                    status_counts["unset"] += 1

                service_counts[span.service_name] += 1
                operation_counts[span.operation_name] += 1

        return {
            "total_traces": total_traces,
            "total_spans": total_spans,
            "spans_by_status": status_counts,
            "services": len(service_counts),
            "operations": len(operation_counts),
            "top_services": dict(
                sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "top_operations": dict(
                sorted(operation_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
        }


# Context variables for current trace and span
current_trace_context: ContextVar[Optional[TraceContext]] = ContextVar(
    "current_trace_context", default=None
)
current_span: ContextVar[Optional[Span]] = ContextVar("current_span", default=None)

# Global instances
_tracers: Dict[str, Tracer] = {}
_trace_collector: Optional[TraceCollector] = None


def get_tracer(service_name: str) -> Tracer:
    """Get or create a tracer for a service"""
    if service_name not in _tracers:
        _tracers[service_name] = Tracer(service_name)
    return _tracers[service_name]


def get_trace_collector() -> TraceCollector:
    """Get the global trace collector"""
    global _trace_collector
    if _trace_collector is None:
        _trace_collector = TraceCollector()
    return _trace_collector


# Convenience decorators and context managers
class traced:
    """Decorator/context manager for tracing"""

    def __init__(
        self,
        operation_name: str,
        service_name: str,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: Optional[Dict[str, Any]] = None,
    ):
        self.operation_name = operation_name
        self.service_name = service_name
        self.kind = kind
        self.attributes = attributes or {}
        self.span: Optional[Span] = None
        self.tracer: Optional[Tracer] = None

    def __enter__(self) -> Span:
        # Get tracer
        self.tracer = get_tracer(self.service_name)

        # Get current context
        context = current_trace_context.get()

        # Start span
        self.span = self.tracer.start_span(
            self.operation_name, context, self.kind, self.attributes
        )

        # Update context
        new_context = self.tracer.get_current_trace_context(self.span)
        current_trace_context.set(new_context)
        current_span.set(self.span)

        return self.span

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.span:
            # Set error status if exception occurred
            if exc_type:
                self.span.set_status(SpanStatus.ERROR, str(exc_val))
                self.span.set_attribute("exception.type", exc_type.__name__)
                self.span.set_attribute("exception.message", str(exc_val))
            else:
                self.span.set_status(SpanStatus.OK)

            # End span
            self.tracer.end_span(self.span)

            # Add to collector
            get_trace_collector().add_span(self.span)

        # Reset context
        current_span.set(None)

    def __call__(self, func):
        """Use as decorator"""
        import functools

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            with self:
                return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            with self:
                return func(*args, **kwargs)

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper


def get_current_span() -> Optional[Span]:
    """Get the current active span"""
    return current_span.get()


def get_current_trace_id() -> Optional[str]:
    """Get the current trace ID"""
    span = current_span.get()
    if span:
        return span.trace_id

    context = current_trace_context.get()
    if context:
        return context.trace_id

    return None
