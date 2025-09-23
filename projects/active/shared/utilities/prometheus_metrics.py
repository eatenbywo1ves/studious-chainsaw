"""
Prometheus Metrics Integration for Enterprise AI Platform
Provides standardized metrics collection across all services
"""

import time
import logging
from typing import Dict, Optional
from functools import wraps
from dataclasses import dataclass
import asyncio
import psutil
import threading

try:
    from prometheus_client import (
        Counter,
        Histogram,
        Gauge,
        Summary,
        Info,
        CollectorRegistry,
        generate_latest,
        CONTENT_TYPE_LATEST,
    )

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

    # Fallback implementations
    class Counter:
        def __init__(self, *args, **kwargs):
            pass

        def inc(self, *args, **kwargs):
            pass

    class Histogram:
        def __init__(self, *args, **kwargs):
            pass

        def observe(self, *args, **kwargs):
            pass

        def time(self):
            return _DummyTimer()

    class Gauge:
        def __init__(self, *args, **kwargs):
            pass

        def set(self, *args, **kwargs):
            pass

        def inc(self, *args, **kwargs):
            pass

        def dec(self, *args, **kwargs):
            pass

    class Summary:
        def __init__(self, *args, **kwargs):
            pass

        def observe(self, *args, **kwargs):
            pass

    class Info:
        def __init__(self, *args, **kwargs):
            pass

        def info(self, *args, **kwargs):
            pass

    class _DummyTimer:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass


@dataclass
class MetricsConfig:
    """Configuration for Prometheus metrics"""

    service_name: str
    namespace: str = "enterprise_ai"
    enable_system_metrics: bool = True
    metrics_port: Optional[int] = None
    push_gateway_url: Optional[str] = None
    collection_interval: float = 15.0


class PrometheusMetrics:
    """Centralized Prometheus metrics manager"""

    def __init__(self, config: MetricsConfig):
        self.config = config
        self.registry = CollectorRegistry()
        self.logger = logging.getLogger(f"metrics.{config.service_name}")

        # Core application metrics
        self.request_count = Counter(
            "http_requests_total",
            "Total number of HTTP requests",
            ["method", "endpoint", "status_code", "service"],
            registry=self.registry,
        )

        self.request_duration = Histogram(
            "http_request_duration_seconds",
            "HTTP request duration in seconds",
            ["method", "endpoint", "service"],
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
            registry=self.registry,
        )

        self.request_size = Histogram(
            "http_request_size_bytes",
            "HTTP request size in bytes",
            ["method", "endpoint", "service"],
            registry=self.registry,
        )

        self.response_size = Histogram(
            "http_response_size_bytes",
            "HTTP response size in bytes",
            ["method", "endpoint", "service"],
            registry=self.registry,
        )

        # Business logic metrics
        self.active_connections = Gauge(
            "active_connections",
            "Number of active connections",
            ["service"],
            registry=self.registry,
        )

        self.service_health = Gauge(
            "service_health_status",
            "Service health status (1=healthy, 0=unhealthy)",
            ["service", "component"],
            registry=self.registry,
        )

        self.custom_counters: Dict[str, Counter] = {}
        self.custom_gauges: Dict[str, Gauge] = {}
        self.custom_histograms: Dict[str, Histogram] = {}

        # Service information
        self.service_info = Info(
            "service_info", "Service information", registry=self.registry
        )

        # System metrics (if enabled)
        if config.enable_system_metrics:
            self._setup_system_metrics()

        # Set service info
        self.service_info.info(
            {
                "service": config.service_name,
                "namespace": config.namespace,
                "version": "1.0.0",
            }
        )

        self._start_system_collection()

    def _setup_system_metrics(self):
        """Set up system-level metrics"""
        self.cpu_usage = Gauge(
            "system_cpu_usage_percent",
            "System CPU usage percentage",
            ["service"],
            registry=self.registry,
        )

        self.memory_usage = Gauge(
            "system_memory_usage_bytes",
            "System memory usage in bytes",
            ["service", "type"],
            registry=self.registry,
        )

        self.disk_usage = Gauge(
            "system_disk_usage_bytes",
            "System disk usage in bytes",
            ["service", "type"],
            registry=self.registry,
        )

        self.network_bytes = Counter(
            "system_network_bytes_total",
            "Total network bytes",
            ["service", "direction"],
            registry=self.registry,
        )

    def _start_system_collection(self):
        """Start background system metrics collection"""
        if not self.config.enable_system_metrics:
            return

        def collect_system_metrics():
            while True:
                try:
                    # CPU usage
                    cpu_percent = psutil.cpu_percent(interval=1)
                    self.cpu_usage.labels(service=self.config.service_name).set(
                        cpu_percent
                    )

                    # Memory usage
                    memory = psutil.virtual_memory()
                    self.memory_usage.labels(
                        service=self.config.service_name, type="used"
                    ).set(memory.used)
                    self.memory_usage.labels(
                        service=self.config.service_name, type="total"
                    ).set(memory.total)

                    # Disk usage
                    disk = psutil.disk_usage("/")
                    self.disk_usage.labels(
                        service=self.config.service_name, type="used"
                    ).set(disk.used)
                    self.disk_usage.labels(
                        service=self.config.service_name, type="total"
                    ).set(disk.total)

                    # Network I/O
                    network = psutil.net_io_counters()
                    self.network_bytes.labels(
                        service=self.config.service_name, direction="sent"
                    )._value._value = network.bytes_sent
                    self.network_bytes.labels(
                        service=self.config.service_name, direction="recv"
                    )._value._value = network.bytes_recv

                except Exception as e:
                    self.logger.error(f"Error collecting system metrics: {e}")

                time.sleep(self.config.collection_interval)

        # Start background thread
        metrics_thread = threading.Thread(target=collect_system_metrics, daemon=True)
        metrics_thread.start()

    def record_request(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        duration: float,
        request_size: Optional[int] = None,
        response_size: Optional[int] = None,
    ):
        """Record HTTP request metrics"""
        labels = {
            "method": method,
            "endpoint": endpoint,
            "status_code": str(status_code),
            "service": self.config.service_name,
        }

        self.request_count.labels(**labels).inc()
        self.request_duration.labels(
            method=method, endpoint=endpoint, service=self.config.service_name
        ).observe(duration)

        if request_size is not None:
            self.request_size.labels(
                method=method, endpoint=endpoint, service=self.config.service_name
            ).observe(request_size)

        if response_size is not None:
            self.response_size.labels(
                method=method, endpoint=endpoint, service=self.config.service_name
            ).observe(response_size)

    def set_active_connections(self, count: int):
        """Update active connections count"""
        self.active_connections.labels(service=self.config.service_name).set(count)

    def set_service_health(self, component: str, healthy: bool):
        """Update service health status"""
        self.service_health.labels(
            service=self.config.service_name, component=component
        ).set(1 if healthy else 0)

    def get_counter(
        self, name: str, description: str, labels: Optional[list] = None
    ) -> Counter:
        """Get or create a custom counter"""
        if name not in self.custom_counters:
            self.custom_counters[name] = Counter(
                name, description, labels or [], registry=self.registry
            )
        return self.custom_counters[name]

    def get_gauge(
        self, name: str, description: str, labels: Optional[list] = None
    ) -> Gauge:
        """Get or create a custom gauge"""
        if name not in self.custom_gauges:
            self.custom_gauges[name] = Gauge(
                name, description, labels or [], registry=self.registry
            )
        return self.custom_gauges[name]

    def get_histogram(
        self,
        name: str,
        description: str,
        labels: Optional[list] = None,
        buckets: Optional[tuple] = None,
    ) -> Histogram:
        """Get or create a custom histogram"""
        if name not in self.custom_histograms:
            self.custom_histograms[name] = Histogram(
                name, description, labels or [], buckets=buckets, registry=self.registry
            )
        return self.custom_histograms[name]

    def generate_metrics(self) -> bytes:
        """Generate Prometheus metrics output"""
        return generate_latest(self.registry)

    def get_content_type(self) -> str:
        """Get Prometheus content type"""
        return CONTENT_TYPE_LATEST


# Decorator for automatic request timing
def track_requests(metrics: PrometheusMetrics):
    """Decorator to automatically track HTTP requests"""

    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                response = await func(*args, **kwargs)
                duration = time.time() - start_time

                # Extract request info from aiohttp request if available
                if len(args) > 0 and hasattr(args[0], "method"):
                    request = args[0]
                    metrics.record_request(
                        method=request.method,
                        endpoint=request.path,
                        status_code=getattr(response, "status", 200),
                        duration=duration,
                    )

                return response
            except Exception as e:
                duration = time.time() - start_time
                if len(args) > 0 and hasattr(args[0], "method"):
                    request = args[0]
                    metrics.record_request(
                        method=request.method,
                        endpoint=request.path,
                        status_code=500,
                        duration=duration,
                    )
                raise

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                response = func(*args, **kwargs)
                time.time() - start_time
                # Similar logic for synchronous functions
                return response
            except Exception:
                time.time() - start_time
                raise

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    return decorator


# Global metrics registry
_metrics_instances: Dict[str, PrometheusMetrics] = {}


def get_metrics(
    service_name: str, config: Optional[MetricsConfig] = None
) -> PrometheusMetrics:
    """Get or create metrics instance for a service"""
    if service_name not in _metrics_instances:
        if config is None:
            config = MetricsConfig(service_name=service_name)
        _metrics_instances[service_name] = PrometheusMetrics(config)
    return _metrics_instances[service_name]


def create_metrics_endpoint():
    """Create a metrics endpoint handler for web frameworks"""

    async def metrics_handler(request):
        service_name = getattr(request.app, "service_name", "unknown")
        metrics = get_metrics(service_name)

        return {
            "body": metrics.generate_metrics(),
            "content_type": metrics.get_content_type(),
        }

    return metrics_handler
