"""
Production monitoring with Prometheus metrics and health checks
"""

from prometheus_client import Counter, Histogram, Gauge, Info, CollectorRegistry
from prometheus_client.exposition import generate_latest
from typing import Dict, Any, Optional
import time
import psutil
import asyncio
from datetime import datetime
from functools import wraps


# Initialize metrics registry
registry = CollectorRegistry()

# Define metrics
operation_counter = Counter(
    'catalytic_operations_total',
    'Total number of catalytic operations',
    ['operation_type', 'status'],
    registry=registry
)

operation_duration = Histogram(
    'catalytic_operation_duration_seconds',
    'Duration of catalytic operations',
    ['operation_type'],
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
    registry=registry
)

memory_usage = Gauge(
    'catalytic_memory_usage_bytes',
    'Current memory usage',
    ['memory_type'],
    registry=registry
)

catalyst_efficiency = Gauge(
    'catalytic_efficiency_ratio',
    'Memory efficiency ratio (saved/used)',
    registry=registry
)

active_catalysts = Gauge(
    'catalytic_active_catalysts',
    'Number of active catalyst memory blocks',
    registry=registry
)

error_counter = Counter(
    'catalytic_errors_total',
    'Total number of errors',
    ['error_type', 'operation'],
    registry=registry
)

system_info = Info(
    'catalytic_system_info',
    'System information',
    registry=registry
)


class MetricsCollector:
    """
    Collects and exposes metrics for monitoring
    """

    def __init__(self):
        self.start_time = time.time()
        self._update_system_info()
        self._last_health_check = time.time()
        self._health_status = "healthy"

    def _update_system_info(self):
        """Update system information metrics"""
        system_info.info({
            'version': '1.0.0',
            'python_version': '3.11',
            'start_time': datetime.utcnow().isoformat(),
            'gpu_available': 'true',  # Check actual GPU availability
        })

    def track_operation(self, operation_type: str):
        """Decorator to track operation metrics"""
        def decorator(func):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = await func(*args, **kwargs)
                    operation_counter.labels(operation_type=operation_type, status='success').inc()
                    return result
                except Exception as e:
                    operation_counter.labels(operation_type=operation_type, status='failure').inc()
                    error_counter.labels(error_type=type(e).__name__, operation=operation_type).inc()
                    raise
                finally:
                    duration = time.time() - start_time
                    operation_duration.labels(operation_type=operation_type).observe(duration)

            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    operation_counter.labels(operation_type=operation_type, status='success').inc()
                    return result
                except Exception as e:
                    operation_counter.labels(operation_type=operation_type, status='failure').inc()
                    error_counter.labels(error_type=type(e).__name__, operation=operation_type).inc()
                    raise
                finally:
                    duration = time.time() - start_time
                    operation_duration.labels(operation_type=operation_type).observe(duration)

            return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
        return decorator

    def update_memory_metrics(self, catalyst_memory: int, saved_memory: int):
        """Update memory-related metrics"""
        process = psutil.Process()
        mem_info = process.memory_info()

        memory_usage.labels(memory_type='rss').set(mem_info.rss)
        memory_usage.labels(memory_type='vms').set(mem_info.vms)
        memory_usage.labels(memory_type='catalyst').set(catalyst_memory)

        if catalyst_memory > 0:
            efficiency = saved_memory / catalyst_memory
            catalyst_efficiency.set(efficiency)

    def update_catalyst_count(self, count: int):
        """Update active catalyst count"""
        active_catalysts.set(count)

    def get_metrics(self) -> bytes:
        """Get current metrics in Prometheus format"""
        return generate_latest(registry)

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check and return status

        Returns:
            Dict containing health status and metadata
        """
        checks = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'uptime_seconds': time.time() - self.start_time,
            'checks': {}
        }

        # Check memory usage
        process = psutil.Process()
        mem_percent = process.memory_percent()
        checks['checks']['memory'] = {
            'status': 'healthy' if mem_percent < 80 else 'degraded',
            'usage_percent': mem_percent
        }

        # Check CPU usage
        cpu_percent = process.cpu_percent(interval=0.1)
        checks['checks']['cpu'] = {
            'status': 'healthy' if cpu_percent < 90 else 'degraded',
            'usage_percent': cpu_percent
        }

        # Check catalyst operations
        try:
            # Simulate catalyst integrity check
            checks['checks']['catalyst'] = {
                'status': 'healthy',
                'active_count': active_catalysts._value.get()
            }
        except Exception as e:
            checks['checks']['catalyst'] = {
                'status': 'unhealthy',
                'error': str(e)
            }

        # Overall status
        if any(check['status'] == 'unhealthy' for check in checks['checks'].values()):
            checks['status'] = 'unhealthy'
        elif any(check['status'] == 'degraded' for check in checks['checks'].values()):
            checks['status'] = 'degraded'

        self._last_health_check = time.time()
        self._health_status = checks['status']

        return checks

    def get_readiness(self) -> Dict[str, Any]:
        """
        Check if service is ready to accept requests

        Returns:
            Dict containing readiness status
        """
        return {
            'ready': self._health_status != 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'last_check': self._last_health_check
        }

    def get_liveness(self) -> Dict[str, Any]:
        """
        Check if service is alive

        Returns:
            Dict containing liveness status
        """
        return {
            'alive': True,
            'timestamp': datetime.utcnow().isoformat(),
            'uptime_seconds': time.time() - self.start_time
        }


# Global metrics collector instance
metrics_collector = MetricsCollector()