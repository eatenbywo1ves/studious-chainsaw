"""
ML-SecTest Framework - Prometheus Metrics
==========================================
Metrics collection and export for production monitoring.

Provides:
- Scan execution metrics
- Vulnerability detection counters
- Agent performance histograms
- System health gauges
"""

from prometheus_client import Counter, Histogram, Gauge, Info
from typing import Callable, Any
from functools import wraps
import time

# ============================================================================
# Metric Definitions
# ============================================================================

# Scan execution metrics
scan_requests_total = Counter(
    'ml_sectest_scan_requests_total',
    'Total number of scan requests received',
    ['challenge_type', 'status']
)

scan_duration_seconds = Histogram(
    'ml_sectest_scan_duration_seconds',
    'Duration of security scans in seconds',
    ['challenge_type', 'parallel_mode'],
    buckets=(5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0)
)

# Agent-specific metrics
agent_executions_total = Counter(
    'ml_sectest_agent_executions_total',
    'Total number of agent executions',
    ['agent_name', 'status']
)

agent_duration_seconds = Histogram(
    'ml_sectest_agent_duration_seconds',
    'Duration of individual agent executions',
    ['agent_name'],
    buckets=(1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0)
)

# Vulnerability detection metrics
vulnerabilities_found_total = Counter(
    'ml_sectest_vulnerabilities_found_total',
    'Total number of vulnerabilities detected',
    ['vulnerability_type', 'severity', 'agent_name']
)

vulnerabilities_by_severity = Gauge(
    'ml_sectest_vulnerabilities_by_severity',
    'Current count of vulnerabilities by severity',
    ['severity']
)

# System health metrics
active_scans = Gauge(
    'ml_sectest_active_scans',
    'Number of currently running scans'
)

agents_available = Gauge(
    'ml_sectest_agents_available',
    'Number of available security testing agents'
)

# Framework information
framework_info = Info(
    'ml_sectest_framework',
    'ML-SecTest Framework information'
)

# API metrics (when API is deployed)
api_requests_total = Counter(
    'ml_sectest_api_requests_total',
    'Total HTTP requests to API',
    ['method', 'endpoint', 'status_code']
)

api_request_duration_seconds = Histogram(
    'ml_sectest_api_request_duration_seconds',
    'API request duration in seconds',
    ['method', 'endpoint'],
    buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0)
)


# ============================================================================
# Metric Decorator Classes
# ============================================================================

class MetricsCollector:
    """Provides decorators for automatic metrics collection."""

    @staticmethod
    def track_scan(challenge_type: str, parallel: bool = False):
        """
        Decorator to track scan execution metrics.

        Args:
            challenge_type: Name of the challenge being scanned
            parallel: Whether parallel execution is enabled

        Example:
            @MetricsCollector.track_scan("vault", parallel=True)
            def run_vault_scan(target_url):
                # scan implementation
                pass
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                start_time = time.time()
                active_scans.inc()

                try:
                    result = func(*args, **kwargs)
                    scan_requests_total.labels(
                        challenge_type=challenge_type,
                        status='success'
                    ).inc()
                    return result

                except Exception:
                    scan_requests_total.labels(
                        challenge_type=challenge_type,
                        status='error'
                    ).inc()
                    raise

                finally:
                    duration = time.time() - start_time
                    scan_duration_seconds.labels(
                        challenge_type=challenge_type,
                        parallel_mode='parallel' if parallel else 'sequential'
                    ).observe(duration)
                    active_scans.dec()

            return wrapper
        return decorator

    @staticmethod
    def track_agent(agent_name: str):
        """
        Decorator to track individual agent execution metrics.

        Args:
            agent_name: Name of the security testing agent

        Example:
            @MetricsCollector.track_agent("PromptInjectionAgent")
            def execute_agent(target_url):
                # agent execution
                pass
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                start_time = time.time()

                try:
                    result = func(*args, **kwargs)
                    agent_executions_total.labels(
                        agent_name=agent_name,
                        status='success'
                    ).inc()
                    return result

                except Exception:
                    agent_executions_total.labels(
                        agent_name=agent_name,
                        status='error'
                    ).inc()
                    raise

                finally:
                    duration = time.time() - start_time
                    agent_duration_seconds.labels(
                        agent_name=agent_name
                    ).observe(duration)

            return wrapper
        return decorator

    @staticmethod
    def track_api_request(method: str, endpoint: str):
        """
        Decorator to track API request metrics.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path

        Example:
            @MetricsCollector.track_api_request("POST", "/api/v1/scan")
            async def create_scan(request):
                # API handler
                pass
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                start_time = time.time()
                status_code = 200

                try:
                    result = await func(*args, **kwargs)
                    return result

                except Exception:
                    status_code = 500
                    raise

                finally:
                    duration = time.time() - start_time

                    api_requests_total.labels(
                        method=method,
                        endpoint=endpoint,
                        status_code=status_code
                    ).inc()

                    api_request_duration_seconds.labels(
                        method=method,
                        endpoint=endpoint
                    ).observe(duration)

            return wrapper
        return decorator


# ============================================================================
# Metric Helper Functions
# ============================================================================

def record_vulnerability(
    vuln_type: str,
    severity: str,
    agent_name: str
) -> None:
    """
    Record a discovered vulnerability.

    Args:
        vuln_type: Type of vulnerability (e.g., 'prompt_injection')
        severity: Severity level (low, medium, high, critical)
        agent_name: Agent that discovered the vulnerability
    """
    vulnerabilities_found_total.labels(
        vulnerability_type=vuln_type,
        severity=severity,
        agent_name=agent_name
    ).inc()

    # Update gauge for dashboard visualization
    vulnerabilities_by_severity.labels(severity=severity).inc()


def set_available_agents(count: int) -> None:
    """
    Set the number of available agents.

    Args:
        count: Number of available security testing agents
    """
    agents_available.set(count)


def initialize_framework_info(version: str = "1.0.0") -> None:
    """
    Initialize framework information metric.

    Args:
        version: Framework version string
    """
    framework_info.info({
        'version': version,
        'name': 'ML-SecTest',
        'description': 'Multi-Agent ML Security Testing Framework'
    })


def reset_vulnerability_counts() -> None:
    """Reset vulnerability count gauges (useful for periodic resets)."""
    for severity in ['low', 'medium', 'high', 'critical']:
        vulnerabilities_by_severity.labels(severity=severity).set(0)


# ============================================================================
# Metrics Export for Prometheus
# ============================================================================

def start_metrics_server(port: int = 9090) -> None:
    """
    Start Prometheus metrics HTTP server.

    Args:
        port: Port to expose metrics on (default: 9090)

    Example:
        start_metrics_server(port=9090)
        # Metrics available at http://localhost:9090/metrics
    """
    from prometheus_client import start_http_server
    start_http_server(port)
    print(f"📊 Metrics server started on port {port}")
    print(f"   Access metrics at: http://localhost:{port}/metrics")


# ============================================================================
# Usage Example
# ============================================================================

if __name__ == "__main__":
    # Initialize framework info
    initialize_framework_info("1.0.0")

    # Set available agents
    set_available_agents(6)

    # Example: Track a scan
    @MetricsCollector.track_scan("vault", parallel=False)
    def example_scan():
        import time
        time.sleep(2)  # Simulate scan
        return {"status": "completed"}

    # Example: Record vulnerability
    record_vulnerability(
        vuln_type="prompt_injection",
        severity="high",
        agent_name="PromptInjectionAgent"
    )

    # Start metrics server
    start_metrics_server(9090)

    # Run example scan
    result = example_scan()

    print("✓ Metrics example completed")
    print("  Visit http://localhost:9090/metrics to see Prometheus metrics")

    # Keep server running
    import time
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n✓ Metrics server stopped")
