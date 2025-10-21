#!/usr/bin/env python3
"""
Health Checker - Advanced health checking for services

Provides TCP port checking and HTTP endpoint validation beyond simple port availability.
"""

import time
import socket
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
from datetime import datetime


try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logging.warning("requests library not available - HTTP health checks disabled")


logger = logging.getLogger('workspace_manager.health')


@dataclass
class HealthCheckResult:
    """Result of a health check operation"""
    healthy: bool
    latency_ms: float
    check_type: str
    timestamp: str
    status_code: Optional[int] = None
    error: Optional[str] = None
    response_body: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

    def __str__(self) -> str:
        status = "✓ Healthy" if self.healthy else "✗ Unhealthy"
        details = f"{self.check_type.upper()}: {status} ({self.latency_ms:.0f}ms)"

        if self.status_code:
            details += f" [HTTP {self.status_code}]"
        if self.error:
            details += f" - {self.error}"

        return details


class HealthChecker:
    """Advanced health checking for services"""

    def __init__(self, timeout: int = 5):
        """
        Initialize health checker

        Args:
            timeout: Default timeout in seconds for health checks
        """
        self.timeout = timeout
        self.check_history = []

    def check_tcp_port(self, host: str, port: int, timeout: Optional[int] = None) -> HealthCheckResult:
        """
        Check if TCP port is available

        Args:
            host: Host to check
            port: Port number
            timeout: Connection timeout in seconds (default: self.timeout)

        Returns:
            HealthCheckResult with connection status
        """
        timeout = timeout or self.timeout
        start_time = time.time()
        error_msg = None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()

            latency_ms = (time.time() - start_time) * 1000
            healthy = (result == 0)

            if not healthy:
                error_msg = f"Connection failed (error code: {result})"

            return HealthCheckResult(
                healthy=healthy,
                latency_ms=latency_ms,
                check_type='tcp',
                timestamp=datetime.now().isoformat(),
                error=error_msg
            )

        except socket.timeout:
            latency_ms = timeout * 1000
            return HealthCheckResult(
                healthy=False,
                latency_ms=latency_ms,
                check_type='tcp',
                timestamp=datetime.now().isoformat(),
                error=f"Connection timeout after {timeout}s"
            )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                healthy=False,
                latency_ms=latency_ms,
                check_type='tcp',
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )

    def check_http_endpoint(self, url: str, timeout: Optional[int] = None,
                           expected_status: int = 200,
                           verify_ssl: bool = True) -> HealthCheckResult:
        """
        Check HTTP/HTTPS endpoint health

        Args:
            url: Full URL to check (e.g., http://localhost:8000/health)
            timeout: Request timeout in seconds (default: self.timeout)
            expected_status: Expected HTTP status code (default: 200)
            verify_ssl: Verify SSL certificates (default: True)

        Returns:
            HealthCheckResult with HTTP response status
        """
        if not REQUESTS_AVAILABLE:
            return HealthCheckResult(
                healthy=False,
                latency_ms=0.0,
                check_type='http',
                timestamp=datetime.now().isoformat(),
                error="requests library not available"
            )

        timeout = timeout or self.timeout
        start_time = time.time()

        try:
            response = requests.get(url, timeout=timeout, verify=verify_ssl)
            latency_ms = (time.time() - start_time) * 1000

            healthy = (response.status_code == expected_status)
            error_msg = None if healthy else f"Expected status {expected_status}, got {response.status_code}"

            # Get response body (limited to first 200 chars)
            response_body = response.text[:200] if response.text else None

            return HealthCheckResult(
                healthy=healthy,
                latency_ms=latency_ms,
                check_type='http',
                timestamp=datetime.now().isoformat(),
                status_code=response.status_code,
                response_body=response_body,
                error=error_msg
            )

        except requests.exceptions.Timeout:
            latency_ms = timeout * 1000
            return HealthCheckResult(
                healthy=False,
                latency_ms=latency_ms,
                check_type='http',
                timestamp=datetime.now().isoformat(),
                error=f"HTTP request timeout after {timeout}s"
            )

        except requests.exceptions.ConnectionError as e:
            latency_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                healthy=False,
                latency_ms=latency_ms,
                check_type='http',
                timestamp=datetime.now().isoformat(),
                error=f"Connection error: {str(e)[:100]}"
            )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                healthy=False,
                latency_ms=latency_ms,
                check_type='http',
                timestamp=datetime.now().isoformat(),
                error=str(e)[:100]
            )

    def wait_for_health(self, check_func, *args, max_wait: int = 30,
                       check_interval: float = 1.0, **kwargs) -> HealthCheckResult:
        """
        Wait for service to become healthy

        Args:
            check_func: Health check function (check_tcp_port or check_http_endpoint)
            *args: Arguments for check function
            max_wait: Maximum time to wait in seconds
            check_interval: Seconds between check attempts
            **kwargs: Keyword arguments for check function

        Returns:
            Final HealthCheckResult (either healthy or timed out)
        """
        start_time = time.time()
        last_result = None

        while time.time() - start_time < max_wait:
            result = check_func(*args, **kwargs)
            last_result = result

            if result.healthy:
                logger.info(
                    f"Service became healthy after {time.time() - start_time:.1f}s",
                    extra={
                        'wait_time_seconds': round(time.time() - start_time, 2),
                        'latency_ms': round(result.latency_ms, 2),
                        'check_type': result.check_type
                    }
                )
                return result

            # Wait before next check
            time.sleep(check_interval)

        # Timeout reached
        total_wait = time.time() - start_time
        logger.warning(
            f"Service did not become healthy after {total_wait:.1f}s",
            extra={
                'wait_time_seconds': round(total_wait, 2),
                'max_wait_seconds': max_wait,
                'last_error': last_result.error if last_result else None
            }
        )

        return last_result or HealthCheckResult(
            healthy=False,
            latency_ms=total_wait * 1000,
            check_type='timeout',
            timestamp=datetime.now().isoformat(),
            error=f"Health check timeout after {max_wait}s"
        )

    def check_tcp_port_smart(self, host: str, port: int, max_wait: int = 30) -> HealthCheckResult:
        """
        Check TCP port with exponential backoff between attempts

        Args:
            host: Host to check
            port: Port number
            max_wait: Maximum time to wait in seconds

        Returns:
            HealthCheckResult when port is available or timeout reached
        """
        delays = [0.1, 0.2, 0.5, 1, 2, 5, 10]  # Exponential backoff intervals
        start_time = time.time()

        for delay in delays:
            # Check if we've exceeded max wait time
            if time.time() - start_time > max_wait:
                return HealthCheckResult(
                    healthy=False,
                    latency_ms=(time.time() - start_time) * 1000,
                    check_type='tcp',
                    timestamp=datetime.now().isoformat(),
                    error=f"Timeout after {max_wait}s"
                )

            # Wait before checking
            time.sleep(delay)

            # Perform health check
            result = self.check_tcp_port(host, port, timeout=1)

            if result.healthy:
                result.latency_ms = (time.time() - start_time) * 1000
                return result

        # Final attempt after all delays
        return self.check_tcp_port(host, port)

    def monitor_service(self, check_func, *args, interval: int = 60, max_failures: int = 3, **kwargs):
        """
        Continuously monitor service health

        Args:
            check_func: Health check function
            *args: Arguments for check function
            interval: Seconds between checks
            max_failures: Number of consecutive failures before alerting
            **kwargs: Keyword arguments for check function

        Yields:
            HealthCheckResult for each check
        """
        consecutive_failures = 0

        while True:
            result = check_func(*args, **kwargs)

            # Track failures
            if not result.healthy:
                consecutive_failures += 1
                if consecutive_failures >= max_failures:
                    logger.error(
                        f"Service unhealthy for {consecutive_failures} consecutive checks",
                        extra={
                            'consecutive_failures': consecutive_failures,
                            'max_failures': max_failures,
                            'error': result.error
                        }
                    )
            else:
                if consecutive_failures > 0:
                    logger.info(f"Service recovered after {consecutive_failures} failures")
                consecutive_failures = 0

            # Store in history
            self.check_history.append(result.to_dict())

            # Limit history size
            if len(self.check_history) > 1000:
                self.check_history = self.check_history[-500:]

            yield result

            time.sleep(interval)

    def get_health_stats(self, limit: int = 100) -> Dict[str, Any]:
        """
        Get statistics from recent health checks

        Args:
            limit: Number of recent checks to analyze

        Returns:
            Dictionary with health check statistics
        """
        recent = self.check_history[-limit:]

        if not recent:
            return {
                'total_checks': 0,
                'healthy_count': 0,
                'unhealthy_count': 0,
                'health_rate': 0.0,
                'avg_latency_ms': 0.0
            }

        healthy = sum(1 for check in recent if check['healthy'])
        unhealthy = len(recent) - healthy

        return {
            'total_checks': len(recent),
            'healthy_count': healthy,
            'unhealthy_count': unhealthy,
            'health_rate': round(healthy / len(recent) * 100, 2) if recent else 0.0,
            'avg_latency_ms': round(sum(c['latency_ms'] for c in recent) / len(recent), 2) if recent else 0.0,
            'check_types': list(set(c['check_type'] for c in recent))
        }


# Example usage and testing
if __name__ == '__main__':

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    checker = HealthChecker(timeout=5)

    print("\n=== Health Checker Test Suite ===\n")

    # Test 1: TCP Port Check (localhost)
    print("Test 1: TCP Port Check")
    print("-" * 40)

    # Check a port that's likely open (HTTP)
    result = checker.check_tcp_port('localhost', 80)
    print(f"Port 80: {result}")

    # Check a port that's likely closed
    result = checker.check_tcp_port('localhost', 9999)
    print(f"Port 9999: {result}")

    # Test 2: HTTP Endpoint Check (if requests available)
    if REQUESTS_AVAILABLE:
        print("\nTest 2: HTTP Endpoint Check")
        print("-" * 40)

        # Check a real endpoint (example.com)
        result = checker.check_http_endpoint('http://example.com', timeout=10)
        print(f"example.com: {result}")

        # Check non-existent endpoint
        result = checker.check_http_endpoint('http://localhost:9999/health', timeout=2)
        print(f"localhost:9999: {result}")

    # Test 3: Smart TCP Check with Exponential Backoff
    print("\nTest 3: Smart TCP Check (Exponential Backoff)")
    print("-" * 40)
    result = checker.check_tcp_port_smart('localhost', 80, max_wait=10)
    print(f"Smart check result: {result}")

    # Test 4: Health Statistics
    print("\nTest 4: Health Check Statistics")
    print("-" * 40)
    stats = checker.get_health_stats()
    print(f"Statistics: {stats}")

    print("\nAll tests complete!")
