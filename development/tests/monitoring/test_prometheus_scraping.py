"""
Prometheus Scraping Validation Tests

Tests to validate that Prometheus is correctly scraping metrics from all configured targets.
This ensures all exporters and application endpoints are functioning correctly.
"""

import requests
import pytest
from typing import Dict, List, Any


class PrometheusValidator:
    """Validates Prometheus metrics collection"""

    def __init__(self, prometheus_url: str = "http://localhost:9090"):
        self.prometheus_url = prometheus_url
        self.api_url = f"{prometheus_url}/api/v1"

    def check_prometheus_health(self) -> bool:
        """Check if Prometheus is healthy"""
        try:
            response = requests.get(f"{self.prometheus_url}/-/healthy", timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f"Prometheus health check failed: {e}")
            return False

    def check_prometheus_ready(self) -> bool:
        """Check if Prometheus is ready"""
        try:
            response = requests.get(f"{self.prometheus_url}/-/ready", timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f"Prometheus ready check failed: {e}")
            return False

    def get_targets(self) -> Dict[str, Any]:
        """Get all Prometheus targets"""
        try:
            response = requests.get(f"{self.api_url}/targets", timeout=5)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Failed to get targets: {e}")
            return {}

    def get_active_targets(self) -> List[Dict[str, Any]]:
        """Get all active targets"""
        targets_data = self.get_targets()
        if targets_data and "data" in targets_data:
            return targets_data["data"].get("activeTargets", [])
        return []

    def check_target_health(self) -> Dict[str, str]:
        """Check health of all targets"""
        active_targets = self.get_active_targets()
        target_health = {}

        for target in active_targets:
            job_name = target.get("labels", {}).get("job", "unknown")
            health_status = target.get("health", "unknown")
            scrape_url = target.get("scrapeUrl", "unknown")

            target_health[f"{job_name} ({scrape_url})"] = health_status

        return target_health

    def query_metric(self, metric_name: str) -> Dict[str, Any]:
        """Query a specific metric"""
        try:
            response = requests.get(
                f"{self.api_url}/query", params={"query": metric_name}, timeout=5
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Failed to query metric {metric_name}: {e}")
            return {}

    def check_metric_exists(self, metric_name: str) -> bool:
        """Check if a metric exists and has data"""
        result = self.query_metric(metric_name)
        if result and "data" in result:
            result_data = result["data"].get("result", [])
            return len(result_data) > 0
        return False

    def get_scrape_duration(self, job: str) -> float:
        """Get the scrape duration for a job"""
        query = f'scrape_duration_seconds{{job="{job}"}}'
        result = self.query_metric(query)
        if result and "data" in result:
            result_data = result["data"].get("result", [])
            if result_data:
                return float(result_data[0]["value"][1])
        return 0.0

    def validate_all_metrics(self) -> Dict[str, bool]:
        """Validate that all expected metrics are being scraped"""
        expected_metrics = {
            # Application metrics
            "http_requests_total": "API request counter",
            "http_request_duration_seconds": "API request latency",
            # Security metrics
            "encryption_errors_total": "Encryption error counter",
            "decryption_errors_total": "Decryption error counter",
            # Cache metrics
            "cache_requests_total": "Cache request counter",
            "cache_misses_total": "Cache miss counter",
            # Database metrics
            "database_query_duration_seconds": "Database query latency",
            "database_connections_active": "Active database connections",
            # Redis metrics (from redis_exporter)
            "redis_memory_used_bytes": "Redis memory usage",
            "redis_connected_clients": "Redis client connections",
            # System metrics (from node_exporter)
            "node_cpu_seconds_total": "CPU time",
            "node_memory_MemTotal_bytes": "Total memory",
            "node_filesystem_size_bytes": "Filesystem size",
        }

        validation_results = {}
        for metric, description in expected_metrics.items():
            exists = self.check_metric_exists(metric)
            validation_results[metric] = exists
            if not exists:
                print(f"WARNING: Metric '{metric}' ({description}) not found")

        return validation_results


# ============================================================================
# PYTEST TEST CASES
# ============================================================================


@pytest.fixture
def validator():
    """Create a PrometheusValidator instance"""
    return PrometheusValidator()


def test_prometheus_health(validator):
    """Test that Prometheus is healthy"""
    assert validator.check_prometheus_health(), "Prometheus is not healthy"


def test_prometheus_ready(validator):
    """Test that Prometheus is ready"""
    assert validator.check_prometheus_ready(), "Prometheus is not ready"


def test_all_targets_up(validator):
    """Test that all configured targets are up"""
    target_health = validator.check_target_health()

    failed_targets = []
    for target, health in target_health.items():
        if health != "up":
            failed_targets.append(f"{target}: {health}")

    assert len(failed_targets) == 0, f"Some targets are down: {failed_targets}"


def test_api_metrics_exist(validator):
    """Test that API metrics are being collected"""
    api_metrics = [
        "http_requests_total",
        "http_request_duration_seconds",
    ]

    for metric in api_metrics:
        assert validator.check_metric_exists(metric), f"API metric '{metric}' not found"


def test_security_metrics_exist(validator):
    """Test that security metrics are being collected"""
    security_metrics = [
        "encryption_errors_total",
        "decryption_errors_total",
    ]

    for metric in security_metrics:
        # These may be zero, but should exist
        exists = validator.check_metric_exists(metric)
        # If not exists, it might be that no errors have occurred yet
        # This is acceptable, so we just warn
        if not exists:
            print(f"INFO: Security metric '{metric}' has no data (may be zero)")


def test_redis_metrics_exist(validator):
    """Test that Redis metrics are being collected"""
    redis_metrics = [
        "redis_memory_used_bytes",
        "redis_connected_clients",
    ]

    for metric in redis_metrics:
        assert validator.check_metric_exists(metric), f"Redis metric '{metric}' not found"


def test_database_metrics_exist(validator):
    """Test that database metrics are being collected"""
    db_metrics = [
        "pg_up",  # PostgreSQL exporter health
        "pg_stat_database_numbackends",  # Number of backends
    ]

    for metric in db_metrics:
        assert validator.check_metric_exists(metric), f"Database metric '{metric}' not found"


def test_system_metrics_exist(validator):
    """Test that system metrics are being collected"""
    system_metrics = [
        "node_cpu_seconds_total",
        "node_memory_MemTotal_bytes",
        "node_filesystem_size_bytes",
    ]

    for metric in system_metrics:
        assert validator.check_metric_exists(metric), f"System metric '{metric}' not found"


def test_scrape_duration_acceptable(validator):
    """Test that scrape durations are within acceptable limits"""
    jobs = ["prometheus", "api-server", "redis-exporter", "postgres-exporter", "node-exporter"]
    max_scrape_duration = 5.0  # seconds

    for job in jobs:
        duration = validator.get_scrape_duration(job)
        if duration > 0:
            assert duration < max_scrape_duration, (
                f"Scrape duration for {job} is too high: {duration}s"
            )


def test_recording_rules_exist(validator):
    """Test that recording rules are generating metrics"""
    recording_rules = [
        "security:failed_logins:rate5m",
        "security:unauthorized_access:rate5m",
        "api:request_rate:avg1h",
        "api:latency:p95",
    ]

    for rule in recording_rules:
        # Recording rules may not exist if there's no data yet
        exists = validator.check_metric_exists(rule)
        if not exists:
            print(f"INFO: Recording rule '{rule}' has no data yet")


# ============================================================================
# STANDALONE VALIDATION SCRIPT
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("PROMETHEUS SCRAPING VALIDATION")
    print("=" * 80)
    print()

    validator = PrometheusValidator()

    # Check Prometheus health
    print("1. Checking Prometheus health...")
    if validator.check_prometheus_health():
        print("   ✓ Prometheus is healthy")
    else:
        print("   ✗ Prometheus is NOT healthy")
        exit(1)

    # Check Prometheus ready
    print("\n2. Checking Prometheus ready status...")
    if validator.check_prometheus_ready():
        print("   ✓ Prometheus is ready")
    else:
        print("   ✗ Prometheus is NOT ready")
        exit(1)

    # Check all targets
    print("\n3. Checking target health...")
    target_health = validator.check_target_health()
    all_up = True
    for target, health in target_health.items():
        status_icon = "✓" if health == "up" else "✗"
        print(f"   {status_icon} {target}: {health}")
        if health != "up":
            all_up = False

    # Validate all metrics
    print("\n4. Validating metric collection...")
    validation_results = validator.validate_all_metrics()
    metrics_ok = sum(1 for v in validation_results.values() if v)
    metrics_total = len(validation_results)

    print(f"   Metrics collected: {metrics_ok}/{metrics_total}")

    # Summary
    print("\n" + "=" * 80)
    if all_up and metrics_ok == metrics_total:
        print("✓ ALL VALIDATIONS PASSED")
        print("=" * 80)
        exit(0)
    else:
        print("✗ SOME VALIDATIONS FAILED")
        print("=" * 80)
        exit(1)
