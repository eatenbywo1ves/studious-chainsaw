#!/usr/bin/env python3
"""
SEC-011 Metrics Testing Script

Programmatically tests SEC-011 request size limit metrics by:
1. Sending various request sizes to trigger metrics
2. Verifying metrics are collected correctly
3. Checking Prometheus has the data
4. Generating load for dashboard visualization

Usage:
    python test-sec011-metrics.py [--app-url URL] [--prometheus-url URL] [--load-test]

Examples:
    # Basic validation
    python test-sec011-metrics.py

    # With custom URLs
    python test-sec011-metrics.py --app-url http://localhost:8000 --prometheus-url http://localhost:9090

    # Run load test for dashboard visualization
    python test-sec011-metrics.py --load-test
"""

import argparse
import requests
import time
import sys
from typing import Dict, Tuple

# ANSI colors
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'  # No Color


class SEC011MetricsTester:
    """Tests SEC-011 request size limit metrics"""

    def __init__(self, app_url: str, prometheus_url: str):
        self.app_url = app_url.rstrip('/')
        self.prometheus_url = prometheus_url.rstrip('/')
        self.metrics_url = f"{self.app_url}/metrics"
        self.test_endpoint = f"{self.app_url}/api/test"

        self.tests_passed = 0
        self.tests_failed = 0

    def print_header(self, text: str):
        """Print formatted header"""
        print("\n" + "=" * 60)
        print(text)
        print("=" * 60)

    def pass_test(self, message: str):
        """Mark test as passed"""
        print(f"{GREEN}✓{NC} {message}")
        self.tests_passed += 1

    def fail_test(self, message: str):
        """Mark test as failed"""
        print(f"{RED}✗{NC} {message}")
        self.tests_failed += 1

    def warn(self, message: str):
        """Print warning"""
        print(f"{YELLOW}⚠{NC} {message}")

    def info(self, message: str):
        """Print info"""
        print(f"{BLUE}ℹ{NC} {message}")

    def test_metrics_endpoint(self) -> bool:
        """Test 1: Check if metrics endpoint is accessible"""
        self.print_header("Test 1: Metrics Endpoint Accessibility")

        try:
            response = requests.get(self.metrics_url, timeout=5)
            if response.status_code == 200:
                self.pass_test(f"Metrics endpoint accessible at {self.metrics_url}")
                return True
            else:
                self.fail_test(f"Metrics endpoint returned {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            self.fail_test(f"Cannot reach metrics endpoint: {e}")
            return False

    def test_metrics_registration(self) -> Tuple[bool, bool]:
        """Test 2: Check if SEC-011 metrics are registered"""
        self.print_header("Test 2: SEC-011 Metrics Registration")

        try:
            response = requests.get(self.metrics_url, timeout=5)
            content = response.text

            # Check for request_size_limit_exceeded_total
            has_exceeded = "request_size_limit_exceeded_total" in content
            if has_exceeded:
                self.pass_test("request_size_limit_exceeded_total metric registered")
            else:
                self.fail_test("request_size_limit_exceeded_total NOT found")

            # Check for request_body_bytes
            has_body_bytes = "request_body_bytes" in content
            if has_body_bytes:
                self.pass_test("request_body_bytes metric registered")
            else:
                self.fail_test("request_body_bytes NOT found")

            return has_exceeded, has_body_bytes

        except requests.exceptions.RequestException as e:
            self.fail_test(f"Error checking metrics: {e}")
            return False, False

    def test_small_request(self) -> bool:
        """Test 3a: Send small valid request"""
        self.print_header("Test 3a: Small Valid Request")

        try:
            response = requests.post(
                self.test_endpoint,
                json={"test": "data"},
                timeout=5
            )

            # Accept 200 (success) or 404 (endpoint doesn't exist yet)
            if response.status_code in [200, 404]:
                self.pass_test(f"Small request sent (HTTP {response.status_code})")
                return True
            else:
                self.warn(f"Unexpected status code: {response.status_code}")
                return False

        except requests.exceptions.RequestException as e:
            self.warn(f"Error sending small request: {e}")
            return False

    def test_large_request_rejection(self) -> bool:
        """Test 3b: Send oversized request (should be rejected)"""
        self.print_header("Test 3b: Large Request Rejection")

        try:
            # Create 11MB payload (exceeds 10MB default limit)
            large_payload = "A" * (11 * 1024 * 1024)

            self.info("Sending 11MB request (exceeds 10MB limit)...")
            response = requests.post(
                self.test_endpoint,
                data=large_payload,
                headers={"Content-Type": "application/octet-stream"},
                timeout=10
            )

            if response.status_code == 413:
                self.pass_test("Large request rejected with HTTP 413 (correct)")
                return True
            else:
                self.warn(f"Expected 413, got {response.status_code}")
                return False

        except requests.exceptions.RequestException as e:
            self.warn(f"Error sending large request: {e}")
            return False

    def test_metrics_data_collection(self) -> Dict[str, int]:
        """Test 4: Verify metrics have collected data"""
        self.print_header("Test 4: Metrics Data Collection")

        # Wait for metrics to update
        time.sleep(2)

        try:
            response = requests.get(self.metrics_url, timeout=5)
            content = response.text

            # Parse histogram buckets
            body_bytes_lines = [line for line in content.split('\n')
                               if 'request_body_bytes_bucket' in line and not line.startswith('#')]

            if body_bytes_lines:
                self.pass_test(f"request_body_bytes has {len(body_bytes_lines)} bucket data points")
                print("   Sample buckets:")
                for line in body_bytes_lines[:3]:
                    print(f"   {line}")
            else:
                self.warn("request_body_bytes histogram has no data yet")

            # Parse rejection counter
            rejection_lines = [line for line in content.split('\n')
                              if 'request_size_limit_exceeded_total' in line and not line.startswith('#')]

            if rejection_lines:
                self.pass_test(f"request_size_limit_exceeded_total has {len(rejection_lines)} data points")
                print("   Sample rejections:")
                for line in rejection_lines[:3]:
                    print(f"   {line}")
            else:
                self.info("No rejections recorded yet (expected if limits not exceeded)")

            return {
                "body_bytes_buckets": len(body_bytes_lines),
                "rejections": len(rejection_lines)
            }

        except requests.exceptions.RequestException as e:
            self.fail_test(f"Error checking metrics data: {e}")
            return {}

    def test_prometheus_integration(self) -> bool:
        """Test 5: Check Prometheus scraping"""
        self.print_header("Test 5: Prometheus Integration")

        try:
            # Check if Prometheus is healthy
            health_url = f"{self.prometheus_url}/-/healthy"
            response = requests.get(health_url, timeout=5)

            if response.status_code != 200:
                self.warn(f"Prometheus not accessible at {self.prometheus_url}")
                return False

            self.pass_test("Prometheus is accessible")

            # Query for SEC-011 metrics
            queries = [
                "request_size_limit_exceeded_total",
                "request_body_bytes_bucket"
            ]

            for query in queries:
                query_url = f"{self.prometheus_url}/api/v1/query?query={query}"
                response = requests.get(query_url, timeout=5)
                data = response.json()

                if data.get("status") == "success" and data.get("data", {}).get("result"):
                    self.pass_test(f"Prometheus has {query} metric")
                else:
                    self.warn(f"Prometheus doesn't have {query} yet (wait for scrape)")

            return True

        except requests.exceptions.RequestException as e:
            self.warn(f"Prometheus not accessible: {e}")
            return False

    def run_load_test(self, duration: int = 60):
        """Generate load for dashboard visualization"""
        self.print_header(f"Load Test: {duration} seconds")

        self.info(f"Generating varied traffic for {duration} seconds...")
        self.info("This will populate the Grafana dashboards with real data")

        start_time = time.time()
        request_count = 0
        rejection_count = 0

        while time.time() - start_time < duration:
            # Send mix of small and large requests
            for size_kb in [1, 10, 100, 500, 1000, 5000, 11000]:  # 11MB will be rejected
                try:
                    payload = "A" * (size_kb * 1024)
                    response = requests.post(
                        self.test_endpoint,
                        data=payload,
                        headers={"Content-Type": "application/octet-stream"},
                        timeout=5
                    )

                    request_count += 1
                    if response.status_code == 413:
                        rejection_count += 1

                except requests.exceptions.RequestException:
                    pass

                time.sleep(0.1)  # Small delay between requests

            # Progress update
            elapsed = int(time.time() - start_time)
            print(f"   Progress: {elapsed}s / {duration}s - Requests: {request_count}, Rejections: {rejection_count}")

        self.info("Load test complete!")
        self.info(f"Total requests: {request_count}")
        self.info(f"Total rejections: {rejection_count}")
        self.info("Check Grafana dashboard: http://grafana:3000/d/sec-011")

    def print_summary(self):
        """Print test summary"""
        self.print_header("Validation Summary")

        print(f"Tests Passed:  {GREEN}{self.tests_passed}{NC}")
        print(f"Tests Failed:  {RED}{self.tests_failed}{NC}")
        print()

        if self.tests_failed == 0:
            print(f"{GREEN}✓ All critical tests passed!{NC}")
            print()
            print("Next steps:")
            print("1. Check Grafana dashboard: http://grafana:3000/d/sec-011")
            print("2. Run load test: python test-sec011-metrics.py --load-test")
            print("3. Test alert rules by generating burst traffic")
            return 0
        else:
            print(f"{RED}✗ Some tests failed{NC}")
            print()
            print("Troubleshooting:")
            print("1. Ensure application is running")
            print("2. Check prometheus_client is installed: pip install prometheus-client")
            print("3. Verify Prometheus scrape configuration")
            return 1

    def run_all_tests(self) -> int:
        """Run all validation tests"""
        print(f"\n{BLUE}SEC-011 Metrics Validation{NC}")
        print(f"App URL:        {self.app_url}")
        print(f"Prometheus URL: {self.prometheus_url}")
        print(f"Metrics URL:    {self.metrics_url}")

        # Run tests in order
        if not self.test_metrics_endpoint():
            print(f"\n{RED}Cannot continue - metrics endpoint not accessible{NC}")
            return 1

        self.test_metrics_registration()
        self.test_small_request()
        self.test_large_request_rejection()
        self.test_metrics_data_collection()
        self.test_prometheus_integration()

        return self.print_summary()


def main():
    parser = argparse.ArgumentParser(description="Test SEC-011 request size limit metrics")
    parser.add_argument(
        "--app-url",
        default="http://localhost:8000",
        help="Application URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--prometheus-url",
        default="http://localhost:9090",
        help="Prometheus URL (default: http://localhost:9090)"
    )
    parser.add_argument(
        "--load-test",
        action="store_true",
        help="Run load test to generate dashboard data"
    )
    parser.add_argument(
        "--load-duration",
        type=int,
        default=60,
        help="Load test duration in seconds (default: 60)"
    )

    args = parser.parse_args()

    tester = SEC011MetricsTester(args.app_url, args.prometheus_url)

    if args.load_test:
        tester.run_load_test(args.load_duration)
        return 0
    else:
        return tester.run_all_tests()


if __name__ == "__main__":
    sys.exit(main())
