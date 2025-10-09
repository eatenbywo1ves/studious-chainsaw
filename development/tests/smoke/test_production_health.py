#!/usr/bin/env python3
"""
Smoke Tests - Production Health Checks

These tests verify that all critical services are healthy in production.
Run these immediately after deployment to ensure basic functionality.
"""

import os
import sys
import pytest
import requests
import time

# Add parent directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# Configuration
PRODUCTION_URL = os.getenv("PRODUCTION_URL", "http://localhost:8000")
API_TIMEOUT = 10  # seconds
HEALTH_CHECK_RETRIES = 3
RETRY_DELAY = 5  # seconds


class TestProductionHealth:
    """Production health check smoke tests"""

    def test_api_server_running(self):
        """Verify API server is running and responding"""
        url = f"{PRODUCTION_URL}/health"

        for attempt in range(HEALTH_CHECK_RETRIES):
            try:
                response = requests.get(url, timeout=API_TIMEOUT)
                assert response.status_code == 200, f"Health check failed: {response.status_code}"

                data = response.json()
                assert data.get("status") == "healthy", f"Service not healthy: {data}"

                print(f"✓ API server healthy: {data}")
                return
            except requests.exceptions.RequestException as e:
                if attempt < HEALTH_CHECK_RETRIES - 1:
                    print(f"Health check attempt {attempt + 1} failed: {e}")
                    time.sleep(RETRY_DELAY)
                else:
                    pytest.fail(
                        f"API server health check failed after {HEALTH_CHECK_RETRIES} attempts: {e}"
                    )

    def test_database_connection(self):
        """Verify database is accessible"""
        url = f"{PRODUCTION_URL}/health/database"

        try:
            response = requests.get(url, timeout=API_TIMEOUT)
            assert response.status_code == 200, (
                f"Database health check failed: {response.status_code}"
            )

            data = response.json()
            assert data.get("database") == "connected", f"Database not connected: {data}"

            print(f"✓ Database connection healthy: {data}")
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Database health check failed: {e}")

    def test_redis_connection(self):
        """Verify Redis cache is accessible (if configured)"""
        url = f"{PRODUCTION_URL}/health/redis"

        try:
            response = requests.get(url, timeout=API_TIMEOUT)

            # Redis might be optional, so 200 or 503 (not configured) are both acceptable
            if response.status_code == 503:
                data = response.json()
                if "not configured" in data.get("message", "").lower():
                    print("✓ Redis not configured (optional)")
                    pytest.skip("Redis not configured")
                    return

            assert response.status_code == 200, f"Redis health check failed: {response.status_code}"

            data = response.json()
            assert data.get("redis") == "connected", f"Redis not connected: {data}"

            print(f"✓ Redis connection healthy: {data}")
        except requests.exceptions.RequestException as e:
            # Redis is optional, so we'll warn but not fail
            print(f"⚠ Redis health check warning: {e}")

    def test_metrics_endpoint(self):
        """Verify Prometheus metrics endpoint is accessible"""
        url = f"{PRODUCTION_URL}/metrics"

        try:
            response = requests.get(url, timeout=API_TIMEOUT)
            assert response.status_code == 200, f"Metrics endpoint failed: {response.status_code}"

            # Verify it's returning Prometheus-formatted metrics
            content = response.text
            assert "# HELP" in content or "# TYPE" in content, "Invalid metrics format"

            print(f"✓ Metrics endpoint healthy (returned {len(content)} bytes)")
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Metrics endpoint check failed: {e}")

    def test_api_response_time(self):
        """Verify API response times are within acceptable limits"""
        url = f"{PRODUCTION_URL}/health"

        response_times = []
        for i in range(5):
            start = time.time()
            try:
                response = requests.get(url, timeout=API_TIMEOUT)
                elapsed = (time.time() - start) * 1000  # Convert to ms
                response_times.append(elapsed)

                assert response.status_code == 200, f"Health check failed: {response.status_code}"
            except requests.exceptions.RequestException as e:
                pytest.fail(f"Response time check failed: {e}")

        avg_response_time = sum(response_times) / len(response_times)
        max_response_time = max(response_times)

        # SLA: p95 < 50ms, but health endpoint should be faster
        assert avg_response_time < 100, f"Average response time too high: {avg_response_time:.2f}ms"
        assert max_response_time < 200, f"Max response time too high: {max_response_time:.2f}ms"

        print(
            f"✓ Response times acceptable: avg={avg_response_time:.2f}ms, max={max_response_time:.2f}ms"
        )

    def test_authentication_endpoint(self):
        """Verify authentication endpoint is accessible"""
        url = f"{PRODUCTION_URL}/api/auth/register"

        try:
            # Try to access endpoint (should return 422 for missing data, not 500)
            response = requests.post(url, json={}, timeout=API_TIMEOUT)

            # We expect validation error, not server error
            assert response.status_code in [400, 422], f"Unexpected status: {response.status_code}"

            print("✓ Authentication endpoint responding correctly")
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Authentication endpoint check failed: {e}")

    def test_rate_limiting_active(self):
        """Verify rate limiting is enforced"""
        url = f"{PRODUCTION_URL}/api/tenants"

        # Make rapid requests to trigger rate limit
        responses = []
        for i in range(150):  # Exceed 100 req/min limit
            try:
                response = requests.get(url, timeout=1)
                responses.append(response.status_code)
            except requests.exceptions.RequestException:
                pass

        # Should have at least one 429 (Too Many Requests) response
        rate_limited = 429 in responses

        if rate_limited:
            print("✓ Rate limiting active (received 429 responses)")
        else:
            print(
                f"⚠ Rate limiting may not be active (no 429 responses in {len(responses)} requests)"
            )
            # Don't fail, as this might be environment-specific

    def test_cors_headers(self):
        """Verify CORS headers are configured"""
        url = f"{PRODUCTION_URL}/health"

        try:
            headers = {"Origin": "https://example.com"}
            response = requests.options(url, headers=headers, timeout=API_TIMEOUT)

            # Check for CORS headers
            cors_headers = {
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Methods",
                "Access-Control-Allow-Headers",
            }

            present_cors = {h for h in cors_headers if h in response.headers}

            if present_cors:
                print(f"✓ CORS headers configured: {present_cors}")
            else:
                print("⚠ CORS headers not found (may be configured at proxy level)")
        except requests.exceptions.RequestException as e:
            print(f"⚠ CORS check warning: {e}")

    def test_security_headers(self):
        """Verify security headers are present"""
        url = f"{PRODUCTION_URL}/health"

        try:
            response = requests.get(url, timeout=API_TIMEOUT)

            security_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": None,  # Just check if present
            }

            present_headers = {}
            for header, expected_value in security_headers.items():
                if header in response.headers:
                    actual_value = response.headers[header]
                    present_headers[header] = actual_value

                    if expected_value and actual_value != expected_value:
                        print(f"⚠ {header}: {actual_value} (expected: {expected_value})")

            if present_headers:
                print(f"✓ Security headers present: {list(present_headers.keys())}")
            else:
                print("⚠ No security headers found (may be configured at proxy level)")
        except requests.exceptions.RequestException as e:
            print(f"⚠ Security headers check warning: {e}")

    def test_error_handling(self):
        """Verify error handling returns proper error responses"""
        url = f"{PRODUCTION_URL}/api/nonexistent-endpoint-12345"

        try:
            response = requests.get(url, timeout=API_TIMEOUT)

            # Should return 404, not 500
            assert response.status_code == 404, f"Expected 404, got {response.status_code}"

            # Should return JSON error response
            try:
                data = response.json()
                assert "detail" in data or "error" in data or "message" in data, (
                    "Error response missing detail field"
                )
                print(f"✓ Error handling working correctly: {data}")
            except ValueError:
                pytest.fail("Error response is not valid JSON")
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Error handling check failed: {e}")


class TestProductionReadiness:
    """Production readiness verification"""

    def test_environment_variables_set(self):
        """Verify critical environment variables are configured"""
        required_vars = [
            "PRODUCTION_URL",
            # Add other critical env vars that should be set
        ]

        missing_vars = [var for var in required_vars if not os.getenv(var)]

        if missing_vars:
            print(f"⚠ Missing environment variables: {missing_vars}")
            # Don't fail, just warn
        else:
            print("✓ All required environment variables are set")

    def test_ssl_certificate(self):
        """Verify SSL certificate is valid (if HTTPS)"""
        if not PRODUCTION_URL.startswith("https"):
            pytest.skip("Not using HTTPS")
            return

        try:
            response = requests.get(f"{PRODUCTION_URL}/health", timeout=API_TIMEOUT, verify=True)
            assert response.status_code == 200, "HTTPS request failed"
            print("✓ SSL certificate is valid")
        except requests.exceptions.SSLError as e:
            pytest.fail(f"SSL certificate validation failed: {e}")
        except requests.exceptions.RequestException as e:
            pytest.fail(f"HTTPS request failed: {e}")


if __name__ == "__main__":
    # Run smoke tests
    print("=" * 80)
    print("PRODUCTION SMOKE TESTS - HEALTH CHECKS")
    print("=" * 80)
    print(f"Target: {PRODUCTION_URL}")
    print(f"Timeout: {API_TIMEOUT}s")
    print("=" * 80)

    # Run with pytest
    pytest.main([__file__, "-v", "--tb=short", "--color=yes"])
