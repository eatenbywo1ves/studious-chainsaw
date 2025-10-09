#!/usr/bin/env python3
"""
Locust Load Testing Suite for Catalytic Computing Security Framework

This file orchestrates all load testing scenarios defined in test_scenarios/.

Usage:
    # Run with Web UI (recommended)
    locust -f locustfile.py --host http://localhost:8000

    # Run headless with 10,000 users
    locust -f locustfile.py --host http://localhost:8000 \
           --users 10000 --spawn-rate 100 --run-time 15m --headless

    # Run specific scenario
    locust -f locustfile.py --host http://localhost:8000 \
           --tags authentication

Scenarios:
    - AuthenticationLoadTest: Login/logout workflow
    - TokenVerificationLoadTest: Token verification performance
    - RateLimitingStressTest: DDoS attack simulation
    - TokenRevocationLoadTest: Distributed blacklist performance
    - MixedWorkloadTest: Realistic production traffic
    - ChaosLoadTest: Resilience under failure + load
"""

import os
import sys
import json
import random
from datetime import datetime
from typing import Optional

from locust import HttpUser, task, between, events, tag

# Add parent directories to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ============================================================================
# CONFIGURATION
# ============================================================================

# API Base URL (override with --host)
API_HOST = os.getenv("API_HOST", "http://localhost:8000")

# Load test configuration
LOAD_TEST_CONFIG = {
    "ramp_up_time": 300,  # 5 minutes to reach target users
    "test_duration": 900,  # 15 minutes sustained load
    "wait_time_min": 1,  # Min wait between requests (seconds)
    "wait_time_max": 3,  # Max wait between requests (seconds)
}

# Test data configuration
TEST_USER_POOL_SIZE = 1000  # Number of unique test users
TEST_PASSWORDS = ["SecurePassword123!", "TestPass456!", "LoadTest789!"]

# ============================================================================
# TEST DATA GENERATION
# ============================================================================


def generate_test_email(user_id: int) -> str:
    """Generate deterministic test user email"""
    return f"loadtest_user_{user_id}@example.com"


def generate_random_password() -> str:
    """Generate random password for testing"""
    return random.choice(TEST_PASSWORDS)


def generate_random_ip() -> str:
    """Generate random IP address for rate limiting tests"""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"


# ============================================================================
# METRICS TRACKING
# ============================================================================


class LoadTestMetrics:
    """Track custom metrics during load testing"""

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset all metrics"""
        self.total_logins = 0
        self.successful_logins = 0
        self.failed_logins = 0
        self.total_verifications = 0
        self.successful_verifications = 0
        self.failed_verifications = 0
        self.total_logouts = 0
        self.successful_logouts = 0
        self.rate_limit_blocks = 0
        self.token_revocations = 0
        self.redis_fallbacks = 0
        self.errors_by_type = {}

    def record_login(self, success: bool):
        """Record login attempt"""
        self.total_logins += 1
        if success:
            self.successful_logins += 1
        else:
            self.failed_logins += 1

    def record_verification(self, success: bool):
        """Record token verification"""
        self.total_verifications += 1
        if success:
            self.successful_verifications += 1
        else:
            self.failed_verifications += 1

    def record_logout(self, success: bool):
        """Record logout"""
        self.total_logouts += 1
        if success:
            self.successful_logouts += 1

    def record_rate_limit_block(self):
        """Record rate limit block"""
        self.rate_limit_blocks += 1

    def record_error(self, error_type: str):
        """Record error by type"""
        self.errors_by_type[error_type] = self.errors_by_type.get(error_type, 0) + 1

    def get_summary(self) -> dict:
        """Get metrics summary"""
        return {
            "logins": {
                "total": self.total_logins,
                "successful": self.successful_logins,
                "failed": self.failed_logins,
                "success_rate": self.successful_logins / max(self.total_logins, 1),
            },
            "verifications": {
                "total": self.total_verifications,
                "successful": self.successful_verifications,
                "failed": self.failed_verifications,
                "success_rate": self.successful_verifications / max(self.total_verifications, 1),
            },
            "logouts": {"total": self.total_logouts, "successful": self.successful_logouts},
            "rate_limiting": {"blocks": self.rate_limit_blocks},
            "errors": self.errors_by_type,
        }


# Global metrics instance
load_test_metrics = LoadTestMetrics()

# ============================================================================
# EVENT HANDLERS
# ============================================================================


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Called when load test starts"""
    print("\n" + "=" * 80)
    print("CATALYTIC COMPUTING SECURITY FRAMEWORK - LOAD TESTING")
    print("=" * 80)
    print(f"Start Time: {datetime.now().isoformat()}")
    print(f"Target Host: {environment.host}")
    print(f"Test Users: {TEST_USER_POOL_SIZE}")
    print("=" * 80 + "\n")

    # Reset metrics
    load_test_metrics.reset()


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Called when load test stops"""
    print("\n" + "=" * 80)
    print("LOAD TEST RESULTS SUMMARY")
    print("=" * 80)

    # Get metrics summary
    summary = load_test_metrics.get_summary()

    print("\nAuthentication Metrics:")
    print(f"  Total Logins: {summary['logins']['total']}")
    print(f"  Successful: {summary['logins']['successful']}")
    print(f"  Failed: {summary['logins']['failed']}")
    print(f"  Success Rate: {summary['logins']['success_rate'] * 100:.2f}%")

    print("\nToken Verification Metrics:")
    print(f"  Total Verifications: {summary['verifications']['total']}")
    print(f"  Successful: {summary['verifications']['successful']}")
    print(f"  Failed: {summary['verifications']['failed']}")
    print(f"  Success Rate: {summary['verifications']['success_rate'] * 100:.2f}%")

    print("\nLogout Metrics:")
    print(f"  Total Logouts: {summary['logouts']['total']}")
    print(f"  Successful: {summary['logouts']['successful']}")

    print("\nRate Limiting Metrics:")
    print(f"  Total Blocks: {summary['rate_limiting']['blocks']}")

    if summary["errors"]:
        print("\nErrors by Type:")
        for error_type, count in summary["errors"].items():
            print(f"  {error_type}: {count}")

    print("\n" + "=" * 80)
    print(f"End Time: {datetime.now().isoformat()}")
    print("=" * 80 + "\n")

    # Export metrics to JSON
    metrics_file = f"load_test_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(metrics_file, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Metrics exported to: {metrics_file}\n")


# ============================================================================
# SCENARIO 1: AUTHENTICATION LOAD TEST
# ============================================================================


@tag("authentication", "login")
class AuthenticationLoadTest(HttpUser):
    """
    Scenario 1: Authentication Load Test

    Simulates realistic user authentication patterns:
    - Login with valid credentials
    - Verify token works
    - Logout (revoke token)

    Target: 10,000 concurrent users
    """

    wait_time = between(LOAD_TEST_CONFIG["wait_time_min"], LOAD_TEST_CONFIG["wait_time_max"])

    def on_start(self):
        """Called when user starts - generate user credentials"""
        user_id = random.randint(1, TEST_USER_POOL_SIZE)
        self.email = generate_test_email(user_id)
        self.password = generate_random_password()
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None

    @task(5)
    def login(self):
        """Task: User login"""
        with self.client.post(
            "/auth/login",
            json={"email": self.email, "password": self.password},
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get("access_token")
                self.refresh_token = data.get("refresh_token")
                load_test_metrics.record_login(success=True)
                response.success()
            elif response.status_code == 429:
                # Rate limited - expected behavior
                load_test_metrics.record_rate_limit_block()
                response.success()
            else:
                load_test_metrics.record_login(success=False)
                load_test_metrics.record_error(f"login_{response.status_code}")
                response.failure(f"Login failed: {response.status_code}")

    @task(10)
    def verify_token(self):
        """Task: Verify token by accessing protected endpoint"""
        if not self.access_token:
            return  # Skip if not logged in

        with self.client.get(
            "/api/protected",
            headers={"Authorization": f"Bearer {self.access_token}"},
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                load_test_metrics.record_verification(success=True)
                response.success()
            else:
                load_test_metrics.record_verification(success=False)
                load_test_metrics.record_error(f"verify_{response.status_code}")
                response.failure(f"Verification failed: {response.status_code}")

    @task(1)
    def logout(self):
        """Task: User logout (revoke token)"""
        if not self.access_token:
            return  # Skip if not logged in

        with self.client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {self.access_token}"},
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                load_test_metrics.record_logout(success=True)
                self.access_token = None
                self.refresh_token = None
                response.success()
            else:
                load_test_metrics.record_error(f"logout_{response.status_code}")
                response.failure(f"Logout failed: {response.status_code}")


# ============================================================================
# SCENARIO 2: TOKEN VERIFICATION LOAD TEST
# ============================================================================


@tag("verification", "performance")
class TokenVerificationLoadTest(HttpUser):
    """
    Scenario 2: Token Verification Load Test

    Focuses on token verification performance:
    - Login once on start
    - Repeatedly verify token (high frequency)
    - Measure verification latency

    Target: 10,000 concurrent users making 200,000+ verifications
    """

    wait_time = between(0.5, 1.5)  # Faster requests for verification test

    def on_start(self):
        """Login once and store token"""
        user_id = random.randint(1, TEST_USER_POOL_SIZE)
        self.email = generate_test_email(user_id)
        self.password = generate_random_password()

        # Login to get token
        response = self.client.post(
            "/auth/login", json={"email": self.email, "password": self.password}
        )

        if response.status_code == 200:
            data = response.json()
            self.access_token = data.get("access_token")
        else:
            self.access_token = None

    @task(100)  # Very high weight - almost all requests are verifications
    def verify_token_high_frequency(self):
        """Task: High-frequency token verification"""
        if not self.access_token:
            return

        with self.client.get(
            "/api/protected",
            headers={"Authorization": f"Bearer {self.access_token}"},
            catch_response=True,
            name="/api/protected [verification-load]",  # Custom name for stats
        ) as response:
            if response.status_code == 200:
                load_test_metrics.record_verification(success=True)
                response.success()
            else:
                load_test_metrics.record_verification(success=False)
                response.failure(f"Verification failed: {response.status_code}")


# ============================================================================
# SCENARIO 3: RATE LIMITING STRESS TEST
# ============================================================================


@tag("rate-limiting", "ddos", "stress")
class RateLimitingStressTest(HttpUser):
    """
    Scenario 3: Rate Limiting Stress Test

    Simulates DDoS attack pattern:
    - Rapid-fire login attempts from same IP
    - Test rate limit enforcement
    - Verify legitimate requests still work

    Target: 10,000 concurrent attackers (burst pattern)
    """

    wait_time = between(0.1, 0.3)  # Very aggressive - attack simulation

    def on_start(self):
        """Setup attacker credentials"""
        self.email = f"attacker_{random.randint(1, 100)}@evil.com"
        self.password = "WrongPassword123!"
        self.attack_ip = generate_random_ip()
        self.blocked = False

    @task(100)
    def brute_force_attack(self):
        """Task: Brute force login attempts"""
        if self.blocked:
            return  # Stop attacking once blocked

        with self.client.post(
            "/auth/login",
            json={"email": self.email, "password": self.password},
            headers={"X-Forwarded-For": self.attack_ip},  # Simulate IP
            catch_response=True,
            name="/auth/login [brute-force-attack]",
        ) as response:
            if response.status_code == 429:
                # Rate limited - success for this test
                load_test_metrics.record_rate_limit_block()
                self.blocked = True
                response.success()
            elif response.status_code == 401:
                # Wrong password - expected
                response.success()
            elif response.status_code == 403:
                # IP blocked - success for this test
                self.blocked = True
                response.success()
            else:
                response.failure(f"Unexpected response: {response.status_code}")


# ============================================================================
# SCENARIO 4: TOKEN REVOCATION LOAD TEST
# ============================================================================


@tag("revocation", "blacklist")
class TokenRevocationLoadTest(HttpUser):
    """
    Scenario 4: Token Revocation Load Test

    Tests distributed blacklist performance:
    - Login to get token
    - Revoke token (logout)
    - Verify revoked token is rejected

    Target: 10,000 concurrent revocations
    """

    wait_time = between(1, 2)

    def on_start(self):
        """Setup user"""
        user_id = random.randint(1, TEST_USER_POOL_SIZE)
        self.email = generate_test_email(user_id)
        self.password = generate_random_password()

    @task(3)
    def login_and_revoke(self):
        """Task: Login then immediately revoke"""
        # Step 1: Login
        response = self.client.post(
            "/auth/login", json={"email": self.email, "password": self.password}
        )

        if response.status_code != 200:
            return

        data = response.json()
        access_token = data.get("access_token")

        # Step 2: Revoke (logout)
        with self.client.post(
            "/auth/logout", headers={"Authorization": f"Bearer {access_token}"}, catch_response=True
        ) as logout_response:
            if logout_response.status_code == 200:
                load_test_metrics.record_logout(success=True)
                load_test_metrics.token_revocations += 1
                logout_response.success()

                # Step 3: Verify revoked token is rejected
                verify_response = self.client.get(
                    "/api/protected",
                    headers={"Authorization": f"Bearer {access_token}"},
                    catch_response=True,
                )

                if verify_response.status_code == 401:
                    # Correctly rejected - success
                    verify_response.success()
                else:
                    verify_response.failure("Revoked token not rejected!")
            else:
                logout_response.failure("Logout failed")


# ============================================================================
# SCENARIO 5: MIXED WORKLOAD TEST (REALISTIC PRODUCTION)
# ============================================================================


@tag("mixed", "production", "realistic")
class MixedWorkloadTest(HttpUser):
    """
    Scenario 5: Mixed Workload Test

    Simulates realistic production traffic:
    - 10% login attempts
    - 70% API requests with valid tokens
    - 15% token refresh
    - 5% logout

    Target: 10,000 concurrent users, 30 minutes sustained
    """

    wait_time = between(1, 3)

    def on_start(self):
        """Setup user and login"""
        user_id = random.randint(1, TEST_USER_POOL_SIZE)
        self.email = generate_test_email(user_id)
        self.password = generate_random_password()
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None

        # Initial login
        self._perform_login()

    def _perform_login(self):
        """Helper: Perform login"""
        response = self.client.post(
            "/auth/login", json={"email": self.email, "password": self.password}
        )

        if response.status_code == 200:
            data = response.json()
            self.access_token = data.get("access_token")
            self.refresh_token = data.get("refresh_token")
            load_test_metrics.record_login(success=True)

    @task(10)
    def periodic_login(self):
        """Task: Periodic re-authentication (10% of traffic)"""
        self._perform_login()

    @task(70)
    def api_requests(self):
        """Task: Regular API requests (70% of traffic)"""
        if not self.access_token:
            return

        with self.client.get(
            "/api/protected",
            headers={"Authorization": f"Bearer {self.access_token}"},
            catch_response=True,
            name="/api/protected [mixed-workload]",
        ) as response:
            if response.status_code == 200:
                load_test_metrics.record_verification(success=True)
                response.success()
            else:
                load_test_metrics.record_verification(success=False)
                response.failure(f"API request failed: {response.status_code}")

    @task(15)
    def token_refresh(self):
        """Task: Token refresh (15% of traffic)"""
        if not self.refresh_token:
            return

        with self.client.post(
            "/auth/refresh", json={"refresh_token": self.refresh_token}, catch_response=True
        ) as response:
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get("access_token")
                response.success()
            else:
                response.failure(f"Token refresh failed: {response.status_code}")

    @task(5)
    def logout(self):
        """Task: Logout (5% of traffic)"""
        if not self.access_token:
            return

        with self.client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {self.access_token}"},
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                load_test_metrics.record_logout(success=True)
                self.access_token = None
                self.refresh_token = None
                response.success()
            else:
                response.failure(f"Logout failed: {response.status_code}")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║         CATALYTIC COMPUTING SECURITY FRAMEWORK - LOAD TESTING SUITE          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

Available Test Scenarios:
  1. AuthenticationLoadTest      - Login/logout workflow
  2. TokenVerificationLoadTest   - Token verification performance
  3. RateLimitingStressTest      - DDoS attack simulation
  4. TokenRevocationLoadTest     - Distributed blacklist performance
  5. MixedWorkloadTest           - Realistic production traffic

Usage:
  # Run with Web UI
  locust -f locustfile.py --host http://localhost:8000

  # Run specific scenario
  locust -f locustfile.py --host http://localhost:8000 --tags authentication

  # Run headless (no UI)
  locust -f locustfile.py --host http://localhost:8000 \\
         --users 10000 --spawn-rate 100 --run-time 15m --headless

For full documentation, see: WEEK3_LOAD_TESTING_SPECIFICATION.md
""")
