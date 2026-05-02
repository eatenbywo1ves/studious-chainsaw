#!/usr/bin/env python3
"""
SaaS Platform Load Testing with Locust
========================================

Simulates realistic user behavior for the Catalytic Computing SaaS platform:
1. User registration
2. Login (JWT authentication)
3. Create lattice
4. Query lattice operations
5. Update subscription
6. Logout

Test Scenarios:
    - 1K concurrent users (typical production load)
    - 10K concurrent users (peak/traffic spike)

Success Criteria:
    - P95 response time < 200ms
    - Success rate > 99%
    - No connection pool exhaustion
    - No authentication failures

Usage:
    # 1K users test
    locust -f locustfile.py --users 1000 --spawn-rate 100 --run-time 5m --host http://localhost:8000

    # 10K users test
    locust -f locustfile.py --users 10000 --spawn-rate 200 --run-time 5m --host http://localhost:8000

    # Web UI (interactive)
    locust -f locustfile.py --host http://localhost:8000
"""

import random
import string
from locust import HttpUser, task, between, events
from typing import Dict, Optional


# ============================================================================
# TEST CONFIGURATION
# ============================================================================

# Realistic think time between user actions (1-3 seconds)
THINK_TIME_MIN = 1
THINK_TIME_MAX = 3

# API endpoints
ENDPOINTS = {
    "health": "/health",
    "register": "/auth/register",
    "login": "/auth/login",
    "logout": "/auth/logout",
    "tenants": "/api/v1/tenants",
    "subscriptions": "/api/v1/subscriptions",
    "lattices": "/api/v1/lattices",
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def generate_random_email() -> str:
    """Generate random email for unique user registration"""
    random_string = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"loadtest_{random_string}@example.com"


def generate_random_company() -> str:
    """Generate random company name"""
    prefixes = ["Tech", "Data", "Cloud", "AI", "Smart", "Digital"]
    suffixes = ["Systems", "Solutions", "Labs", "Corp", "Group", "Ventures"]
    return f"{random.choice(prefixes)} {random.choice(suffixes)}"


def generate_strong_password() -> str:
    """Generate strong password meeting requirements"""
    # At least 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special
    password = (
        random.choice(string.ascii_uppercase)
        + random.choice(string.ascii_lowercase)
        + random.choice(string.digits)
        + random.choice("!@#$%^&*")
        + "".join(random.choices(string.ascii_letters + string.digits, k=4))
    )
    return password


# ============================================================================
# METRICS TRACKING
# ============================================================================


class MetricsCollector:
    """Collect and report test metrics"""

    def __init__(self):
        self.auth_failures = 0
        self.connection_errors = 0
        self.timeout_errors = 0
        self.server_errors = 0
        self.client_errors = 0
        self.successful_requests = 0
        self.total_requests = 0

    def record_success(self):
        self.successful_requests += 1
        self.total_requests += 1

    def record_auth_failure(self):
        self.auth_failures += 1
        self.total_requests += 1

    def record_connection_error(self):
        self.connection_errors += 1
        self.total_requests += 1

    def record_timeout(self):
        self.timeout_errors += 1
        self.total_requests += 1

    def record_server_error(self):
        self.server_errors += 1
        self.total_requests += 1

    def record_client_error(self):
        self.client_errors += 1
        self.total_requests += 1

    def get_success_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100

    def print_summary(self):
        print("\n" + "=" * 80)
        print("LOAD TEST METRICS SUMMARY")
        print("=" * 80)
        print(f"Total Requests:       {self.total_requests}")
        print(f"Successful:           {self.successful_requests}")
        print(f"Success Rate:         {self.get_success_rate():.2f}%")
        print(f"Auth Failures:        {self.auth_failures}")
        print(f"Connection Errors:    {self.connection_errors}")
        print(f"Timeout Errors:       {self.timeout_errors}")
        print(f"Server Errors (5xx):  {self.server_errors}")
        print(f"Client Errors (4xx):  {self.client_errors}")
        print("=" * 80)


# Global metrics collector
metrics = MetricsCollector()


# ============================================================================
# LOCUST USER BEHAVIORS
# ============================================================================


class SaaSUser(HttpUser):
    """
    Simulates a typical SaaS platform user.

    User Journey:
    1. Health check (weight 2) - lightweight monitoring
    2. Register account (weight 1) - one-time action
    3. Login (weight 5) - frequent action
    4. Create lattice (weight 3) - medium frequency
    5. Query operations (weight 4) - frequent reads
    6. Update subscription (weight 1) - rare action
    """

    # Wait between 1-3 seconds between tasks (realistic user behavior)
    wait_time = between(THINK_TIME_MIN, THINK_TIME_MAX)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token: Optional[str] = None
        self.tenant_id: Optional[str] = None
        self.user_email: Optional[str] = None
        self.user_password: Optional[str] = None
        self.headers: Dict[str, str] = {"Content-Type": "application/json"}

    def on_start(self):
        """
        Called when a simulated user starts.
        Register and login to get authentication token.
        """
        # Generate unique user credentials
        self.user_email = generate_random_email()
        self.user_password = generate_strong_password()
        company_name = generate_random_company()

        # Try to register (may fail if user exists, that's okay)
        try:
            with self.client.post(
                ENDPOINTS["register"],
                json={
                    "email": self.user_email,
                    "password": self.user_password,
                    "company_name": company_name,
                },
                catch_response=True,
            ) as response:
                if response.status_code == 201:
                    data = response.json()
                    self.tenant_id = data.get("tenant_id")
                    metrics.record_success()
                    response.success()
                elif response.status_code == 409:
                    # User already exists, that's fine
                    response.success()
                else:
                    metrics.record_client_error()
                    response.failure(f"Registration failed: {response.status_code}")

        except Exception as e:
            print(f"Registration error: {e}")
            metrics.record_connection_error()

        # Login to get JWT token
        self.perform_login()

    def perform_login(self):
        """Login and store JWT token"""
        try:
            with self.client.post(
                ENDPOINTS["login"],
                json={"email": self.user_email, "password": self.user_password},
                catch_response=True,
            ) as response:
                if response.status_code == 200:
                    data = response.json()
                    self.token = data.get("access_token")
                    if self.token:
                        self.headers["Authorization"] = f"Bearer {self.token}"
                        metrics.record_success()
                        response.success()
                    else:
                        metrics.record_auth_failure()
                        response.failure("No access token received")
                else:
                    metrics.record_auth_failure()
                    response.failure(f"Login failed: {response.status_code}")

        except Exception as e:
            print(f"Login error: {e}")
            metrics.record_connection_error()

    @task(2)
    def health_check(self):
        """
        Check API health endpoint.
        Weight: 2 (common monitoring task)
        """
        with self.client.get(
            ENDPOINTS["health"], catch_response=True, name="/health [GET]"
        ) as response:
            if response.status_code == 200:
                metrics.record_success()
                response.success()
            else:
                metrics.record_server_error()
                response.failure(f"Health check failed: {response.status_code}")

    @task(5)
    def get_tenant_info(self):
        """
        Get tenant information (requires authentication).
        Weight: 5 (frequent read operation)
        """
        if not self.token or not self.tenant_id:
            return

        with self.client.get(
            f"{ENDPOINTS['tenants']}/{self.tenant_id}",
            headers=self.headers,
            catch_response=True,
            name="/api/v1/tenants/{id} [GET]",
        ) as response:
            if response.status_code == 200:
                metrics.record_success()
                response.success()
            elif response.status_code == 401:
                metrics.record_auth_failure()
                # Token may have expired, try to re-login
                self.perform_login()
                response.failure("Authentication required")
            elif response.status_code >= 500:
                metrics.record_server_error()
                response.failure(f"Server error: {response.status_code}")
            else:
                metrics.record_client_error()
                response.failure(f"Request failed: {response.status_code}")

    @task(3)
    def create_lattice(self):
        """
        Create a new lattice (requires authentication).
        Weight: 3 (medium frequency write operation)
        """
        if not self.token:
            return

        lattice_data = {
            "name": f"LoadTest-Lattice-{random.randint(1000, 9999)}",
            "dimensions": random.choice([2, 3, 4]),
            "size": random.choice([10, 20, 50]),
        }

        with self.client.post(
            ENDPOINTS["lattices"],
            headers=self.headers,
            json=lattice_data,
            catch_response=True,
            name="/api/v1/lattices [POST]",
        ) as response:
            if response.status_code in [200, 201]:
                metrics.record_success()
                response.success()
            elif response.status_code == 401:
                metrics.record_auth_failure()
                self.perform_login()
                response.failure("Authentication required")
            elif response.status_code >= 500:
                metrics.record_server_error()
                response.failure(f"Server error: {response.status_code}")
            else:
                metrics.record_client_error()
                response.failure(f"Request failed: {response.status_code}")

    @task(4)
    def list_lattices(self):
        """
        List all lattices for the tenant (requires authentication).
        Weight: 4 (frequent read operation)
        """
        if not self.token:
            return

        with self.client.get(
            ENDPOINTS["lattices"],
            headers=self.headers,
            catch_response=True,
            name="/api/v1/lattices [GET]",
        ) as response:
            if response.status_code == 200:
                metrics.record_success()
                response.success()
            elif response.status_code == 401:
                metrics.record_auth_failure()
                self.perform_login()
                response.failure("Authentication required")
            elif response.status_code >= 500:
                metrics.record_server_error()
                response.failure(f"Server error: {response.status_code}")
            else:
                metrics.record_client_error()
                response.failure(f"Request failed: {response.status_code}")

    @task(1)
    def get_subscription_info(self):
        """
        Get subscription information (requires authentication).
        Weight: 1 (infrequent operation)
        """
        if not self.token:
            return

        with self.client.get(
            ENDPOINTS["subscriptions"],
            headers=self.headers,
            catch_response=True,
            name="/api/v1/subscriptions [GET]",
        ) as response:
            if response.status_code == 200:
                metrics.record_success()
                response.success()
            elif response.status_code == 401:
                metrics.record_auth_failure()
                self.perform_login()
                response.failure("Authentication required")
            elif response.status_code >= 500:
                metrics.record_server_error()
                response.failure(f"Server error: {response.status_code}")
            else:
                metrics.record_client_error()
                response.failure(f"Request failed: {response.status_code}")


# ============================================================================
# EVENT HANDLERS
# ============================================================================


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Print metrics summary when test stops"""
    print("\n")
    print("🏁 Load test completed!")
    metrics.print_summary()

    # Check if success rate meets threshold
    success_rate = metrics.get_success_rate()
    if success_rate >= 99.0:
        print("✅ SUCCESS RATE TARGET MET (≥99%)")
    else:
        print(f"⚠️  SUCCESS RATE BELOW TARGET: {success_rate:.2f}% < 99%")


@events.quitting.add_listener
def on_quitting(environment, **kwargs):
    """Print final message when Locust is quitting"""
    print("\n👋 Locust shutting down...")
    print("Review metrics above to validate production readiness.\n")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("SaaS Platform Load Testing")
    print("=" * 80)
    print("\nUsage:")
    print("  1K users:  locust -f locustfile.py --users 1000 --spawn-rate 100 --run-time 5m --host http://localhost:8000")
    print("  10K users: locust -f locustfile.py --users 10000 --spawn-rate 200 --run-time 5m --host http://localhost:8000")
    print("  Web UI:    locust -f locustfile.py --host http://localhost:8000")
    print("\nSuccessCriteria:")
    print("  - P95 response time < 200ms")
    print("  - Success rate > 99%")
    print("  - No connection pool exhaustion")
    print("  - No authentication failures")
    print("=" * 80 + "\n")
