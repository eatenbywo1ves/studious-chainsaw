#!/usr/bin/env python3
"""
Catalytic Computing SaaS Platform - Load Testing Framework
===========================================================

Comprehensive load testing suite using Locust to validate performance
under realistic production workloads.

Test Scenarios:
    1. BaselineTest - 100 users, 10 minutes (normal operations)
    2. StressTest - 500 users, 5 minutes (high load)
    3. SpikeTest - 0→1000 users in 1 minute (traffic spike)
    4. SoakTest - 50 users, 4 hours (stability/memory leaks)
    5. MixedWorkloadTest - Realistic production traffic patterns

Performance Targets:
    - API Latency p95: <500ms
    - API Latency p99: <1000ms
    - Throughput: >1000 req/s
    - Error rate: <1%

Usage:
    # Run with Web UI
    locust -f locustfile.py --host http://localhost:8000

    # Run baseline test (headless)
    locust -f locustfile.py --host http://localhost:8000 \
           --tags baseline --users 100 --spawn-rate 10 --run-time 10m --headless

    # Run stress test
    locust -f locustfile.py --host http://localhost:8000 \
           --tags stress --users 500 --spawn-rate 50 --run-time 5m --headless

    # Run spike test
    locust -f locustfile.py --host http://localhost:8000 \
           --tags spike --users 1000 --spawn-rate 1000 --run-time 5m --headless

Author: Catalytic Computing Team
Version: 1.0.0
Date: 2025-10-06
"""

import os
import json
import random
import logging
from datetime import datetime
from typing import Optional, Dict, Any

from locust import HttpUser, task, between, events, tag

# ============================================================================
# CONFIGURATION
# ============================================================================

# API Configuration
API_HOST = os.getenv("API_HOST", "http://localhost:8000")
API_TIMEOUT = int(os.getenv("API_TIMEOUT", "30"))

# Test Data Configuration
TEST_USER_POOL_SIZE = 1000
TEST_COMPANIES = ["Acme Corp", "Globex Inc", "Initech LLC", "Umbrella Corp", "Stark Industries"]
TEST_PLANS = ["free", "pro", "enterprise"]

# Performance Targets
PERFORMANCE_TARGETS = {
    "p95_latency_ms": 500,
    "p99_latency_ms": 1000,
    "target_throughput_rps": 1000,
    "max_error_rate_pct": 1.0
}

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# TEST DATA GENERATION
# ============================================================================

class TestDataGenerator:
    """Generate realistic test data for load testing"""

    @staticmethod
    def generate_email(user_id: int) -> str:
        """Generate deterministic test email"""
        return f"loadtest_user_{user_id}@loadtest.example.com"

    @staticmethod
    def generate_password() -> str:
        """Generate valid test password"""
        return "LoadTest123!SecurePassword"

    @staticmethod
    def generate_company_name() -> str:
        """Generate random company name"""
        return f"{random.choice(TEST_COMPANIES)} {random.randint(1, 9999)}"

    @staticmethod
    def generate_user_data(user_id: int) -> Dict[str, Any]:
        """Generate complete user registration data"""
        return {
            "company_name": TestDataGenerator.generate_company_name(),
            "email": TestDataGenerator.generate_email(user_id),
            "password": TestDataGenerator.generate_password(),
            "first_name": f"User{user_id}",
            "last_name": f"LoadTest{user_id}",
            "plan_code": random.choice(TEST_PLANS)
        }

    @staticmethod
    def generate_lattice_data() -> Dict[str, Any]:
        """Generate lattice creation data"""
        return {
            "name": f"Test Lattice {random.randint(1000, 9999)}",
            "dimensions": random.randint(2, 5),
            "size": random.choice([100, 500, 1000, 2000]),
            "field_type": random.choice(["real", "complex"]),
            "geometry": random.choice(["euclidean", "hyperbolic", "spherical"]),
            "enable_gpu": random.choice([True, False])
        }

# ============================================================================
# METRICS TRACKING
# ============================================================================

class LoadTestMetrics:
    """Track detailed metrics during load testing"""

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset all metrics"""
        self.registrations = {"total": 0, "successful": 0, "failed": 0}
        self.logins = {"total": 0, "successful": 0, "failed": 0}
        self.lattice_operations = {"created": 0, "listed": 0, "retrieved": 0, "deleted": 0}
        self.token_operations = {"refreshed": 0, "verified": 0, "revoked": 0}
        self.errors_by_status = {}
        self.response_times = []

    def record_registration(self, success: bool):
        """Record registration attempt"""
        self.registrations["total"] += 1
        if success:
            self.registrations["successful"] += 1
        else:
            self.registrations["failed"] += 1

    def record_login(self, success: bool):
        """Record login attempt"""
        self.logins["total"] += 1
        if success:
            self.logins["successful"] += 1
        else:
            self.logins["failed"] += 1

    def record_lattice_created(self):
        """Record lattice creation"""
        self.lattice_operations["created"] += 1

    def record_lattice_listed(self):
        """Record lattice list operation"""
        self.lattice_operations["listed"] += 1

    def record_lattice_retrieved(self):
        """Record lattice get operation"""
        self.lattice_operations["retrieved"] += 1

    def record_lattice_deleted(self):
        """Record lattice deletion"""
        self.lattice_operations["deleted"] += 1

    def record_error(self, status_code: int):
        """Record error by status code"""
        key = f"HTTP_{status_code}"
        self.errors_by_status[key] = self.errors_by_status.get(key, 0) + 1

    def get_summary(self) -> Dict[str, Any]:
        """Get complete metrics summary"""
        return {
            "registrations": self.registrations,
            "logins": self.logins,
            "lattice_operations": self.lattice_operations,
            "token_operations": self.token_operations,
            "errors": self.errors_by_status,
            "performance_targets": PERFORMANCE_TARGETS
        }

# Global metrics instance
metrics = LoadTestMetrics()

# ============================================================================
# EVENT HANDLERS
# ============================================================================

@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Called when load test starts"""
    logger.info("=" * 80)
    logger.info("CATALYTIC COMPUTING SAAS - LOAD TESTING FRAMEWORK")
    logger.info("=" * 80)
    logger.info(f"Start Time: {datetime.now().isoformat()}")
    logger.info(f"Target Host: {environment.host}")
    logger.info(f"Test User Pool: {TEST_USER_POOL_SIZE} users")
    logger.info("Performance Targets:")
    logger.info(f"  - p95 Latency: <{PERFORMANCE_TARGETS['p95_latency_ms']}ms")
    logger.info(f"  - p99 Latency: <{PERFORMANCE_TARGETS['p99_latency_ms']}ms")
    logger.info(f"  - Throughput: >{PERFORMANCE_TARGETS['target_throughput_rps']} req/s")
    logger.info(f"  - Error Rate: <{PERFORMANCE_TARGETS['max_error_rate_pct']}%")
    logger.info("=" * 80)
    metrics.reset()

@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Called when load test stops"""
    logger.info("\n" + "=" * 80)
    logger.info("LOAD TEST RESULTS SUMMARY")
    logger.info("=" * 80)

    summary = metrics.get_summary()

    logger.info("\nAuthentication Metrics:")
    logger.info(f"  Registrations: {summary['registrations']['successful']}/{summary['registrations']['total']}")
    logger.info(f"  Logins: {summary['logins']['successful']}/{summary['logins']['total']}")

    logger.info("\nLattice Operations:")
    logger.info(f"  Created: {summary['lattice_operations']['created']}")
    logger.info(f"  Listed: {summary['lattice_operations']['listed']}")
    logger.info(f"  Retrieved: {summary['lattice_operations']['retrieved']}")
    logger.info(f"  Deleted: {summary['lattice_operations']['deleted']}")

    if summary['errors']:
        logger.info("\nErrors by Status Code:")
        for error_type, count in summary['errors'].items():
            logger.info(f"  {error_type}: {count}")

    logger.info("\n" + "=" * 80)
    logger.info(f"End Time: {datetime.now().isoformat()}")
    logger.info("=" * 80)

    # Export metrics to JSON
    metrics_file = f"load_test_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(metrics_file, 'w') as f:
        json.dump(summary, f, indent=2)
    logger.info(f"\nMetrics exported to: {metrics_file}\n")

# ============================================================================
# BASE USER CLASS
# ============================================================================

class SaaSUser(HttpUser):
    """Base class for all load test users"""

    abstract = True  # Don't run this class directly

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_id = random.randint(1, TEST_USER_POOL_SIZE)
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.tenant_id: Optional[str] = None
        self.lattice_ids: list = []

    def register_user(self) -> bool:
        """Helper: Register a new user"""
        user_data = TestDataGenerator.generate_user_data(self.user_id)

        with self.client.post(
            "/api/auth/register",
            json=user_data,
            catch_response=True,
            timeout=API_TIMEOUT
        ) as response:
            if response.status_code == 201:
                data = response.json()
                self.access_token = data.get("access_token")
                self.refresh_token = data.get("refresh_token")
                self.tenant_id = data.get("tenant_id")
                metrics.record_registration(success=True)
                response.success()
                return True
            else:
                metrics.record_registration(success=False)
                metrics.record_error(response.status_code)
                response.failure(f"Registration failed: {response.status_code}")
                return False

    def login_user(self) -> bool:
        """Helper: Login existing user"""
        login_data = {
            "email": TestDataGenerator.generate_email(self.user_id),
            "password": TestDataGenerator.generate_password()
        }

        with self.client.post(
            "/api/auth/login",
            json=login_data,
            catch_response=True,
            timeout=API_TIMEOUT
        ) as response:
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get("access_token")
                self.refresh_token = data.get("refresh_token")
                metrics.record_login(success=True)
                response.success()
                return True
            else:
                metrics.record_login(success=False)
                metrics.record_error(response.status_code)
                response.failure(f"Login failed: {response.status_code}")
                return False

    def get_auth_headers(self) -> Dict[str, str]:
        """Get authorization headers"""
        if self.access_token:
            return {"Authorization": f"Bearer {self.access_token}"}
        return {}

# ============================================================================
# SCENARIO 1: BASELINE TEST (100 users, 10 minutes)
# ============================================================================

@tag('baseline', 'normal')
class BaselineTest(SaaSUser):
    """
    Baseline Load Test

    Simulates normal production operations with 100 concurrent users.

    Test Pattern:
        - User registration
        - Login/logout cycles
        - Lattice creation and management
        - Regular API operations

    Target: 100 concurrent users
    Duration: 10 minutes
    Expected: All operations complete successfully with p95 < 500ms
    """

    wait_time = between(2, 5)  # Normal user behavior

    def on_start(self):
        """Setup: Register or login user"""
        logger.info(f"[BASELINE] User {self.user_id} starting")
        # Try to register, if exists then login
        if not self.register_user():
            self.login_user()

    @task(10)
    def create_lattice(self):
        """Task: Create a new lattice"""
        if not self.access_token:
            return

        lattice_data = TestDataGenerator.generate_lattice_data()

        with self.client.post(
            "/api/lattices",
            json=lattice_data,
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices [CREATE]"
        ) as response:
            if response.status_code == 201:
                data = response.json()
                self.lattice_ids.append(data.get("id"))
                metrics.record_lattice_created()
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"Lattice creation failed: {response.status_code}")

    @task(30)
    def list_lattices(self):
        """Task: List all lattices"""
        if not self.access_token:
            return

        with self.client.get(
            "/api/lattices",
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices [LIST]"
        ) as response:
            if response.status_code == 200:
                metrics.record_lattice_listed()
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"List lattices failed: {response.status_code}")

    @task(20)
    def get_lattice_details(self):
        """Task: Get specific lattice details"""
        if not self.access_token or not self.lattice_ids:
            return

        lattice_id = random.choice(self.lattice_ids)

        with self.client.get(
            f"/api/lattices/{lattice_id}",
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices/{id} [GET]"
        ) as response:
            if response.status_code == 200:
                metrics.record_lattice_retrieved()
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"Get lattice failed: {response.status_code}")

    @task(5)
    def delete_lattice(self):
        """Task: Delete a lattice"""
        if not self.access_token or not self.lattice_ids:
            return

        lattice_id = self.lattice_ids.pop(random.randrange(len(self.lattice_ids)))

        with self.client.delete(
            f"/api/lattices/{lattice_id}",
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices/{id} [DELETE]"
        ) as response:
            if response.status_code == 204:
                metrics.record_lattice_deleted()
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"Delete lattice failed: {response.status_code}")

    @task(15)
    def check_health(self):
        """Task: Check system health"""
        with self.client.get(
            "/health",
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/health"
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Health check failed: {response.status_code}")

# ============================================================================
# SCENARIO 2: STRESS TEST (500 users, 5 minutes)
# ============================================================================

@tag('stress', 'high-load')
class StressTest(SaaSUser):
    """
    Stress Test

    Tests system performance under high concurrent load.

    Test Pattern:
        - Rapid user registration
        - High-frequency API calls
        - Concurrent lattice operations

    Target: 500 concurrent users
    Duration: 5 minutes
    Expected: System remains stable, p95 < 500ms, error rate < 1%
    """

    wait_time = between(1, 2)  # Faster requests

    def on_start(self):
        """Setup: Register user"""
        logger.info(f"[STRESS] User {self.user_id} starting")
        self.register_user()

    @task(20)
    def rapid_create_lattices(self):
        """Task: Rapid lattice creation"""
        if not self.access_token:
            return

        lattice_data = TestDataGenerator.generate_lattice_data()

        with self.client.post(
            "/api/lattices",
            json=lattice_data,
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices [STRESS-CREATE]"
        ) as response:
            if response.status_code == 201:
                data = response.json()
                self.lattice_ids.append(data.get("id"))
                metrics.record_lattice_created()
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"Stress create failed: {response.status_code}")

    @task(50)
    def rapid_list_lattices(self):
        """Task: High-frequency list operations"""
        if not self.access_token:
            return

        with self.client.get(
            "/api/lattices",
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices [STRESS-LIST]"
        ) as response:
            if response.status_code == 200:
                metrics.record_lattice_listed()
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"Stress list failed: {response.status_code}")

    @task(30)
    def rapid_get_details(self):
        """Task: High-frequency detail retrieval"""
        if not self.access_token or not self.lattice_ids:
            return

        lattice_id = random.choice(self.lattice_ids)

        with self.client.get(
            f"/api/lattices/{lattice_id}",
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices/{id} [STRESS-GET]"
        ) as response:
            if response.status_code == 200:
                metrics.record_lattice_retrieved()
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"Stress get failed: {response.status_code}")

# ============================================================================
# SCENARIO 3: SPIKE TEST (0→1000 users in 1 minute)
# ============================================================================

@tag('spike', 'burst')
class SpikeTest(SaaSUser):
    """
    Spike Test

    Tests system response to sudden traffic spikes.

    Test Pattern:
        - Instant traffic surge (0→1000 users in 60s)
        - Burst API requests
        - System recovery validation

    Target: 1000 concurrent users (spike from 0)
    Duration: 5 minutes
    Expected: System handles spike gracefully, recovers quickly
    """

    wait_time = between(0.5, 1.5)  # Very fast during spike

    def on_start(self):
        """Setup: Quick registration"""
        logger.info(f"[SPIKE] User {self.user_id} starting")
        self.register_user()

    @task(40)
    def burst_create(self):
        """Task: Burst lattice creation"""
        if not self.access_token:
            return

        lattice_data = TestDataGenerator.generate_lattice_data()
        # Use smaller lattices during spike
        lattice_data["size"] = min(lattice_data["size"], 500)

        with self.client.post(
            "/api/lattices",
            json=lattice_data,
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices [SPIKE-CREATE]"
        ) as response:
            if response.status_code == 201:
                data = response.json()
                self.lattice_ids.append(data.get("id"))
                metrics.record_lattice_created()
                response.success()
            elif response.status_code == 429:
                # Rate limiting is expected during spike
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"Spike create failed: {response.status_code}")

    @task(60)
    def burst_read(self):
        """Task: Burst read operations"""
        if not self.access_token:
            return

        with self.client.get(
            "/api/lattices",
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices [SPIKE-READ]"
        ) as response:
            if response.status_code == 200:
                metrics.record_lattice_listed()
                response.success()
            elif response.status_code == 429:
                # Rate limiting is expected
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"Spike read failed: {response.status_code}")

# ============================================================================
# SCENARIO 4: SOAK TEST (50 users, 4 hours)
# ============================================================================

@tag('soak', 'stability', 'endurance')
class SoakTest(SaaSUser):
    """
    Soak Test (Endurance Test)

    Tests system stability over extended periods to detect memory leaks,
    resource exhaustion, and degradation over time.

    Test Pattern:
        - Low but constant load
        - Continuous operations
        - Long-running monitoring

    Target: 50 concurrent users
    Duration: 4 hours (240 minutes)
    Expected: No memory leaks, stable performance, no degradation

    Note: For actual execution, run with --run-time 4h
    """

    wait_time = between(5, 10)  # Slower, sustained load

    def on_start(self):
        """Setup: Register user"""
        logger.info(f"[SOAK] User {self.user_id} starting long-term test")
        self.register_user()

    @task(25)
    def sustained_create(self):
        """Task: Sustained lattice creation"""
        if not self.access_token:
            return

        lattice_data = TestDataGenerator.generate_lattice_data()

        with self.client.post(
            "/api/lattices",
            json=lattice_data,
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices [SOAK-CREATE]"
        ) as response:
            if response.status_code == 201:
                data = response.json()
                self.lattice_ids.append(data.get("id"))
                metrics.record_lattice_created()
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"Soak create failed: {response.status_code}")

    @task(50)
    def sustained_read(self):
        """Task: Sustained read operations"""
        if not self.access_token:
            return

        with self.client.get(
            "/api/lattices",
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices [SOAK-READ]"
        ) as response:
            if response.status_code == 200:
                metrics.record_lattice_listed()
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"Soak read failed: {response.status_code}")

    @task(15)
    def sustained_update(self):
        """Task: Sustained update operations"""
        if not self.access_token or not self.lattice_ids:
            return

        lattice_id = random.choice(self.lattice_ids)

        with self.client.get(
            f"/api/lattices/{lattice_id}",
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices/{id} [SOAK-GET]"
        ) as response:
            if response.status_code == 200:
                metrics.record_lattice_retrieved()
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"Soak get failed: {response.status_code}")

    @task(10)
    def sustained_delete(self):
        """Task: Sustained deletion (cleanup)"""
        if not self.access_token or len(self.lattice_ids) < 5:
            return  # Keep at least some lattices

        lattice_id = self.lattice_ids.pop(0)  # Delete oldest

        with self.client.delete(
            f"/api/lattices/{lattice_id}",
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices/{id} [SOAK-DELETE]"
        ) as response:
            if response.status_code == 204:
                metrics.record_lattice_deleted()
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"Soak delete failed: {response.status_code}")

# ============================================================================
# SCENARIO 5: MIXED WORKLOAD (Realistic Production)
# ============================================================================

@tag('mixed', 'production', 'realistic')
class MixedWorkloadTest(SaaSUser):
    """
    Mixed Workload Test

    Simulates realistic production traffic with varied operations.

    Traffic Mix:
        - 15% Authentication (login/register)
        - 60% Read operations (list/get)
        - 20% Write operations (create)
        - 5% Delete operations

    Target: 200 concurrent users
    Duration: 15 minutes
    Expected: Realistic performance baseline
    """

    wait_time = between(2, 4)

    def on_start(self):
        """Setup: Register or login"""
        logger.info(f"[MIXED] User {self.user_id} starting")
        if not self.register_user():
            self.login_user()

    @task(15)
    def auth_operations(self):
        """Task: Authentication operations (15%)"""
        # Refresh token occasionally
        if self.refresh_token and random.random() < 0.5:
            with self.client.post(
                "/api/auth/refresh",
                json={"refresh_token": self.refresh_token},
                catch_response=True,
                timeout=API_TIMEOUT,
                name="/api/auth/refresh [MIXED]"
            ) as response:
                if response.status_code == 200:
                    data = response.json()
                    self.access_token = data.get("access_token")
                    metrics.token_operations["refreshed"] += 1
                    response.success()

    @task(30)
    def read_list(self):
        """Task: List operations (30%)"""
        if not self.access_token:
            return

        with self.client.get(
            "/api/lattices",
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices [MIXED-LIST]"
        ) as response:
            if response.status_code == 200:
                metrics.record_lattice_listed()
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"Mixed list failed: {response.status_code}")

    @task(30)
    def read_detail(self):
        """Task: Detail retrieval (30%)"""
        if not self.access_token or not self.lattice_ids:
            return

        lattice_id = random.choice(self.lattice_ids)

        with self.client.get(
            f"/api/lattices/{lattice_id}",
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices/{id} [MIXED-GET]"
        ) as response:
            if response.status_code == 200:
                metrics.record_lattice_retrieved()
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"Mixed get failed: {response.status_code}")

    @task(20)
    def write_create(self):
        """Task: Create operations (20%)"""
        if not self.access_token:
            return

        lattice_data = TestDataGenerator.generate_lattice_data()

        with self.client.post(
            "/api/lattices",
            json=lattice_data,
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices [MIXED-CREATE]"
        ) as response:
            if response.status_code == 201:
                data = response.json()
                self.lattice_ids.append(data.get("id"))
                metrics.record_lattice_created()
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"Mixed create failed: {response.status_code}")

    @task(5)
    def delete_cleanup(self):
        """Task: Delete operations (5%)"""
        if not self.access_token or not self.lattice_ids:
            return

        lattice_id = self.lattice_ids.pop(random.randrange(len(self.lattice_ids)))

        with self.client.delete(
            f"/api/lattices/{lattice_id}",
            headers=self.get_auth_headers(),
            catch_response=True,
            timeout=API_TIMEOUT,
            name="/api/lattices/{id} [MIXED-DELETE]"
        ) as response:
            if response.status_code == 204:
                metrics.record_lattice_deleted()
                response.success()
            else:
                metrics.record_error(response.status_code)
                response.failure(f"Mixed delete failed: {response.status_code}")

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    print("""
================================================================================

         CATALYTIC COMPUTING SAAS - LOAD TESTING FRAMEWORK v1.0.0

================================================================================

Available Test Scenarios:
  1. BaselineTest       - 100 users, 10 min (normal operations)
  2. StressTest         - 500 users, 5 min (high load)
  3. SpikeTest          - 0->1000 users, 5 min (traffic spike)
  4. SoakTest           - 50 users, 4 hours (stability)
  5. MixedWorkloadTest  - 200 users, 15 min (realistic traffic)

Performance Targets:
  - API Latency p95: <500ms
  - API Latency p99: <1000ms
  - Throughput: >1000 req/s
  - Error rate: <1%

Usage Examples:

  # Run with Web UI (all scenarios)
  locust -f locustfile.py --host http://localhost:8000

  # Run baseline test (headless)
  locust -f locustfile.py --host http://localhost:8000 \\
         --tags baseline --users 100 --spawn-rate 10 --run-time 10m --headless

  # Run stress test (headless)
  locust -f locustfile.py --host http://localhost:8000 \\
         --tags stress --users 500 --spawn-rate 50 --run-time 5m --headless

  # Run spike test (headless)
  locust -f locustfile.py --host http://localhost:8000 \\
         --tags spike --users 1000 --spawn-rate 1000 --run-time 5m --headless

  # Run soak test (4 hours, headless)
  locust -f locustfile.py --host http://localhost:8000 \\
         --tags soak --users 50 --spawn-rate 5 --run-time 4h --headless

  # Run mixed workload (headless)
  locust -f locustfile.py --host http://localhost:8000 \\
         --tags mixed --users 200 --spawn-rate 20 --run-time 15m --headless

For detailed documentation, see: tests/load/README.md
""")
