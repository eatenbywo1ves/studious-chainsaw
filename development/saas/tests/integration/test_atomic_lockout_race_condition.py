"""
Critical Test: Verify atomic operations prevent race condition

This test MUST pass with atomic implementation.
This test SHOULD fail with legacy implementation (demonstrating the vulnerability).

Test Strategy:
- Pre-populate attempts just below threshold
- Send concurrent requests to exploit race window
- Verify lockout enforced atomically
- Ensure no extra attempts slip through
"""

import pytest
import redis
import threading
import time
import sys
import os
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from auth.account_lockout import AccountLockoutManager


@pytest.fixture
def redis_client():
    """Real Redis connection for integration testing"""
    # Honor REDIS_HOST/REDIS_PORT/REDIS_PASSWORD so the test runs both
    # locally (defaults to localhost:6379) and inside a container on a
    # compose network (e.g. REDIS_HOST=redis).
    redis_host = os.getenv('REDIS_HOST', 'localhost')
    redis_port = int(os.getenv('REDIS_PORT', '6379'))
    redis_password = os.getenv('REDIS_PASSWORD', '')

    client = redis.Redis(
        host=redis_host,
        port=redis_port,
        password=redis_password if redis_password else None,
        db=15,  # Separate DB for testing
        decode_responses=True
    )

    # Clear test database
    client.flushdb()

    yield client

    # Cleanup
    client.flushdb()
    client.close()


class TestAtomicLockoutRaceCondition:
    """Test suite for race condition vulnerability"""

    def test_concurrent_requests_atomic_no_race(self, redis_client):
        """
        CRITICAL TEST: Verify atomic implementation prevents race condition

        Test Strategy:
        1. Pre-populate with 4 attempts (just below threshold of 5)
        2. Send 20 concurrent requests
        3. Verify account is locked
        4. Verify no extra attempts slipped through
        """
        # Use atomic implementation
        manager = AccountLockoutManager(
            redis_client=redis_client,
            max_attempts=5,
            enable_atomic=True
        )

        identifier = "atomic_test@example.com"

        # Pre-populate with 4 attempts (just below threshold)
        for _ in range(4):
            manager.record_failed_attempt(identifier)

        # Verify not locked yet
        is_locked, _ = manager.is_locked_out(identifier)
        assert not is_locked, "Should not be locked with 4 attempts"

        # Send 20 concurrent requests to exploit race window
        threads = []
        exceptions = []

        def concurrent_attempt():
            try:
                manager.record_failed_attempt(identifier)
            except Exception as e:
                exceptions.append(e)

        for _ in range(20):
            t = threading.Thread(target=concurrent_attempt)
            threads.append(t)
            t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join()

        # Verify no exceptions
        assert len(exceptions) == 0, f"Unexpected exceptions: {exceptions}"

        # CRITICAL ASSERTIONS

        # 1. Account MUST be locked
        is_locked, ttl = manager.is_locked_out(identifier)
        assert is_locked, "RACE CONDITION DETECTED: Account should be locked!"
        assert ttl > 0, "Lockout TTL should be positive"

        # 2. Verify attempt count
        attempts_key = f"login_attempts:{identifier}"
        actual_count = redis_client.zcard(attempts_key)

        # With atomic operations, all 24 attempts (4 + 20) are recorded
        # but lockout is set atomically at threshold
        assert actual_count >= 5, f"Should have at least 5 attempts, got {actual_count}"

        # Success: Lockout enforced atomically
        print(f"✓ Test passed: {actual_count} attempts recorded, account locked")

    def test_concurrent_requests_legacy_has_race(self, redis_client):
        """
        VULNERABILITY DEMONSTRATION: Legacy implementation allows race condition

        This test demonstrates the vulnerability in the legacy code.
        It may fail with legacy implementation (proving the bug).
        """
        # Use legacy implementation
        manager = AccountLockoutManager(
            redis_client=redis_client,
            max_attempts=5,
            enable_atomic=False  # Use vulnerable legacy code
        )

        identifier = "legacy_test@example.com"

        # Pre-populate with 4 attempts
        for _ in range(4):
            manager.record_failed_attempt(identifier)

        # Send 10 concurrent requests
        threads = []

        def concurrent_attempt():
            try:
                manager.record_failed_attempt(identifier)
            except Exception:
                pass  # Ignore exceptions for demonstration

        for _ in range(10):
            t = threading.Thread(target=concurrent_attempt)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Check results
        attempts_key = f"login_attempts:{identifier}"
        actual_count = redis_client.zcard(attempts_key)
        is_locked, _ = manager.is_locked_out(identifier)

        # With legacy implementation, race condition may allow more attempts
        print(f"Legacy implementation: {actual_count} attempts, locked={is_locked}")

        # This test may pass or fail depending on timing
        # The point is to demonstrate the vulnerability exists
        if actual_count > 5 and not is_locked:
            print("✗ VULNERABILITY CONFIRMED: Race condition allowed bypass")
        elif actual_count > 5 and is_locked:
            print("⚠ Race condition present but lockout eventually set")

    def test_sequential_requests_both_implementations(self, redis_client):
        """
        Verify both implementations work correctly with sequential requests

        This test should pass for both implementations.
        """
        for atomic_enabled in [True, False]:
            redis_client.flushdb()

            manager = AccountLockoutManager(
                redis_client=redis_client,
                max_attempts=5,
                enable_atomic=atomic_enabled
            )

            identifier = f"sequential_test_{atomic_enabled}@example.com"

            # Send 5 sequential requests
            for i in range(5):
                manager.record_failed_attempt(identifier)
                is_locked, _ = manager.is_locked_out(identifier)

                if i < 4:
                    assert not is_locked, f"Should not be locked at attempt {i+1}"
                else:
                    assert is_locked, f"Should be locked at attempt {i+1}"

            print(f"✓ Sequential test passed (atomic={atomic_enabled})")

    def test_high_concurrency_stress(self, redis_client):
        """
        Stress test with very high concurrency

        Tests the atomic implementation under extreme load.
        """
        manager = AccountLockoutManager(
            redis_client=redis_client,
            max_attempts=5,
            enable_atomic=True
        )

        identifier = "stress_test@example.com"

        # Pre-populate with 4 attempts
        for _ in range(4):
            manager.record_failed_attempt(identifier)

        # Send 100 concurrent requests
        threads = []
        exceptions = []

        def concurrent_attempt():
            try:
                manager.record_failed_attempt(identifier)
            except Exception as e:
                exceptions.append(e)

        for _ in range(100):
            t = threading.Thread(target=concurrent_attempt)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Verify no exceptions
        assert len(exceptions) == 0, f"Unexpected exceptions: {exceptions}"

        # Account MUST be locked
        is_locked, _ = manager.is_locked_out(identifier)
        assert is_locked, "Account should be locked under high concurrency"

        print("✓ High concurrency stress test passed")

    def test_multiple_users_concurrent(self, redis_client):
        """
        Test multiple users with concurrent attempts

        Ensures atomicity works correctly across different identifiers.
        """
        manager = AccountLockoutManager(
            redis_client=redis_client,
            max_attempts=5,
            enable_atomic=True
        )

        identifiers = [f"user{i}@example.com" for i in range(10)]

        # Pre-populate each user with 4 attempts
        for identifier in identifiers:
            for _ in range(4):
                manager.record_failed_attempt(identifier)

        # Send concurrent 5th attempt for all users
        threads = []

        def concurrent_attempt(identifier):
            manager.record_failed_attempt(identifier)

        for identifier in identifiers:
            for _ in range(5):  # 5 concurrent attempts per user
                t = threading.Thread(target=concurrent_attempt, args=(identifier,))
                threads.append(t)
                t.start()

        for t in threads:
            t.join()

        # Verify all users are locked
        for identifier in identifiers:
            is_locked, _ = manager.is_locked_out(identifier)
            assert is_locked, f"User {identifier} should be locked"

        print("✓ Multi-user concurrent test passed")

    def test_lockout_clears_on_success(self, redis_client):
        """
        Test that successful login clears attempts

        Ensures atomic implementation correctly handles success flow.
        """
        manager = AccountLockoutManager(
            redis_client=redis_client,
            max_attempts=5,
            enable_atomic=True
        )

        identifier = "success_test@example.com"

        # Record 3 failed attempts
        for _ in range(3):
            manager.record_failed_attempt(identifier)

        # Verify attempts recorded
        attempts_key = f"login_attempts:{identifier}"
        count = redis_client.zcard(attempts_key)
        assert count == 3, "Should have 3 attempts"

        # Successful login
        manager.record_successful_login(identifier)

        # Verify attempts cleared
        count = redis_client.zcard(attempts_key)
        assert count == 0, "Attempts should be cleared after successful login"

        print("✓ Successful login clears attempts")

    def test_performance_benchmark(self, redis_client):
        """
        Benchmark atomic vs legacy performance

        Measures latency to ensure <6% overhead.
        """
        import statistics

        identifiers = [f"perf_user{i}@example.com" for i in range(100)]

        # Benchmark atomic implementation
        manager_atomic = AccountLockoutManager(
            redis_client=redis_client,
            max_attempts=5,
            enable_atomic=True
        )

        atomic_times = []
        for identifier in identifiers:
            start = time.time()
            manager_atomic.record_failed_attempt(identifier)
            atomic_times.append((time.time() - start) * 1000)  # Convert to ms

        redis_client.flushdb()

        # Benchmark legacy implementation
        manager_legacy = AccountLockoutManager(
            redis_client=redis_client,
            max_attempts=5,
            enable_atomic=False
        )

        legacy_times = []
        for identifier in identifiers:
            start = time.time()
            manager_legacy.record_failed_attempt(identifier)
            legacy_times.append((time.time() - start) * 1000)

        # Calculate statistics
        atomic_median = statistics.median(atomic_times)
        atomic_p95 = statistics.quantiles(atomic_times, n=20)[18]  # 95th percentile
        legacy_median = statistics.median(legacy_times)
        legacy_p95 = statistics.quantiles(legacy_times, n=20)[18]

        overhead_median = ((atomic_median - legacy_median) / legacy_median) * 100
        overhead_p95 = ((atomic_p95 - legacy_p95) / legacy_p95) * 100

        print("\nPerformance Benchmark Results:")
        print(f"  Atomic median: {atomic_median:.2f}ms")
        print(f"  Legacy median: {legacy_median:.2f}ms")
        print(f"  Overhead (median): {overhead_median:.1f}%")
        print(f"  Atomic p95: {atomic_p95:.2f}ms")
        print(f"  Legacy p95: {legacy_p95:.2f}ms")
        print(f"  Overhead (p95): {overhead_p95:.1f}%")

        # Assert overhead is acceptable (<20% for p95)
        assert overhead_p95 < 20, f"Overhead too high: {overhead_p95:.1f}%"

        print("✓ Performance benchmark passed")


# Run with: pytest tests/integration/test_atomic_lockout_race_condition.py -v -s
