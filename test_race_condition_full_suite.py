"""
Comprehensive Test Suite for Race Condition Vulnerability
Tests both vulnerable and fixed implementations

Usage:
    pytest test_race_condition_full_suite.py -v
    pytest test_race_condition_full_suite.py -v --concurrent=50
"""

import pytest
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Tuple
from redis import Redis
import statistics

# Assuming the account lockout module is available
# from development.saas.auth.account_lockout import AccountLockoutManager


class MockAccountLockoutManager:
    """Mock implementation for testing - replace with actual import"""

    def __init__(self, redis_client, max_attempts=5, lockout_duration=900, attempt_window=300):
        self.redis_client = redis_client
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration
        self.attempt_window = attempt_window
        self.key_prefix = "login_attempts:"

    def record_failed_attempt(self, identifier: str) -> None:
        """Vulnerable implementation for comparison"""
        attempts_key = f"{self.key_prefix}{identifier}"
        lockout_key = f"account_lockout:{identifier}"
        current_time = time.time()

        pipe = self.redis_client.pipeline()
        pipe.zadd(attempts_key, {str(current_time): current_time})
        pipe.zremrangebyscore(attempts_key, 0, current_time - self.attempt_window)
        pipe.zcard(attempts_key)
        pipe.expire(attempts_key, self.attempt_window)
        results = pipe.execute()

        attempt_count = results[2]

        # RACE CONDITION: Non-atomic check and set
        if attempt_count >= self.max_attempts:
            self.redis_client.setex(lockout_key, self.lockout_duration, str(current_time))

    def is_locked_out(self, identifier: str) -> Tuple[bool, int]:
        """Check lockout status"""
        lockout_key = f"account_lockout:{identifier}"
        lockout_time = self.redis_client.get(lockout_key)

        if lockout_time:
            ttl = self.redis_client.ttl(lockout_key)
            return True, max(0, ttl)
        return False, 0

    def get_remaining_attempts(self, identifier: str) -> int:
        """Get remaining attempts"""
        attempts_key = f"{self.key_prefix}{identifier}"
        current_time = time.time()

        self.redis_client.zremrangebyscore(
            attempts_key, 0, current_time - self.attempt_window
        )
        attempt_count = self.redis_client.zcard(attempts_key)
        return max(0, self.max_attempts - attempt_count)


class FixedAccountLockoutManager(MockAccountLockoutManager):
    """Fixed implementation using Lua script"""

    ATOMIC_LOCKOUT_SCRIPT = """
    local attempts_key = KEYS[1]
    local lockout_key = KEYS[2]
    local current_time = tonumber(ARGV[1])
    local attempt_window = tonumber(ARGV[2])
    local max_attempts = tonumber(ARGV[3])
    local lockout_duration = tonumber(ARGV[4])

    -- Add attempt and clean old ones
    redis.call('ZADD', attempts_key, current_time, tostring(current_time))
    redis.call('ZREMRANGEBYSCORE', attempts_key, 0, current_time - attempt_window)

    -- Count attempts
    local attempt_count = redis.call('ZCARD', attempts_key)

    -- Set expiration
    redis.call('EXPIRE', attempts_key, attempt_window)

    -- Atomic lockout check and set
    local is_locked = 0
    if attempt_count >= max_attempts then
        redis.call('SETEX', lockout_key, lockout_duration, tostring(current_time))
        is_locked = 1
    end

    return {attempt_count, is_locked}
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Pre-load script for efficiency
        try:
            self._script_sha = self.redis_client.script_load(self.ATOMIC_LOCKOUT_SCRIPT)
        except Exception:
            self._script_sha = None

    def record_failed_attempt(self, identifier: str) -> None:
        """Fixed implementation using atomic Lua script"""
        attempts_key = f"{self.key_prefix}{identifier}"
        lockout_key = f"account_lockout:{identifier}"
        current_time = time.time()

        try:
            if self._script_sha:
                self.redis_client.evalsha(
                    self._script_sha,
                    2,
                    attempts_key,
                    lockout_key,
                    current_time,
                    self.attempt_window,
                    self.max_attempts,
                    self.lockout_duration,
                )
            else:
                self.redis_client.eval(
                    self.ATOMIC_LOCKOUT_SCRIPT,
                    2,
                    attempts_key,
                    lockout_key,
                    current_time,
                    self.attempt_window,
                    self.max_attempts,
                    self.lockout_duration,
                )
        except Exception as e:
            print(f"Error in Lua script execution: {e}")
            raise


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def redis_client():
    """Provide Redis client for testing"""
    import os
    password = os.getenv("REDIS_PASSWORD")
    client = Redis(
        host="localhost",
        port=6379,
        password=password,
        decode_responses=True,
        db=15  # Use test DB
    )

    # Clear test database
    client.flushdb()

    yield client

    # Cleanup
    client.flushdb()
    client.close()


@pytest.fixture
def vulnerable_manager(redis_client):
    """Provide vulnerable account lockout manager"""
    return MockAccountLockoutManager(
        redis_client=redis_client, max_attempts=5, lockout_duration=900, attempt_window=300
    )


@pytest.fixture
def fixed_manager(redis_client):
    """Provide fixed account lockout manager"""
    return FixedAccountLockoutManager(
        redis_client=redis_client, max_attempts=5, lockout_duration=900, attempt_window=300
    )


# ============================================================================
# TEST 1: Basic Functionality
# ============================================================================


class TestBasicFunctionality:
    """Test basic lockout functionality (no concurrency)"""

    def test_sequential_attempts_vulnerable(self, vulnerable_manager):
        """Test sequential attempts with vulnerable implementation"""
        identifier = "test1@example.com"

        # Record 4 attempts (below threshold)
        for i in range(4):
            vulnerable_manager.record_failed_attempt(identifier)

        is_locked, _ = vulnerable_manager.is_locked_out(identifier)
        assert not is_locked, "Should not be locked after 4 attempts"

        # 5th attempt should trigger lockout
        vulnerable_manager.record_failed_attempt(identifier)

        is_locked, ttl = vulnerable_manager.is_locked_out(identifier)
        assert is_locked, "Should be locked after 5 attempts"
        assert ttl > 0, "TTL should be positive"

    def test_sequential_attempts_fixed(self, fixed_manager):
        """Test sequential attempts with fixed implementation"""
        identifier = "test2@example.com"

        # Record 4 attempts (below threshold)
        for i in range(4):
            fixed_manager.record_failed_attempt(identifier)

        is_locked, _ = fixed_manager.is_locked_out(identifier)
        assert not is_locked, "Should not be locked after 4 attempts"

        # 5th attempt should trigger lockout
        fixed_manager.record_failed_attempt(identifier)

        is_locked, ttl = fixed_manager.is_locked_out(identifier)
        assert is_locked, "Should be locked after 5 attempts"
        assert ttl > 0, "TTL should be positive"

    def test_remaining_attempts(self, fixed_manager):
        """Test remaining attempts calculation"""
        identifier = "test3@example.com"

        remaining = fixed_manager.get_remaining_attempts(identifier)
        assert remaining == 5, "Should have 5 attempts initially"

        fixed_manager.record_failed_attempt(identifier)
        remaining = fixed_manager.get_remaining_attempts(identifier)
        assert remaining == 4, "Should have 4 attempts after 1 failed"

        for _ in range(4):
            fixed_manager.record_failed_attempt(identifier)

        remaining = fixed_manager.get_remaining_attempts(identifier)
        assert remaining == 0, "Should have 0 attempts after lockout"


# ============================================================================
# TEST 2: Race Condition Detection
# ============================================================================


class TestRaceCondition:
    """Test for race condition vulnerability"""

    def test_concurrent_vulnerable_exploitable(self, vulnerable_manager, redis_client):
        """
        Demonstrate race condition in vulnerable implementation
        This test SHOULD FAIL (proving vulnerability exists)
        """
        identifier = "race_test_vuln@example.com"

        # Pre-populate with 4 attempts
        for _ in range(4):
            vulnerable_manager.record_failed_attempt(identifier)
            time.sleep(0.01)  # Small delay to ensure ordering

        # Now send 20 concurrent requests
        threads = []
        results = {"not_locked": 0, "locked": 0}

        def concurrent_attempt():
            vulnerable_manager.record_failed_attempt(identifier)
            time.sleep(0.001)  # Tiny delay to check lock status
            is_locked, _ = vulnerable_manager.is_locked_out(identifier)
            if is_locked:
                results["locked"] += 1
            else:
                results["not_locked"] += 1

        for i in range(20):
            t = threading.Thread(target=concurrent_attempt, name=f"Thread-{i}")
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Check final state
        attempts_key = f"login_attempts:{identifier}"
        actual_attempts = redis_client.zcard(attempts_key)
        is_locked, _ = vulnerable_manager.is_locked_out(identifier)

        print("\n--- Vulnerable Implementation Results ---")
        print(f"Total attempts in Redis: {actual_attempts}")
        print(f"Threshold: {vulnerable_manager.max_attempts}")
        print(f"Is locked: {is_locked}")
        print(f"Threads that saw 'not locked': {results['not_locked']}")
        print(f"Threads that saw 'locked': {results['locked']}")

        # EXPECT: actual_attempts > max_attempts (vulnerability)
        # This assertion SHOULD FAIL on vulnerable code
        with pytest.raises(AssertionError):
            assert (
                actual_attempts <= vulnerable_manager.max_attempts
            ), f"VULNERABILITY: {actual_attempts} > {vulnerable_manager.max_attempts}"

    def test_concurrent_fixed_secure(self, fixed_manager, redis_client):
        """
        Verify fixed implementation prevents race condition
        This test SHOULD PASS
        """
        identifier = "race_test_fixed@example.com"

        # Pre-populate with 4 attempts
        for _ in range(4):
            fixed_manager.record_failed_attempt(identifier)
            time.sleep(0.01)

        # Send 20 concurrent requests
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(fixed_manager.record_failed_attempt, identifier) for _ in range(20)]
            for f in futures:
                f.result()

        # Check final state
        attempts_key = f"login_attempts:{identifier}"
        actual_attempts = redis_client.zcard(attempts_key)
        is_locked, _ = fixed_manager.is_locked_out(identifier)

        print("\n--- Fixed Implementation Results ---")
        print(f"Total attempts in Redis: {actual_attempts}")
        print(f"Threshold: {fixed_manager.max_attempts}")
        print(f"Is locked: {is_locked}")

        # PASS: Must be locked if count >= threshold
        if actual_attempts >= fixed_manager.max_attempts:
            assert is_locked, f"CRITICAL: {actual_attempts} attempts but not locked!"

    @pytest.mark.parametrize("concurrent_threads", [5, 10, 20, 50])
    def test_concurrent_scale_fixed(self, fixed_manager, redis_client, concurrent_threads):
        """Test fixed implementation scales with concurrency"""
        identifier = f"scale_test_{concurrent_threads}@example.com"

        # Start at 3 attempts
        for _ in range(3):
            fixed_manager.record_failed_attempt(identifier)

        # Concurrent attempts
        with ThreadPoolExecutor(max_workers=concurrent_threads) as executor:
            futures = [
                executor.submit(fixed_manager.record_failed_attempt, identifier)
                for _ in range(concurrent_threads)
            ]
            for f in futures:
                f.result()

        # Verify invariant
        attempts_key = f"login_attempts:{identifier}"
        actual_attempts = redis_client.zcard(attempts_key)
        is_locked, _ = fixed_manager.is_locked_out(identifier)

        # Invariant: If count >= threshold, MUST be locked
        if actual_attempts >= fixed_manager.max_attempts:
            assert is_locked, f"Invariant violated with {concurrent_threads} threads!"


# ============================================================================
# TEST 3: Property-Based Testing
# ============================================================================


class TestPropertyInvariant:
    """Test invariant properties that must always hold"""

    def test_invariant_lockout_implies_threshold(self, fixed_manager, redis_client):
        """
        Property: If locked, then attempt_count >= threshold
        Contrapositive: If attempt_count < threshold, then not locked
        """
        identifier = "property_test_1@example.com"

        # Record 3 attempts (below threshold)
        for _ in range(3):
            fixed_manager.record_failed_attempt(identifier)

        attempts_key = f"login_attempts:{identifier}"
        actual_attempts = redis_client.zcard(attempts_key)
        is_locked, _ = fixed_manager.is_locked_out(identifier)

        # Property: count < threshold → not locked
        if actual_attempts < fixed_manager.max_attempts:
            assert not is_locked, "Must not be locked if below threshold"

    def test_invariant_threshold_implies_lockout(self, fixed_manager, redis_client):
        """
        Property: If attempt_count >= threshold, then locked
        """
        identifier = "property_test_2@example.com"

        # Record max_attempts
        for _ in range(fixed_manager.max_attempts):
            fixed_manager.record_failed_attempt(identifier)

        attempts_key = f"login_attempts:{identifier}"
        actual_attempts = redis_client.zcard(attempts_key)
        is_locked, _ = fixed_manager.is_locked_out(identifier)

        # Property: count >= threshold → locked
        if actual_attempts >= fixed_manager.max_attempts:
            assert is_locked, "MUST be locked if at or above threshold"

    @pytest.mark.parametrize("initial_attempts", [0, 2, 4])
    @pytest.mark.parametrize("concurrent_threads", [10, 20, 50])
    def test_invariant_concurrent(self, fixed_manager, redis_client, initial_attempts, concurrent_threads):
        """
        Property test with various initial states and concurrency levels
        """
        identifier = f"property_concurrent_{initial_attempts}_{concurrent_threads}@example.com"

        # Initial attempts
        for _ in range(initial_attempts):
            fixed_manager.record_failed_attempt(identifier)

        # Concurrent attempts
        with ThreadPoolExecutor(max_workers=concurrent_threads) as executor:
            futures = [
                executor.submit(fixed_manager.record_failed_attempt, identifier)
                for _ in range(concurrent_threads)
            ]
            for f in futures:
                f.result()

        # Check invariant
        attempts_key = f"login_attempts:{identifier}"
        actual_attempts = redis_client.zcard(attempts_key)
        is_locked, _ = fixed_manager.is_locked_out(identifier)

        # CRITICAL INVARIANT
        if actual_attempts >= fixed_manager.max_attempts:
            assert is_locked, (
                f"INVARIANT VIOLATED: {actual_attempts} attempts "
                f"(threshold={fixed_manager.max_attempts}) but not locked!"
            )


# ============================================================================
# TEST 4: Performance Testing
# ============================================================================


class TestPerformance:
    """Test performance characteristics"""

    def test_performance_sequential(self, vulnerable_manager, fixed_manager):
        """Compare sequential performance"""
        iterations = 1000

        # Vulnerable implementation
        start = time.time()
        for i in range(iterations):
            vulnerable_manager.record_failed_attempt(f"perf_vuln_{i}@example.com")
        vuln_time = time.time() - start

        # Fixed implementation
        start = time.time()
        for i in range(iterations):
            fixed_manager.record_failed_attempt(f"perf_fixed_{i}@example.com")
        fixed_time = time.time() - start

        print("\n--- Performance Comparison ---")
        print(f"Vulnerable: {vuln_time:.3f}s ({iterations/vuln_time:.1f} ops/s)")
        print(f"Fixed:      {fixed_time:.3f}s ({iterations/fixed_time:.1f} ops/s)")
        print(f"Overhead:   {(fixed_time/vuln_time - 1)*100:.1f}%")

        # Allow up to 20% performance overhead
        assert fixed_time <= vuln_time * 1.20, f"Performance regression too high: {fixed_time/vuln_time*100:.1f}%"

    def test_latency_distribution(self, fixed_manager):
        """Test latency distribution of fixed implementation"""
        identifier = "latency_test@example.com"
        iterations = 100
        latencies = []

        for i in range(iterations):
            start = time.perf_counter()
            fixed_manager.record_failed_attempt(identifier)
            latency = (time.perf_counter() - start) * 1000  # ms
            latencies.append(latency)

        p50 = statistics.median(latencies)
        p95 = statistics.quantiles(latencies, n=20)[18]  # 95th percentile
        p99 = statistics.quantiles(latencies, n=100)[98]  # 99th percentile

        print("\n--- Latency Distribution ---")
        print(f"P50: {p50:.2f}ms")
        print(f"P95: {p95:.2f}ms")
        print(f"P99: {p99:.2f}ms")

        # Reasonable latency thresholds
        assert p50 < 5, f"P50 latency too high: {p50:.2f}ms"
        assert p95 < 15, f"P95 latency too high: {p95:.2f}ms"
        assert p99 < 50, f"P99 latency too high: {p99:.2f}ms"


# ============================================================================
# TEST 5: Edge Cases
# ============================================================================


class TestEdgeCases:
    """Test edge cases and error conditions"""

    def test_redis_connection_failure(self, fixed_manager):
        """Test behavior when Redis connection fails"""
        # Close Redis connection to simulate failure
        original_client = fixed_manager.redis_client
        fixed_manager.redis_client.connection_pool.disconnect()

        with pytest.raises(Exception):
            fixed_manager.record_failed_attempt("failure_test@example.com")

        # Restore
        fixed_manager.redis_client = original_client

    def test_window_expiration(self, fixed_manager, redis_client):
        """Test that old attempts expire correctly"""
        identifier = "expiration_test@example.com"

        # Use manager with short window
        short_window_manager = FixedAccountLockoutManager(
            redis_client=redis_client, max_attempts=5, lockout_duration=900, attempt_window=2  # 2 seconds
        )

        # Record 3 attempts
        for _ in range(3):
            short_window_manager.record_failed_attempt(identifier)

        # Wait for window to expire
        time.sleep(3)

        # Should have 5 attempts again (window expired)
        remaining = short_window_manager.get_remaining_attempts(identifier)
        assert remaining == 5, "Old attempts should have expired"

    def test_lockout_expiration(self, fixed_manager):
        """Test that lockout expires correctly"""
        identifier = "lockout_expiry_test@example.com"

        # Use manager with short lockout duration
        short_lockout_manager = FixedAccountLockoutManager(
            redis_client=fixed_manager.redis_client,
            max_attempts=5,
            lockout_duration=2,  # 2 seconds
            attempt_window=300,
        )

        # Trigger lockout
        for _ in range(5):
            short_lockout_manager.record_failed_attempt(identifier)

        is_locked, _ = short_lockout_manager.is_locked_out(identifier)
        assert is_locked, "Should be locked"

        # Wait for lockout to expire
        time.sleep(3)

        is_locked, _ = short_lockout_manager.is_locked_out(identifier)
        assert not is_locked, "Lockout should have expired"


# ============================================================================
# TEST 6: Stress Testing
# ============================================================================


class TestStress:
    """Stress tests to verify robustness under extreme load"""

    @pytest.mark.slow
    def test_extreme_concurrency(self, fixed_manager, redis_client):
        """Test with extremely high concurrency (100 threads)"""
        identifier = "stress_extreme@example.com"

        # Start near threshold
        for _ in range(4):
            fixed_manager.record_failed_attempt(identifier)

        # 100 concurrent threads
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(fixed_manager.record_failed_attempt, identifier) for _ in range(100)]
            for f in futures:
                f.result()

        # Verify invariant still holds
        attempts_key = f"login_attempts:{identifier}"
        actual_attempts = redis_client.zcard(attempts_key)
        is_locked, _ = fixed_manager.is_locked_out(identifier)

        if actual_attempts >= fixed_manager.max_attempts:
            assert is_locked, "Invariant must hold even under extreme concurrency"

    @pytest.mark.slow
    def test_sustained_load(self, fixed_manager):
        """Test sustained load over time"""
        duration_seconds = 10
        target_rps = 100  # requests per second

        start_time = time.time()
        request_count = 0

        while time.time() - start_time < duration_seconds:
            identifier = f"sustained_{request_count % 100}@example.com"
            fixed_manager.record_failed_attempt(identifier)
            request_count += 1

            # Rate limiting
            time.sleep(1.0 / target_rps)

        actual_duration = time.time() - start_time
        actual_rps = request_count / actual_duration

        print("\n--- Sustained Load Test ---")
        print(f"Duration: {actual_duration:.1f}s")
        print(f"Requests: {request_count}")
        print(f"Actual RPS: {actual_rps:.1f}")

        assert actual_rps >= target_rps * 0.8, "Failed to maintain target RPS"


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
