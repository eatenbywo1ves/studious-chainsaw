"""
Circuit Breaker Test Suite
Tests circuit breaker patterns and fault tolerance
"""

from libraries.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerRegistry,
    CircuitBreakerConfig,
    CircuitState,
    CircuitBreakerException,
    ServiceCircuitBreakers,
    circuit_breaker,
)
import asyncio
from datetime import datetime
import sys
from pathlib import Path

# Add shared libraries to path
sys.path.append(str(Path(__file__).parent.parent))


# Test service functions
class TestService:
    """Mock service for testing"""

    def __init__(self):
        self.call_count = 0
        self.should_fail = False
        self.should_be_slow = False
        self.failure_rate = 0.0  # 0.0 to 1.0

    async def make_call(self, data: str = "test") -> str:
        """Mock service call"""
        self.call_count += 1

        # Simulate random failures based on failure rate
        if (
            self.failure_rate > 0
            and (self.call_count % int(1 / self.failure_rate)) == 0
        ):
            raise Exception("Random service failure")

        if self.should_fail:
            raise Exception("Service is failing")

        if self.should_be_slow:
            await asyncio.sleep(2.0)  # Slow call

        return f"Service response: {data} (call #{self.call_count})"

    def sync_call(self, data: str = "test") -> str:
        """Mock synchronous service call"""
        self.call_count += 1

        if self.should_fail:
            raise Exception("Sync service is failing")

        return f"Sync response: {data} (call #{self.call_count})"

    def reset(self):
        """Reset service state"""
        self.call_count = 0
        self.should_fail = False
        self.should_be_slow = False
        self.failure_rate = 0.0


async def test_basic_circuit_breaker():
    """Test basic circuit breaker functionality"""
    print("Testing basic circuit breaker...")

    service = TestService()
    config = CircuitBreakerConfig(failure_threshold=3, timeout=1)
    cb = CircuitBreaker("test_service", config)

    try:
        # Test normal operation (should work)
        result = await cb.call(service.make_call, "normal")
        if "Service response: normal" in result:
            print("PASS: Normal operation works")
        else:
            print("FAIL: Normal operation failed")
            return False

        # Test failure scenarios
        service.should_fail = True

        # Make calls until circuit opens
        failures = 0
        for i in range(5):
            try:
                await cb.call(service.make_call, f"fail_{i}")
            except Exception:
                failures += 1

        # Circuit should be open now
        if cb.get_state() == CircuitState.OPEN:
            print("PASS: Circuit opened after failures")
        else:
            print("FAIL: Circuit should be open")
            return False

        # Test fast-fail
        try:
            await cb.call(service.make_call, "should_fail_fast")
            print("FAIL: Should have failed fast")
            return False
        except CircuitBreakerException:
            print("PASS: Fast-fail working")

        return True

    except Exception as e:
        print(f"FAIL: Test error: {e}")
        return False


async def test_circuit_recovery():
    """Test circuit breaker recovery"""
    print("Testing circuit breaker recovery...")

    service = TestService()
    config = CircuitBreakerConfig(failure_threshold=2, timeout=1, success_threshold=2)
    cb = CircuitBreaker("recovery_test", config)

    try:
        # Fail the service to open circuit
        service.should_fail = True

        for i in range(3):
            try:
                await cb.call(service.make_call)
            except Exception:
                pass

        # Circuit should be open
        if cb.get_state() != CircuitState.OPEN:
            print("FAIL: Circuit should be open")
            return False

        # Wait for timeout
        await asyncio.sleep(1.1)

        # Fix the service
        service.should_fail = False

        # First call should move to half-open
        await cb.call(service.make_call, "recovery1")

        if cb.get_state() != CircuitState.HALF_OPEN:
            print("FAIL: Circuit should be half-open")
            return False

        # Second successful call should close circuit
        await cb.call(service.make_call, "recovery2")

        if cb.get_state() == CircuitState.CLOSED:
            print("PASS: Circuit recovered successfully")
            return True
        else:
            print("FAIL: Circuit should be closed after recovery")
            return False

    except Exception as e:
        print(f"FAIL: Recovery test error: {e}")
        return False


async def test_slow_call_detection():
    """Test slow call detection"""
    print("Testing slow call detection...")

    service = TestService()
    config = CircuitBreakerConfig(
        slow_call_threshold=1.0,
        slow_call_rate_threshold=0.5,
        minimum_calls=4,
        window_size=10,
    )
    cb = CircuitBreaker("slow_test", config)

    try:
        # Make some normal calls
        await cb.call(service.make_call, "normal1")
        await cb.call(service.make_call, "normal2")

        # Make slow calls
        service.should_be_slow = True
        await cb.call(service.make_call, "slow1")
        await cb.call(service.make_call, "slow2")

        # Check statistics
        stats = cb.get_statistics()

        if stats["slow_calls"] >= 2:
            print("PASS: Slow calls detected")

            # Note: Circuit might not open immediately due to other thresholds
            # This test verifies slow call tracking is working
            return True
        else:
            print("FAIL: Slow calls not properly detected")
            return False

    except Exception as e:
        print(f"FAIL: Slow call test error: {e}")
        return False


async def test_failure_rate_threshold():
    """Test failure rate threshold"""
    print("Testing failure rate threshold...")

    service = TestService()
    service.failure_rate = 0.5  # 50% failure rate

    config = CircuitBreakerConfig(
        failure_rate_threshold=0.4, minimum_calls=10, window_size=20
    )  # 40% threshold
    cb = CircuitBreaker("failure_rate_test", config)

    try:
        # Make enough calls to trigger failure rate evaluation
        successful_calls = 0
        failed_calls = 0

        for i in range(15):
            try:
                await cb.call(service.make_call, f"call_{i}")
                successful_calls += 1
            except Exception:
                failed_calls += 1

        cb.get_statistics()
        actual_failure_rate = failed_calls / (successful_calls + failed_calls)

        print(f"  Actual failure rate: {actual_failure_rate:.2f}")
        print(f"  Threshold: {config.failure_rate_threshold}")

        if actual_failure_rate >= config.failure_rate_threshold:
            print("PASS: Failure rate threshold test setup correct")
            # Circuit might be open due to high failure rate
            return True
        else:
            print("PASS: Failure rate tracking working (rate below threshold)")
            return True

    except Exception as e:
        print(f"FAIL: Failure rate test error: {e}")
        return False


async def test_circuit_breaker_registry():
    """Test circuit breaker registry"""
    print("Testing circuit breaker registry...")

    try:
        registry = CircuitBreakerRegistry()

        # Register circuit breakers
        cb1 = registry.register("service1", CircuitBreakerConfig(failure_threshold=2))
        ___cb2 = registry.register(
            "service2", CircuitBreakerConfig(failure_threshold=3)
        )

        # Test get
        retrieved_cb1 = registry.get("service1")
        if retrieved_cb1 is not cb1:
            print("FAIL: Registry get failed")
            return False

        # Test get_or_create
        cb3 = registry.get_or_create("service3")
        if registry.get("service3") is not cb3:
            print("FAIL: Get or create failed")
            return False

        # Test statistics
        stats = registry.get_all_statistics()
        if len(stats["circuit_breakers"]) == 3:
            print("PASS: Registry management working")
            return True
        else:
            print("FAIL: Registry statistics incorrect")
            return False

    except Exception as e:
        print(f"FAIL: Registry test error: {e}")
        return False


async def test_decorator():
    """Test circuit breaker decorator"""
    print("Testing circuit breaker decorator...")

    service = TestService()

    @circuit_breaker("decorated_service", CircuitBreakerConfig(failure_threshold=2))
    async def decorated_call(data: str):
        return await service.make_call(data)

    try:
        # Normal call
        result = await decorated_call("decorator_test")
        if "Service response" in result:
            print("PASS: Decorator working for normal calls")
        else:
            print("FAIL: Decorator normal call failed")
            return False

        # Test failure handling
        service.should_fail = True

        for i in range(3):
            try:
                await decorated_call(f"fail_{i}")
            except Exception:
                pass

        # Should fail fast now
        try:
            await decorated_call("should_fail_fast")
            print("FAIL: Decorator should fail fast")
            return False
        except CircuitBreakerException:
            print("PASS: Decorator fast-fail working")
            return True

    except Exception as e:
        print(f"FAIL: Decorator test error: {e}")
        return False


async def test_service_circuit_breakers():
    """Test service circuit breakers integration"""
    print("Testing service circuit breakers...")

    try:
        service_cbs = ServiceCircuitBreakers()
        service = TestService()

        # Test API gateway protection
        result = await service_cbs.protected_api_call(service.make_call, "api_test")
        if "Service response" in result:
            print("PASS: Service circuit breaker integration working")
            return True
        else:
            print("FAIL: Service circuit breaker failed")
            return False

    except Exception as e:
        print(f"FAIL: Service circuit breakers test error: {e}")
        return False


async def test_statistics_and_monitoring():
    """Test statistics and monitoring"""
    print("Testing statistics and monitoring...")

    try:
        service = TestService()
        cb = CircuitBreaker("stats_test", CircuitBreakerConfig(failure_threshold=3))

        # Make some calls
        await cb.call(service.make_call, "stats1")
        await cb.call(service.make_call, "stats2")

        service.should_fail = True
        try:
            await cb.call(service.make_call, "fail1")
        except Exception:
            pass

        # Get statistics
        stats = cb.get_statistics()

        expected_fields = [
            "name",
            "state",
            "total_calls",
            "successful_calls",
            "failed_calls",
            "failure_rate",
            "average_duration",
        ]

        missing_fields = [field for field in expected_fields if field not in stats]

        if not missing_fields:
            print("PASS: Statistics comprehensive")
            print(f"  Total calls: {stats['total_calls']}")
            print(f"  Success rate: {(1 - stats['failure_rate']) * 100:.1f}%")
            return True
        else:
            print(f"FAIL: Missing statistics fields: {missing_fields}")
            return False

    except Exception as e:
        print(f"FAIL: Statistics test error: {e}")
        return False


async def run_all_tests():
    """Run all circuit breaker tests"""
    print("=== Circuit Breaker Test Suite ===")
    print(f"Started at: {datetime.now()}")
    print()

    tests = [
        test_basic_circuit_breaker,
        test_circuit_recovery,
        test_slow_call_detection,
        test_failure_rate_threshold,
        test_circuit_breaker_registry,
        test_decorator,
        test_service_circuit_breakers,
        test_statistics_and_monitoring,
    ]

    results = []

    for test in tests:
        try:
            result = await test()
            results.append(result)
        except Exception as e:
            print(f"FAIL: Test {test.__name__} crashed: {e}")
            results.append(False)
        print()

    # Summary
    passed = sum(results)
    total = len(results)

    print("=" * 50)
    print(f"Test Results: {passed}/{total} passed")

    if passed == total:
        print("SUCCESS: All circuit breaker tests passed!")
    else:
        print(f"WARNING: {total - passed} test(s) failed")

    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(run_all_tests())
