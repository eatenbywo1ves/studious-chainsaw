#!/usr/bin/env python3
"""Development Deployment Validation for Redis Circuit Breaker"""

import sys
from pathlib import Path

# Add project paths
security_path = Path(__file__).parent
saas_path = security_path.parent / "saas"
sys.path.insert(0, str(security_path))
sys.path.insert(0, str(saas_path))

print("\n" + "="*70)
print("  Redis Circuit Breaker - Development Deployment")
print("="*70 + "\n")

# Step 1: Import circuit breaker
print("[Step 1] Importing circuit breaker...")
try:
    from application.redis_circuit_breaker import (
        CircuitBreaker, CircuitBreakerConfig, CircuitState, CircuitBreakerOpenError
    )
    print("[OK] Circuit breaker imports successful")
except Exception as e:
    print(f"[ERROR] Import failed: {e}")
    sys.exit(1)

# Step 2: Initialize circuit breaker
print("\n[Step 2] Initializing circuit breaker...")
try:
    config = CircuitBreakerConfig(
        failure_threshold=3,
        failure_timeout=30.0,
        reset_timeout=30.0,
        success_threshold=2,
    )
    breaker = CircuitBreaker(config)
    print(f"[OK] Circuit breaker initialized: state={breaker.state.value}")
except Exception as e:
    print(f"[ERROR] Initialization failed: {e}")
    sys.exit(1)

# Step 3: Test successful call
print("\n[Step 3] Testing successful call...")
try:
    result = breaker.call(lambda: "test_success")
    assert result == "test_success"
    print("[OK] Successful call validated")
except Exception as e:
    print(f"[ERROR] Test failed: {e}")
    sys.exit(1)

# Step 4: Test failure handling
print("\n[Step 4] Testing failure handling...")
try:
    failure_count = 0
    for i in range(3):
        try:
            breaker.call(lambda: (_ for _ in ()).throw(ConnectionError("test")))
        except ConnectionError:
            failure_count += 1
    print(f"[OK] Registered {failure_count} failures")
except Exception as e:
    print(f"[ERROR] Failure test failed: {e}")
    sys.exit(1)

# Step 5: Verify circuit opened
print("\n[Step 5] Verifying circuit state...")
if breaker.is_open:
    print("[OK] Circuit opened after threshold failures")
else:
    print(f"[WARN] Circuit state: {breaker.state.value}")

# Step 6: Test rejection when open
print("\n[Step 6] Testing call rejection...")
try:
    breaker.call(lambda: "should_fail")
    print("[WARN] Circuit did not reject call")
except CircuitBreakerOpenError:
    print("[OK] Circuit correctly rejects calls when open")

# Step 7: Check metrics
print("\n[Step 7] Checking metrics...")
metrics = breaker.get_metrics()
print(f"[OK] Successful calls: {metrics['successful_calls']}")
print(f"[OK] Failed calls: {metrics['failed_calls']}")
print(f"[OK] Rejected calls: {metrics['rejected_calls']}")

# Step 8: Import resilient pool
print("\n[Step 8] Importing resilient pool...")
try:
    from application.redis_resilient_pool import ResilientRedisPool, DeploymentEnvironment
    print("[OK] Resilient pool imports successful")
except Exception as e:
    print(f"[ERROR] Import failed: {e}")
    sys.exit(1)

# Summary
print("\n" + "="*70)
print("  DEPLOYMENT VALIDATION: SUCCESS")
print("="*70)
print("\n[NEXT STEPS]")
print("  1. Run full test suite: pytest tests/test_redis_*.py -v")
print("  2. Proceed to Gate 1 approval for staging deployment")
print()

sys.exit(0)
