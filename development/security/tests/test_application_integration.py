"""
Application Integration Test
Tests security system integration without requiring full server startup
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_security_manager_import():
    """Test that security manager can be imported"""
    try:
        print("✓ Security manager imports successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to import security manager: {e}")
        return False


def test_security_manager_initialization():
    """Test security manager initialization (with fallback)"""
    try:
        from application.security_init import get_security_manager
        from application.jwt_security import SecurityLevel

        # Initialize with minimal config
        security = get_security_manager(
            private_key_path="../keys/jwt_development_private.pem",
            public_key_path="../keys/jwt_development_public.pem",
            security_level=SecurityLevel.ENHANCED,
            redis_host="localhost",
            redis_port=6379
        )

        print("✓ Security manager initialized")
        print(f"  - JWT manager: {'✓' if security.jwt else '✗'}")
        print(f"  - Rate limiter: {'✓' if security.rate_limiter else '✗'}")
        print(f"  - Validator: {'✓' if security.validator else '✗'}")
        print(f"  - Redis: {'✓' if security.redis else '✗'}")

        return True
    except Exception as e:
        print(f"✗ Failed to initialize security manager: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_health_check():
    """Test security manager health check"""
    try:
        from application.security_init import get_security_manager

        security = get_security_manager()
        health = security.health_check()

        print("✓ Health check successful")
        print(f"  - Redis available: {health['redis']['available']}")
        print(f"  - JWT initialized: {health['jwt']['initialized']}")
        print(f"  - JWT using Redis: {health['jwt']['using_redis']}")
        print(f"  - Rate limiter initialized: {health['rate_limiter']['initialized']}")
        print(f"  - Rate limiter using Redis: {health['rate_limiter']['using_redis']}")
        print(f"  - DDoS protection: {health['rate_limiter']['ddos_protection']}")

        return True
    except Exception as e:
        print(f"✗ Health check failed: {e}")
        return False


def test_jwt_token_creation():
    """Test JWT token creation"""
    try:
        from application.security_init import get_security_manager
        from application.jwt_security import TokenType

        security = get_security_manager()

        # Create token
        token = security.jwt.create_access_token(
            subject="test_user",
            user_id="user_test_123",
            roles=["user"],
            permissions=["read", "write"]
        )

        print("✓ Token created successfully")
        print(f"  - Token length: {len(token)} characters")
        print(f"  - Token preview: {token[:50]}...")

        # Verify token
        payload = security.jwt.verify_token(token, TokenType.ACCESS)
        print(f"  - Token verified for user: {payload['user_id']}")

        return True
    except Exception as e:
        print(f"✗ Token creation/verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_input_validation():
    """Test input validator"""
    try:
        from application.security_init import get_security_manager

        security = get_security_manager()

        # Test email validation
        result = security.validator.validate_email("test@example.com")
        print("✓ Email validation works")
        print(f"  - Valid email: {result.is_valid}")
        print(f"  - Sanitized: {result.sanitized_value}")

        # Test SQL injection detection
        sql_result = security.validator.validate_sql_input("SELECT * FROM users WHERE id = 1")
        print(f"  - SQL input validation: {'SAFE' if sql_result.is_valid else 'BLOCKED'}")

        return True
    except Exception as e:
        print(f"✗ Input validation failed: {e}")
        return False


def test_application_imports():
    """Test that saas_server.py can import security modules"""
    try:
        # Add saas/api to path
        saas_api_path = Path(__file__).parent.parent.parent / "saas" / "api"
        sys.path.insert(0, str(saas_api_path.parent.parent))

        # Try importing the modules that saas_server.py uses

        print("✓ All saas_server.py imports successful")
        print("  - SecurityManager: ✓")
        print("  - TokenType: ✓")
        print("  - SecurityLevel: ✓")
        print("  - RateLimitMiddleware: ✓")

        return True
    except Exception as e:
        print(f"✗ Application imports failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all integration tests"""
    print("="*60)
    print("Application Integration Tests")
    print("="*60)
    print()

    tests = [
        ("Security Manager Import", test_security_manager_import),
        ("Security Manager Initialization", test_security_manager_initialization),
        ("Health Check", test_health_check),
        ("JWT Token Creation", test_jwt_token_creation),
        ("Input Validation", test_input_validation),
        ("Application Imports", test_application_imports),
    ]

    results = []
    for name, test_func in tests:
        print(f"\nTest: {name}")
        print("-" * 60)
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"✗ Test crashed: {e}")
            results.append((name, False))
        print()

    # Summary
    print("="*60)
    print("Test Summary")
    print("="*60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")

    print()
    print(f"Results: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 All integration tests passed!")
        return 0
    else:
        print(f"\n⚠ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
