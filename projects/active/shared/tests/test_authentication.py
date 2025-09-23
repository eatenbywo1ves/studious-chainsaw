"""
Authentication System Test Suite
Tests JWT tokens, API keys, user management, and RBAC
"""

from libraries.authentication import (
    AuthenticationManager,
    AuthConfig,
    UserRole,
    Permission,
    AuthMethod,
)
import asyncio
from datetime import datetime
import sys
from pathlib import Path

# Add shared libraries to path
sys.path.append(str(Path(__file__).parent.parent))


async def test_user_creation():
    """Test user creation and management"""
    print("Testing user creation...")

    try:
        auth_manager = AuthenticationManager()

        # Create test user
        user = await auth_manager.create_user(
            username="testuser",
            email="test@example.com",
            password="testpassword123",
            roles={UserRole.USER},
        )

        if user.username == "testuser" and user.email == "test@example.com":
            print("PASS: User creation working")
        else:
            print("FAIL: User creation failed")
            return False

        # Test duplicate username
        try:
            await auth_manager.create_user(
                username="testuser", email="other@example.com", password="password123"
            )
            print("FAIL: Should not allow duplicate username")
            return False
        except ValueError:
            print("PASS: Duplicate username prevention working")

        return True

    except Exception as e:
        print(f"FAIL: User creation test error: {e}")
        return False


async def test_password_authentication():
    """Test password-based authentication"""
    print("Testing password authentication...")

    try:
        auth_manager = AuthenticationManager()

        # Create test user
        ___user = await auth_manager.create_user(
            username="authtest", email="auth@example.com", password="securepass123"
        )

        # Test correct credentials
        authenticated_user = await auth_manager.authenticate(
            AuthMethod.BASIC_AUTH, {"username": "authtest", "password": "securepass123"}
        )

        if authenticated_user and authenticated_user.username == "authtest":
            print("PASS: Correct password authentication working")
        else:
            print("FAIL: Correct password authentication failed")
            return False

        # Test incorrect credentials
        failed_user = await auth_manager.authenticate(
            AuthMethod.BASIC_AUTH, {"username": "authtest", "password": "wrongpassword"}
        )

        if failed_user is None:
            print("PASS: Incorrect password rejection working")
        else:
            print("FAIL: Should reject incorrect password")
            return False

        return True

    except Exception as e:
        print(f"FAIL: Password authentication test error: {e}")
        return False


async def test_jwt_tokens():
    """Test JWT token generation and validation"""
    print("Testing JWT tokens...")

    try:
        auth_manager = AuthenticationManager()

        # Create test user
        user = await auth_manager.create_user(
            username="jwttest",
            email="jwt@example.com",
            password="jwtpass123",
            roles={UserRole.USER, UserRole.ADMIN},
        )

        # Generate JWT token
        token = await auth_manager.generate_jwt(user)

        if not token or len(token) < 10:
            print("FAIL: JWT generation failed")
            return False

        print("PASS: JWT generation working")

        # Validate JWT token
        validated_user = await auth_manager.validate_jwt(token)

        if validated_user and validated_user.username == "jwttest":
            print("PASS: JWT validation working")
        else:
            print("FAIL: JWT validation failed")
            return False

        # Test token revocation
        await auth_manager.revoke_jwt(token)
        revoked_user = await auth_manager.validate_jwt(token)

        if revoked_user is None:
            print("PASS: JWT revocation working")
        else:
            print("FAIL: Revoked token should be invalid")
            return False

        return True

    except Exception as e:
        print(f"FAIL: JWT test error: {e}")
        return False


async def test_api_keys():
    """Test API key creation and validation"""
    print("Testing API keys...")

    try:
        auth_manager = AuthenticationManager()

        # Create test user
        user = await auth_manager.create_user(
            username="apitest", email="api@example.com", password="apipass123"
        )

        # Create API key
        api_key = await auth_manager.create_api_key(
            user_id=user.id, name="test-api-key", expires_days=30
        )

        if not api_key.key or not api_key.key.startswith("ak_"):
            print("FAIL: API key generation failed")
            return False

        print("PASS: API key generation working")

        # Validate API key
        validated_user = await auth_manager.validate_api_key(api_key.key)

        if validated_user and validated_user.username == "apitest":
            print("PASS: API key validation working")
        else:
            print("FAIL: API key validation failed")
            return False

        # Test API key revocation
        await auth_manager.revoke_api_key(api_key.key)
        revoked_user = await auth_manager.validate_api_key(api_key.key)

        if revoked_user is None:
            print("PASS: API key revocation working")
        else:
            print("FAIL: Revoked API key should be invalid")
            return False

        return True

    except Exception as e:
        print(f"FAIL: API key test error: {e}")
        return False


async def test_role_based_access_control():
    """Test role-based access control"""
    print("Testing RBAC...")

    try:
        auth_manager = AuthenticationManager()

        # Create users with different roles
        admin_user = await auth_manager.create_user(
            username="admin",
            email="admin@example.com",
            password="adminpass123",
            roles={UserRole.ADMIN},
        )

        regular_user = await auth_manager.create_user(
            username="user",
            email="user@example.com",
            password="userpass123",
            roles={UserRole.USER},
        )

        # Test admin permissions
        if auth_manager.has_permission(admin_user, Permission.ADMIN):
            print("PASS: Admin permissions working")
        else:
            print("FAIL: Admin should have admin permission")
            return False

        # Test user permissions
        if not auth_manager.has_permission(regular_user, Permission.ADMIN):
            print("PASS: User permission restriction working")
        else:
            print("FAIL: Regular user should not have admin permission")
            return False

        # Test specific permissions
        if auth_manager.has_permission(regular_user, Permission.READ):
            print("PASS: User has read permission")
        else:
            print("FAIL: User should have read permission")
            return False

        return True

    except Exception as e:
        print(f"FAIL: RBAC test error: {e}")
        return False


async def test_rate_limiting():
    """Test authentication rate limiting"""
    print("Testing rate limiting...")

    try:
        config = AuthConfig(max_login_attempts=2, lockout_duration_minutes=1)
        auth_manager = AuthenticationManager(config)

        # Create test user
        await auth_manager.create_user(
            username="ratetest", email="rate@example.com", password="ratepass123"
        )

        # Make failed authentication attempts
        for i in range(3):
            user = await auth_manager.authenticate(
                AuthMethod.BASIC_AUTH,
                {"username": "ratetest", "password": "wrongpassword"},
            )

        # Should be rate limited now
        user = await auth_manager.authenticate(
            AuthMethod.BASIC_AUTH,
            {
                "username": "ratetest",
                "password": "ratepass123",
            },  # Even correct password
        )

        if user is None:
            print("PASS: Rate limiting working")
            return True
        else:
            print("FAIL: Should be rate limited after failed attempts")
            return False

    except Exception as e:
        print(f"FAIL: Rate limiting test error: {e}")
        return False


async def test_password_change():
    """Test password change functionality"""
    print("Testing password change...")

    try:
        auth_manager = AuthenticationManager()

        # Create test user
        user = await auth_manager.create_user(
            username="changetest", email="change@example.com", password="oldpassword123"
        )

        # Change password
        success = await auth_manager.change_password(
            user.id, "oldpassword123", "newpassword123"
        )

        if not success:
            print("FAIL: Password change failed")
            return False

        # Test old password no longer works
        old_auth = await auth_manager.authenticate(
            AuthMethod.BASIC_AUTH,
            {"username": "changetest", "password": "oldpassword123"},
        )

        if old_auth is not None:
            print("FAIL: Old password should not work")
            return False

        # Test new password works
        new_auth = await auth_manager.authenticate(
            AuthMethod.BASIC_AUTH,
            {"username": "changetest", "password": "newpassword123"},
        )

        if new_auth and new_auth.username == "changetest":
            print("PASS: Password change working")
            return True
        else:
            print("FAIL: New password should work")
            return False

    except Exception as e:
        print(f"FAIL: Password change test error: {e}")
        return False


async def test_statistics():
    """Test authentication statistics"""
    print("Testing statistics...")

    try:
        auth_manager = AuthenticationManager()

        # Create some test data
        for i in range(3):
            await auth_manager.create_user(
                username=f"statsuser{i}",
                email=f"stats{i}@example.com",
                password="statspass123",
            )

        stats = auth_manager.get_statistics()

        expected_fields = [
            "total_users",
            "active_users",
            "total_api_keys",
            "active_api_keys",
            "revoked_tokens",
        ]

        missing_fields = [field for field in expected_fields if field not in stats]

        if not missing_fields and stats["total_users"] >= 3:
            print("PASS: Statistics working")
            print(f"  Total users: {stats['total_users']}")
            print(f"  Active users: {stats['active_users']}")
            return True
        else:
            print("FAIL: Statistics incomplete or incorrect")
            return False

    except Exception as e:
        print(f"FAIL: Statistics test error: {e}")
        return False


async def run_all_tests():
    """Run all authentication tests"""
    print("=== Authentication System Test Suite ===")
    print(f"Started at: {datetime.now()}")
    print()

    tests = [
        test_user_creation,
        test_password_authentication,
        test_jwt_tokens,
        test_api_keys,
        test_role_based_access_control,
        test_rate_limiting,
        test_password_change,
        test_statistics,
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
        print("SUCCESS: All authentication tests passed!")
    else:
        print(f"WARNING: {total - passed} test(s) failed")

    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(run_all_tests())
