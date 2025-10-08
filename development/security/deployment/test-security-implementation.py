#!/usr/bin/env python3
"""
Security Implementation Test Suite
Tests the security hardening deployment in development environment
"""

import os
import sys
from pathlib import Path

# Color codes
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
RED = '\033[0;31m'
NC = '\033[0m'

def print_header(message):
    print(f"\n{BLUE}{'=' * 60}{NC}")
    print(f"{BLUE}{message}{NC}")
    print(f"{BLUE}{'=' * 60}{NC}\n")

def print_success(message):
    print(f"{GREEN}[OK] {message}{NC}")

def print_warning(message):
    print(f"{YELLOW}[WARN] {message}{NC}")

def print_error(message):
    print(f"{RED}[ERROR] {message}{NC}")

def test_key_generation():
    """Test that all security keys were generated"""
    print_header("Testing Key Generation")

    project_root = Path(__file__).parent.parent.parent
    keys_dir = project_root / "security" / "keys"

    required_keys = [
        "jwt_development_private.pem",
        "jwt_development_public.pem",
        "api_encryption_development.key",
        "db_encryption_development.key"
    ]

    all_present = True
    for key_file in required_keys:
        key_path = keys_dir / key_file
        if key_path.exists():
            print_success(f"Found: {key_file}")
            # Check permissions
            if 'private' in key_file:
                stat_info = os.stat(key_path)
                # Check if only owner has read/write (0600)
                if stat_info.st_mode & 0o777 == 0o600:
                    print_success("  Permissions correct (600)")
                else:
                    print_warning(f"  Permissions: {oct(stat_info.st_mode & 0o777)} (should be 600)")
        else:
            print_error(f"Missing: {key_file}")
            all_present = False

    return all_present

def test_environment_config():
    """Test environment configuration"""
    print_header("Testing Environment Configuration")

    project_root = Path(__file__).parent.parent.parent
    env_file = project_root / "saas" / ".env"

    if not env_file.exists():
        print_error(".env file not found in saas/")
        return False

    print_success(".env file exists")

    # Check for required variables
    required_vars = [
        "JWT_PRIVATE_KEY_PATH",
        "JWT_PUBLIC_KEY_PATH",
        "SECURITY_LEVEL",
        "RATE_LIMIT_ENABLED"
    ]

    with open(env_file, 'r') as f:
        content = f.read()

    all_present = True
    for var in required_vars:
        if var in content:
            print_success(f"Found: {var}")
        else:
            print_warning(f"Missing: {var}")
            all_present = False

    return all_present

def test_security_modules():
    """Test that security modules can be imported"""
    print_header("Testing Security Module Imports")

    try:
        project_root = Path(__file__).parent.parent.parent
        sys.path.insert(0, str(project_root))

        # Test JWT Security
        try:
            from security.application.jwt_security import JWTSecurityManager, SecurityLevel
            print_success("JWT Security module imported")
        except ImportError as e:
            print_error(f"JWT Security import failed: {e}")
            return False

        # Test Rate Limiting
        try:
            from security.application.rate_limiting import AdvancedRateLimiter
            print_success("Rate Limiting module imported")
        except ImportError as e:
            print_error(f"Rate Limiting import failed: {e}")
            return False

        # Test Input Validation
        try:
            from security.application.input_validation import SecurityInputValidator
            print_success("Input Validation module imported")
        except ImportError as e:
            print_error(f"Input Validation import failed: {e}")
            return False

        return True

    except Exception as e:
        print_error(f"Module import test failed: {e}")
        return False

def test_jwt_functionality():
    """Test JWT security manager functionality"""
    print_header("Testing JWT Functionality")

    try:
        project_root = Path(__file__).parent.parent.parent
        sys.path.insert(0, str(project_root))

        from security.application.jwt_security import JWTSecurityManager, SecurityLevel

        # Initialize JWT manager
        keys_dir = project_root / "security" / "keys"
        private_key = keys_dir / "jwt_development_private.pem"
        public_key = keys_dir / "jwt_development_public.pem"

        jwt_manager = JWTSecurityManager(
            private_key_path=str(private_key),
            public_key_path=str(public_key),
            access_token_expire_minutes=15,
            refresh_token_expire_days=7,
            security_level=SecurityLevel.BASIC
        )

        print_success("JWT Manager initialized")

        # Test token generation
        test_subject = "auth"
        test_user_id = "test_user_123"
        test_roles = ["user", "admin"]
        test_permissions = ["read", "write"]

        access_token = jwt_manager.create_access_token(
            subject=test_subject,
            user_id=test_user_id,
            roles=test_roles,
            permissions=test_permissions
        )
        print_success("Access token generated")

        # Test token verification
        decoded = jwt_manager.verify_token(access_token)
        if decoded and decoded.get("user_id") == test_user_id:
            print_success("Token verification successful")
            if decoded.get("roles") == test_roles:
                print_success("  Roles preserved correctly")
            if decoded.get("permissions") == test_permissions:
                print_success("  Permissions preserved correctly")
        else:
            print_error("Token verification failed")
            return False

        return True

    except Exception as e:
        print_error(f"JWT functionality test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_dependencies():
    """Test that all security dependencies are installed"""
    print_header("Testing Security Dependencies")

    required_packages = [
        ("PyJWT", "jwt"),
        ("cryptography", "cryptography"),
        ("python-jose", "jose"),
        ("slowapi", "slowapi"),
        ("redis", "redis"),
        ("pydantic", "pydantic"),
        ("email-validator", "email_validator"),
        ("argon2-cffi", "argon2")
    ]

    all_installed = True
    for package_name, import_name in required_packages:
        try:
            __import__(import_name)
            print_success(f"{package_name} installed")
        except ImportError:
            print_error(f"{package_name} not installed")
            all_installed = False

    return all_installed

def test_docker_override():
    """Test docker-compose.override.yml exists"""
    print_header("Testing Docker Configuration")

    project_root = Path(__file__).parent.parent.parent
    override_file = project_root / "saas" / "docker-compose.override.yml"

    if override_file.exists():
        print_success("docker-compose.override.yml exists")

        with open(override_file, 'r') as f:
            content = f.read()

        if "security_opt" in content and "no-new-privileges" in content:
            print_success("Security options configured")
        else:
            print_warning("Security options may not be fully configured")

        return True
    else:
        print_warning("docker-compose.override.yml not found (optional)")
        return True

def generate_report(results):
    """Generate test report"""
    print_header("Test Report Summary")

    total_tests = len(results)
    passed_tests = sum(1 for r in results.values() if r)
    failed_tests = total_tests - passed_tests

    print(f"Total Tests: {total_tests}")
    print(f"{GREEN}Passed: {passed_tests}{NC}")
    if failed_tests > 0:
        print(f"{RED}Failed: {failed_tests}{NC}")

    print("\nTest Results:")
    for test_name, result in results.items():
        status = f"{GREEN}PASS{NC}" if result else f"{RED}FAIL{NC}"
        print(f"  {test_name}: {status}")

    if all(results.values()):
        print(f"\n{GREEN}All security tests passed!{NC}")
        print("\nNext steps:")
        print("  1. Start the API server: cd saas/api && uvicorn saas_server:app --reload")
        print("  2. Test authentication endpoints")
        print("  3. Verify rate limiting behavior")
        print("  4. Review security monitoring")
    else:
        print(f"\n{RED}Some tests failed. Please review errors above.{NC}")

def main():
    """Run all tests"""
    print(f"{BLUE}")
    print("=" * 60)
    print("  Security Implementation Test Suite")
    print("  Environment: Development")
    print("=" * 60)
    print(f"{NC}")

    results = {}

    # Run all tests
    results["Key Generation"] = test_key_generation()
    results["Environment Config"] = test_environment_config()
    results["Dependencies"] = test_dependencies()
    results["Security Modules"] = test_security_modules()
    results["JWT Functionality"] = test_jwt_functionality()
    results["Docker Configuration"] = test_docker_override()

    # Generate report
    generate_report(results)

    # Return exit code
    return 0 if all(results.values()) else 1

if __name__ == "__main__":
    sys.exit(main())
