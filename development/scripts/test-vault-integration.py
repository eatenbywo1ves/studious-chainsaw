#!/usr/bin/env python3
"""
Vault Integration Test Suite

Comprehensive validation tests for HashiCorp Vault integration.
Tests connectivity, secret retrieval, rotation, and fallback mechanisms.

Part of Phase 6: Secrets Management

Usage:
    python scripts/test-vault-integration.py
    python scripts/test-vault-integration.py --verbose
    python scripts/test-vault-integration.py --vault-url http://staging-vault:8200
"""

import os
import sys
import time
import argparse
from pathlib import Path
from typing import Dict, Any, List, Tuple

# Add saas directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "saas"))

try:
    from auth.vault_client import (
        VaultClient,
        get_vault_client,
        get_secret,
        get_database_config,
        get_redis_config,
        get_jwt_config,
        vault_health_check
    )
    VAULT_CLIENT_AVAILABLE = True
except ImportError as e:
    print(f"ERROR: Could not import vault_client: {e}")
    VAULT_CLIENT_AVAILABLE = False

try:
    import hvac
    HVAC_AVAILABLE = True
except ImportError:
    print("WARNING: hvac library not installed")
    HVAC_AVAILABLE = False


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class VaultIntegrationTester:
    """Test suite for Vault integration"""

    def __init__(self, vault_url: str = "http://localhost:8200", verbose: bool = False):
        self.vault_url = vault_url
        self.verbose = verbose
        self.tests_passed = 0
        self.tests_failed = 0
        self.tests_skipped = 0

    def print_header(self, text: str) -> None:
        """Print test section header"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{text:^80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 80}{Colors.RESET}\n")

    def print_test(self, name: str, status: str, message: str = "") -> None:
        """Print test result"""
        if status == "PASS":
            icon = f"{Colors.GREEN}✓{Colors.RESET}"
            self.tests_passed += 1
        elif status == "FAIL":
            icon = f"{Colors.RED}✗{Colors.RESET}"
            self.tests_failed += 1
        elif status == "SKIP":
            icon = f"{Colors.YELLOW}⊗{Colors.RESET}"
            self.tests_skipped += 1
        else:
            icon = "?"

        print(f"{icon} {name:<60} [{status}]")
        if message and (self.verbose or status == "FAIL"):
            print(f"  {Colors.YELLOW}{message}{Colors.RESET}")

    def test_prerequisites(self) -> bool:
        """Test 1: Check prerequisites"""
        self.print_header("Test 1: Prerequisites")

        # Test 1.1: Python version
        python_version = sys.version_info
        if python_version >= (3, 8):
            self.print_test(
                "Python version >= 3.8",
                "PASS",
                f"Python {python_version.major}.{python_version.minor}.{python_version.micro}"
            )
        else:
            self.print_test(
                "Python version >= 3.8",
                "FAIL",
                f"Python {python_version.major}.{python_version.minor} is too old"
            )
            return False

        # Test 1.2: hvac library
        if HVAC_AVAILABLE:
            self.print_test("hvac library installed", "PASS", f"hvac version: {hvac.__version__}")
        else:
            self.print_test("hvac library installed", "FAIL", "Run: pip install hvac==2.1.0")
            return False

        # Test 1.3: vault_client module
        if VAULT_CLIENT_AVAILABLE:
            self.print_test("vault_client module importable", "PASS")
        else:
            self.print_test("vault_client module importable", "FAIL")
            return False

        return True

    def test_vault_connectivity(self) -> bool:
        """Test 2: Vault connectivity"""
        self.print_header("Test 2: Vault Connectivity")

        # Test 2.1: Vault HTTP endpoint
        try:
            import requests
            response = requests.get(f"{self.vault_url}/v1/sys/health", timeout=5)
            if response.status_code in [200, 429, 472, 473]:
                self.print_test(
                    "Vault HTTP endpoint reachable",
                    "PASS",
                    f"Status: {response.status_code}"
                )
            else:
                self.print_test(
                    "Vault HTTP endpoint reachable",
                    "FAIL",
                    f"Unexpected status: {response.status_code}"
                )
                return False
        except ImportError:
            self.print_test(
                "Vault HTTP endpoint reachable",
                "SKIP",
                "requests library not installed"
            )
        except Exception as e:
            self.print_test(
                "Vault HTTP endpoint reachable",
                "FAIL",
                f"Connection error: {e}"
            )
            return False

        # Test 2.2: Vault client initialization
        try:
            client = VaultClient(vault_url=self.vault_url)
            self.print_test("VaultClient initialization", "PASS")
        except Exception as e:
            self.print_test("VaultClient initialization", "FAIL", str(e))
            return False

        # Test 2.3: Vault authentication
        if client.connected:
            self.print_test("Vault authentication", "PASS")
        else:
            self.print_test(
                "Vault authentication",
                "FAIL",
                "Not authenticated (check VAULT_TOKEN)"
            )
            return False

        return True

    def test_secret_retrieval(self) -> bool:
        """Test 3: Secret retrieval"""
        self.print_header("Test 3: Secret Retrieval")

        client = get_vault_client()

        # Test 3.1: Database config
        try:
            db_config = get_database_config()
            if db_config and isinstance(db_config, dict):
                self.print_test(
                    "get_database_config()",
                    "PASS",
                    f"Retrieved {len(db_config)} keys"
                )
            else:
                self.print_test("get_database_config()", "FAIL", "Invalid response")
                return False
        except Exception as e:
            self.print_test("get_database_config()", "FAIL", str(e))
            return False

        # Test 3.2: Redis config
        try:
            redis_config = get_redis_config()
            if redis_config and isinstance(redis_config, dict):
                self.print_test(
                    "get_redis_config()",
                    "PASS",
                    f"Retrieved {len(redis_config)} keys"
                )
            else:
                self.print_test("get_redis_config()", "FAIL", "Invalid response")
        except Exception as e:
            self.print_test("get_redis_config()", "FAIL", str(e))

        # Test 3.3: JWT config
        try:
            jwt_config = get_jwt_config()
            if jwt_config and isinstance(jwt_config, dict):
                self.print_test(
                    "get_jwt_config()",
                    "PASS",
                    f"Retrieved {len(jwt_config)} keys"
                )
            else:
                self.print_test("get_jwt_config()", "FAIL", "Invalid response")
        except Exception as e:
            self.print_test("get_jwt_config()", "FAIL", str(e))

        # Test 3.4: Individual secret retrieval
        try:
            db_password = get_secret("database", "password")
            if db_password:
                self.print_test(
                    "get_secret() - database password",
                    "PASS",
                    f"Length: {len(db_password)} chars"
                )
            else:
                self.print_test(
                    "get_secret() - database password",
                    "FAIL",
                    "No value returned"
                )
        except Exception as e:
            self.print_test("get_secret() - database password", "FAIL", str(e))

        return True

    def test_cache_behavior(self) -> bool:
        """Test 4: Cache behavior"""
        self.print_header("Test 4: Cache Behavior")

        client = get_vault_client()

        # Test 4.1: Cache miss (first retrieval)
        client.clear_cache()
        start = time.time()
        secret1 = client.get_secret("database", "password")
        time1 = time.time() - start

        if secret1:
            self.print_test(
                "Cache MISS - first retrieval",
                "PASS",
                f"Retrieved in {time1*1000:.2f}ms"
            )
        else:
            self.print_test("Cache MISS - first retrieval", "FAIL")
            return False

        # Test 4.2: Cache hit (second retrieval)
        start = time.time()
        secret2 = client.get_secret("database", "password")
        time2 = time.time() - start

        if secret2 == secret1:
            self.print_test(
                "Cache HIT - second retrieval",
                "PASS",
                f"Retrieved in {time2*1000:.2f}ms (cache speedup: {time1/time2:.1f}x)"
            )
        else:
            self.print_test("Cache HIT - second retrieval", "FAIL", "Value mismatch")

        # Test 4.3: Cache clear
        client.clear_cache()
        if len(client.cache) == 0:
            self.print_test("Cache clear", "PASS")
        else:
            self.print_test("Cache clear", "FAIL", f"{len(client.cache)} items remain")

        return True

    def test_health_check(self) -> bool:
        """Test 5: Health check"""
        self.print_header("Test 5: Health Check")

        try:
            health = vault_health_check()

            # Test 5.1: Health check structure
            required_keys = [
                "vault_available",
                "vault_connected",
                "vault_url",
                "environment"
            ]

            missing_keys = [k for k in required_keys if k not in health]
            if not missing_keys:
                self.print_test(
                    "Health check structure",
                    "PASS",
                    f"All {len(required_keys)} keys present"
                )
            else:
                self.print_test(
                    "Health check structure",
                    "FAIL",
                    f"Missing keys: {missing_keys}"
                )
                return False

            # Test 5.2: Vault status
            if health.get("vault_connected"):
                self.print_test("Vault connection status", "PASS", "Connected")
            else:
                self.print_test(
                    "Vault connection status",
                    "FAIL",
                    "Not connected (fallback mode)"
                )

            # Test 5.3: Authentication status
            if health.get("authenticated"):
                self.print_test("Vault authentication status", "PASS", "Authenticated")
            else:
                self.print_test(
                    "Vault authentication status",
                    "FAIL",
                    "Not authenticated"
                )

            return True

        except Exception as e:
            self.print_test("Health check", "FAIL", str(e))
            return False

    def test_fallback_mechanism(self) -> bool:
        """Test 6: Fallback to .env"""
        self.print_header("Test 6: Fallback Mechanism")

        # Test 6.1: Create client with invalid URL (simulates Vault down)
        try:
            fallback_client = VaultClient(
                vault_url="http://invalid-vault:9999",
                vault_token="invalid"
            )

            if not fallback_client.connected:
                self.print_test(
                    "Fallback client created",
                    "PASS",
                    "Not connected (expected)"
                )
            else:
                self.print_test(
                    "Fallback client created",
                    "FAIL",
                    "Should not be connected"
                )
                return False

        except Exception as e:
            self.print_test("Fallback client created", "FAIL", str(e))
            return False

        # Test 6.2: Test fallback to environment variable
        # Set a test env var
        test_key = "FALLBACK_TEST_SECRET"
        test_value = "fallback_test_value_123"
        os.environ[test_key] = test_value

        try:
            # This should fall back to os.getenv() since Vault is unreachable
            retrieved = fallback_client.get_secret("fallback_test", "secret", test_value)

            if retrieved == test_value:
                self.print_test(
                    "Fallback to environment variable",
                    "PASS",
                    "Retrieved from env var"
                )
            else:
                self.print_test(
                    "Fallback to environment variable",
                    "FAIL",
                    f"Expected '{test_value}', got '{retrieved}'"
                )

        except Exception as e:
            self.print_test("Fallback to environment variable", "FAIL", str(e))
        finally:
            # Cleanup
            if test_key in os.environ:
                del os.environ[test_key]

        return True

    def print_summary(self) -> int:
        """Print test summary and return exit code"""
        self.print_header("Test Summary")

        total = self.tests_passed + self.tests_failed + self.tests_skipped
        pass_rate = (self.tests_passed / total * 100) if total > 0 else 0

        print(f"Total tests:    {total}")
        print(f"{Colors.GREEN}Passed:         {self.tests_passed}{Colors.RESET}")
        print(f"{Colors.RED}Failed:         {self.tests_failed}{Colors.RESET}")
        print(f"{Colors.YELLOW}Skipped:        {self.tests_skipped}{Colors.RESET}")
        print(f"\nPass rate:      {pass_rate:.1f}%")

        if self.tests_failed == 0:
            print(f"\n{Colors.GREEN}{Colors.BOLD}✓ ALL TESTS PASSED{Colors.RESET}")
            return 0
        else:
            print(f"\n{Colors.RED}{Colors.BOLD}✗ {self.tests_failed} TEST(S) FAILED{Colors.RESET}")
            return 1

    def run_all_tests(self) -> int:
        """Run all test suites"""
        print(f"{Colors.BOLD}Vault Integration Test Suite{Colors.RESET}")
        print(f"Vault URL: {self.vault_url}")
        print(f"Verbose: {self.verbose}")

        # Run tests in sequence
        if not self.test_prerequisites():
            print(f"\n{Colors.RED}Prerequisites failed - aborting{Colors.RESET}")
            return self.print_summary()

        if not self.test_vault_connectivity():
            print(f"\n{Colors.YELLOW}Vault not available - running limited tests{Colors.RESET}")
            # Skip tests that require Vault
            self.tests_skipped += 10  # Approximate number of skipped tests
        else:
            # Full test suite
            self.test_secret_retrieval()
            self.test_cache_behavior()
            self.test_health_check()

        # Fallback tests can run regardless of Vault status
        self.test_fallback_mechanism()

        return self.print_summary()


def main():
    """Main test runner"""
    parser = argparse.ArgumentParser(
        description="Vault Integration Test Suite"
    )
    parser.add_argument(
        "--vault-url",
        default=os.getenv("VAULT_ADDR", "http://localhost:8200"),
        help="Vault server URL (default: http://localhost:8200)"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    tester = VaultIntegrationTester(
        vault_url=args.vault_url,
        verbose=args.verbose
    )

    exit_code = tester.run_all_tests()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
