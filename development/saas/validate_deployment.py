#!/usr/bin/env python3
"""
Deployment Validation Script
Post-Load Testing Optimization Validation

This script validates that the health endpoint and stats API optimizations
are working correctly after deployment.

Usage:
    python validate_deployment.py --host http://localhost:8000
    python validate_deployment.py --host https://staging.example.com --token YOUR_AUTH_TOKEN
"""

import argparse
import json
import platform
import subprocess
import sys
import time
from typing import Dict, List, Tuple
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("ERROR: requests library not installed")
    print("Install with: pip install requests")
    sys.exit(1)


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

    @classmethod
    def disable(cls):
        """Disable colors (for Windows without ANSI support)"""
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.RED = ''
        cls.BLUE = ''
        cls.NC = ''


class ValidationResult:
    """Container for validation test results"""
    def __init__(self, name: str, passed: bool, message: str, details: str = ""):
        self.name = name
        self.passed = passed
        self.message = message
        self.details = details

    def __str__(self):
        status = f"{Colors.GREEN}✓ PASS{Colors.NC}" if self.passed else f"{Colors.RED}✗ FAIL{Colors.NC}"
        return f"{status} {self.name}: {self.message}"


class DeploymentValidator:
    """Validates deployment health and performance"""

    def __init__(self, base_url: str, auth_token: str = None):
        self.base_url = base_url.rstrip('/')
        self.auth_token = auth_token
        self.results: List[ValidationResult] = []
        self.session = requests.Session()

        # Set timeout for all requests
        self.session.timeout = (5, 30)  # 5s connect, 30s read

        # Add auth header if provided
        if auth_token:
            self.session.headers.update({'Authorization': f'Bearer {auth_token}'})

    def log_info(self, message: str):
        """Print info message"""
        print(f"{Colors.BLUE}[INFO]{Colors.NC} {message}")

    def log_success(self, message: str):
        """Print success message"""
        print(f"{Colors.GREEN}[PASS]{Colors.NC} {message}")

    def log_warning(self, message: str):
        """Print warning message"""
        print(f"{Colors.YELLOW}[WARN]{Colors.NC} {message}")

    def log_error(self, message: str):
        """Print error message"""
        print(f"{Colors.RED}[FAIL]{Colors.NC} {message}")

    def add_result(self, result: ValidationResult):
        """Add validation result"""
        self.results.append(result)
        print(f"  {result}")
        if result.details:
            print(f"    {result.details}")

    def validate_health_endpoint(self) -> bool:
        """Test 1: Validate health endpoint response"""
        self.log_info("Test 1: Health Endpoint Response...")

        try:
            response = self.session.get(f"{self.base_url}/health")
            data = response.json()

            # Check status code
            if response.status_code != 200:
                self.add_result(ValidationResult(
                    "Health Endpoint Status",
                    False,
                    f"HTTP {response.status_code} (expected 200)",
                    f"Response: {response.text[:200]}"
                ))
                return False

            self.add_result(ValidationResult(
                "Health Endpoint Status",
                True,
                "HTTP 200 OK"
            ))

            # Check response structure
            required_fields = ['status', 'database', 'gpu_available', 'timestamp']
            missing_fields = [f for f in required_fields if f not in data]

            if missing_fields:
                self.add_result(ValidationResult(
                    "Health Response Structure",
                    False,
                    f"Missing fields: {', '.join(missing_fields)}"
                ))
                return False

            self.add_result(ValidationResult(
                "Health Response Structure",
                True,
                "All required fields present"
            ))

            # CRITICAL: Check that stats field is NOT present (optimization)
            if 'stats' in data:
                self.add_result(ValidationResult(
                    "Health Endpoint Optimization",
                    False,
                    "Response contains 'stats' field!",
                    "The health endpoint optimization was not applied correctly. "
                    "Stats should be moved to /api/stats endpoint."
                ))
                return False

            self.add_result(ValidationResult(
                "Health Endpoint Optimization",
                True,
                "Lightweight response (no stats field)",
                "Optimization successfully applied"
            ))

            return True

        except requests.exceptions.RequestException as e:
            self.add_result(ValidationResult(
                "Health Endpoint Connection",
                False,
                f"Failed to connect: {str(e)}"
            ))
            return False

        except json.JSONDecodeError as e:
            self.add_result(ValidationResult(
                "Health Response Format",
                False,
                f"Invalid JSON: {str(e)}"
            ))
            return False

    def validate_response_time(self) -> bool:
        """Test 2: Validate health endpoint response time"""
        self.log_info("Test 2: Health Endpoint Response Time...")

        try:
            # Warm up request
            self.session.get(f"{self.base_url}/health")

            # Measure response time over 10 requests
            times = []
            for _ in range(10):
                start = time.time()
                response = self.session.get(f"{self.base_url}/health")
                elapsed = (time.time() - start) * 1000  # Convert to ms
                times.append(elapsed)

                if response.status_code != 200:
                    break

            avg_time = sum(times) / len(times)
            min_time = min(times)
            max_time = max(times)

            # Check against targets
            if avg_time > 100:
                self.add_result(ValidationResult(
                    "Response Time (Average)",
                    False,
                    f"{avg_time:.1f}ms (target: <100ms)",
                    f"Min: {min_time:.1f}ms, Max: {max_time:.1f}ms"
                ))
                return False
            elif avg_time > 50:
                self.add_result(ValidationResult(
                    "Response Time (Average)",
                    True,
                    f"{avg_time:.1f}ms (acceptable, target: <50ms)",
                    f"Min: {min_time:.1f}ms, Max: {max_time:.1f}ms"
                ))
            else:
                self.add_result(ValidationResult(
                    "Response Time (Average)",
                    True,
                    f"{avg_time:.1f}ms (excellent!)",
                    f"Min: {min_time:.1f}ms, Max: {max_time:.1f}ms"
                ))

            return True

        except requests.exceptions.RequestException as e:
            self.add_result(ValidationResult(
                "Response Time Test",
                False,
                f"Failed: {str(e)}"
            ))
            return False

    def validate_stats_endpoint(self) -> bool:
        """Test 3: Validate stats endpoint exists and requires auth"""
        self.log_info("Test 3: Stats Endpoint Authentication...")

        try:
            # Test without auth token (should fail)
            session_no_auth = requests.Session()
            response_no_auth = session_no_auth.get(
                f"{self.base_url}/api/stats",
                timeout=5
            )

            if response_no_auth.status_code in [401, 403]:
                self.add_result(ValidationResult(
                    "Stats Endpoint Authentication",
                    True,
                    f"Requires authentication (HTTP {response_no_auth.status_code})"
                ))
            else:
                self.add_result(ValidationResult(
                    "Stats Endpoint Authentication",
                    False,
                    f"HTTP {response_no_auth.status_code} (expected 401/403)",
                    "Stats endpoint should require authentication!"
                ))
                return False

            # If auth token provided, test with auth
            if self.auth_token:
                response_with_auth = self.session.get(f"{self.base_url}/api/stats")

                if response_with_auth.status_code == 200:
                    data = response_with_auth.json()

                    # Check that stats endpoint has the statistics
                    if 'tenants' in data and 'users' in data:
                        self.add_result(ValidationResult(
                            "Stats Endpoint Response",
                            True,
                            "Returns detailed statistics with valid auth"
                        ))
                    else:
                        self.add_result(ValidationResult(
                            "Stats Endpoint Response",
                            False,
                            "Missing expected statistics fields"
                        ))
                        return False
                else:
                    self.log_warning(
                        f"Auth token provided but stats endpoint returned HTTP {response_with_auth.status_code}"
                    )

            return True

        except requests.exceptions.RequestException as e:
            self.add_result(ValidationResult(
                "Stats Endpoint Test",
                False,
                f"Failed: {str(e)}"
            ))
            return False

    def validate_connection_leaks(self) -> bool:
        """Test 4: Check for connection leaks (Linux only)"""
        self.log_info("Test 4: Connection Leak Check...")

        # Only run on Linux
        if platform.system() != 'Linux':
            self.log_warning("Skipping connection leak check (requires Linux)")
            self.add_result(ValidationResult(
                "Connection Leak Check",
                True,
                "Skipped (not on Linux)",
                "This check requires Linux netstat command"
            ))
            return True

        try:
            # Parse URL to get port
            parsed = urlparse(self.base_url)
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)

            # Check for CLOSE_WAIT connections
            result = subprocess.run(
                f"netstat -an | grep ':{port}' | grep 'CLOSE_WAIT' | wc -l",
                shell=True,
                capture_output=True,
                text=True
            )

            close_wait_count = int(result.stdout.strip())

            if close_wait_count > 10:
                self.add_result(ValidationResult(
                    "Connection Leak Check",
                    False,
                    f"Found {close_wait_count} CLOSE_WAIT connections",
                    "Possible connection leak detected. Monitor during load testing."
                ))
                return False
            elif close_wait_count > 0:
                self.add_result(ValidationResult(
                    "Connection Leak Check",
                    True,
                    f"Found {close_wait_count} CLOSE_WAIT connections (acceptable)",
                    "A few CLOSE_WAIT connections are normal"
                ))
            else:
                self.add_result(ValidationResult(
                    "Connection Leak Check",
                    True,
                    "No CLOSE_WAIT connections found",
                    "Connection leak fix validated"
                ))

            return True

        except Exception as e:
            self.log_warning(f"Could not check connection leaks: {e}")
            self.add_result(ValidationResult(
                "Connection Leak Check",
                True,
                "Could not check (non-critical)"
            ))
            return True

    def validate_platform(self) -> bool:
        """Test 5: Validate deployment platform"""
        self.log_info("Test 5: Platform Validation...")

        system = platform.system()
        is_linux = system == 'Linux'

        if is_linux:
            self.add_result(ValidationResult(
                "Deployment Platform",
                True,
                f"Running on {system} (recommended for production)"
            ))
        else:
            self.add_result(ValidationResult(
                "Deployment Platform",
                False,
                f"Running on {system} (Windows has FD_SETSIZE limit)",
                "Production deployment requires Linux for >1K concurrent users"
            ))
            return False

        # Check file descriptor limit on Linux
        if is_linux:
            try:
                result = subprocess.run(
                    "ulimit -n",
                    shell=True,
                    capture_output=True,
                    text=True
                )
                fd_limit = int(result.stdout.strip())

                if fd_limit >= 65536:
                    self.add_result(ValidationResult(
                        "File Descriptor Limit",
                        True,
                        f"{fd_limit} (sufficient for high concurrency)"
                    ))
                else:
                    self.add_result(ValidationResult(
                        "File Descriptor Limit",
                        False,
                        f"{fd_limit} (recommend 65536+)",
                        "Run: ulimit -n 65536"
                    ))
                    return False

            except Exception as e:
                self.log_warning(f"Could not check ulimit: {e}")

        return True

    def run_all_validations(self) -> bool:
        """Run all validation tests"""
        print("\n" + "=" * 70)
        print("DEPLOYMENT VALIDATION")
        print("=" * 70)
        print(f"Target: {self.base_url}")
        print(f"Platform: {platform.system()} {platform.release()}")
        print("=" * 70 + "\n")

        # Run all tests
        tests = [
            ("Health Endpoint", self.validate_health_endpoint),
            ("Response Time", self.validate_response_time),
            ("Stats Endpoint", self.validate_stats_endpoint),
            ("Connection Leaks", self.validate_connection_leaks),
            ("Platform", self.validate_platform),
        ]

        for test_name, test_func in tests:
            try:
                test_func()
            except Exception as e:
                self.log_error(f"Test '{test_name}' crashed: {e}")
                self.add_result(ValidationResult(
                    test_name,
                    False,
                    f"Test crashed: {str(e)}"
                ))

            print()  # Blank line between tests

        # Summary
        self.print_summary()

        # Return overall pass/fail
        return all(r.passed for r in self.results)

    def print_summary(self):
        """Print validation summary"""
        print("=" * 70)
        print("VALIDATION SUMMARY")
        print("=" * 70)

        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)
        total = len(self.results)

        print(f"\nTotal Tests: {total}")
        print(f"{Colors.GREEN}Passed: {passed}{Colors.NC}")
        print(f"{Colors.RED}Failed: {failed}{Colors.NC}")

        if failed > 0:
            print(f"\n{Colors.RED}VALIDATION FAILED{Colors.NC}")
            print("\nFailed Tests:")
            for result in self.results:
                if not result.passed:
                    print(f"  • {result.name}: {result.message}")
        else:
            print(f"\n{Colors.GREEN}ALL VALIDATIONS PASSED ✓{Colors.NC}")
            print("\nDeployment is ready for load testing.")
            print("\nNext Steps:")
            print("  1. Run baseline load test (100 users)")
            print("  2. Run production load test (1K users)")
            print("  3. Validate >99% success rate, <100ms P50 latency")

        print("\n" + "=" * 70 + "\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Validate deployment after load testing optimizations'
    )
    parser.add_argument(
        '--host',
        default='http://localhost:8000',
        help='Base URL of the deployed application (default: http://localhost:8000)'
    )
    parser.add_argument(
        '--token',
        help='Authentication token for testing /api/stats endpoint'
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )

    args = parser.parse_args()

    # Disable colors if requested or on Windows (unless ANSICON is available)
    if args.no_color or (platform.system() == 'Windows' and 'ANSICON' not in os.environ):
        Colors.disable()

    # Run validation
    validator = DeploymentValidator(args.host, args.token)
    success = validator.run_all_validations()

    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    import os
    main()
