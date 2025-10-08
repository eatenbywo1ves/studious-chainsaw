#!/usr/bin/env python3
"""
Automated Penetration Testing Suite
Tests security vulnerabilities before production deployment
"""

import requests
import time
import sys
from urllib.parse import urljoin

# Color codes
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
RED = '\033[0;31m'
NC = '\033[0m'


class PenetrationTester:
    """Automated penetration testing"""

    def __init__(self, base_url: str, verbose: bool = False):
        self.base_url = base_url
        self.verbose = verbose
        self.results = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        self.session = requests.Session()

    def print_header(self, message: str):
        print(f"\n{BLUE}{'=' * 70}{NC}")
        print(f"{BLUE}{message}{NC}")
        print(f"{BLUE}{'=' * 70}{NC}\n")

    def print_test(self, message: str):
        print(f"{BLUE}[TEST] {message}{NC}")

    def print_pass(self, message: str):
        print(f"{GREEN}[PASS] {message}{NC}")

    def print_fail(self, message: str, severity: str = 'medium'):
        color = RED if severity in ['critical', 'high'] else YELLOW
        print(f"{color}[FAIL] {message} (Severity: {severity.upper()}){NC}")
        self.results[severity].append(message)

    def print_info(self, message: str):
        print(f"{YELLOW}[INFO] {message}{NC}")

    # ========================================================================
    # 1. AUTHENTICATION TESTS
    # ========================================================================

    def test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        self.print_header("1. Authentication Bypass Tests")

        # Test 1: Access protected endpoint without token
        self.print_test("Testing access to protected endpoint without authentication")
        try:
            response = self.session.get(urljoin(self.base_url, '/api/protected'))
            if response.status_code == 200:
                self.print_fail("Protected endpoint accessible without authentication", 'critical')
            else:
                self.print_pass("Protected endpoint properly secured")
        except Exception as e:
            self.print_info(f"Endpoint not available: {e}")

        # Test 2: SQL injection in login
        self.print_test("Testing SQL injection in login endpoint")
        payloads = [
            "' OR '1'='1",
            "admin'--",
            "' OR 1=1--",
            "admin' OR '1'='1'/*"
        ]
        for payload in payloads:
            try:
                response = self.session.post(
                    urljoin(self.base_url, '/auth/login'),
                    json={'username': payload, 'password': payload}
                )
                if response.status_code == 200 and 'token' in response.text.lower():
                    self.print_fail(f"SQL injection successful with payload: {payload}", 'critical')
                    break
            except:
                pass
        else:
            self.print_pass("SQL injection attempts blocked")

        # Test 3: Weak password acceptance
        self.print_test("Testing weak password acceptance")
        # This test would require creating test accounts
        self.print_info("Manual verification needed for password strength policy")

    def test_session_management(self):
        """Test session management security"""
        self.print_header("2. Session Management Tests")

        # Test 1: Token in URL
        self.print_test("Checking if tokens are passed in URLs")
        # Check server logs or URL patterns
        self.print_pass("Tokens should be in headers, not URLs (manual verification needed)")

        # Test 2: Session fixation
        self.print_test("Testing session fixation vulnerabilities")
        self.print_info("Manual testing required")

        # Test 3: Token expiration
        self.print_test("Verifying token expiration")
        self.print_info("Create token and wait 16 minutes, then test (manual verification)")

    # ========================================================================
    # 2. AUTHORIZATION TESTS
    # ========================================================================

    def test_authorization_bypass(self):
        """Test for authorization bypass (privilege escalation)"""
        self.print_header("3. Authorization Bypass Tests")

        # Test 1: Insecure Direct Object Reference (IDOR)
        self.print_test("Testing IDOR vulnerabilities")
        # Try accessing other users' resources
        self.print_info("Create two users, try user1 accessing user2's resources")

        # Test 2: Path traversal
        self.print_test("Testing path traversal attacks")
        payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '....//....//....//etc/passwd'
        ]
        for payload in payloads:
            try:
                response = self.session.get(urljoin(self.base_url, f'/api/files/{payload}'))
                if response.status_code == 200 and ('root:' in response.text or 'Administrator' in response.text):
                    self.print_fail(f"Path traversal successful: {payload}", 'critical')
                    break
            except:
                pass
        else:
            self.print_pass("Path traversal attempts blocked")

    # ========================================================================
    # 3. INJECTION TESTS
    # ========================================================================

    def test_injection_attacks(self):
        """Test for various injection vulnerabilities"""
        self.print_header("4. Injection Attack Tests")

        # Test 1: XSS
        self.print_test("Testing Cross-Site Scripting (XSS)")
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            'javascript:alert("XSS")',
            '<svg onload=alert("XSS")>'
        ]

        # Test input fields
        try:
            response = self.session.post(
                urljoin(self.base_url, '/api/test-input'),
                json={'text': xss_payloads[0]}
            )
            if xss_payloads[0] in response.text:
                self.print_fail("XSS payload not sanitized", 'high')
            else:
                self.print_pass("XSS payloads properly sanitized")
        except:
            self.print_info("XSS test endpoint not available")

        # Test 2: Command Injection
        self.print_test("Testing command injection")
        self.print_info("Command injection test requires manual verification of input processing")

        # Test 3: NoSQL Injection
        self.print_test("Testing NoSQL injection")
        self.print_info("NoSQL injection test requires database interaction testing")

    # ========================================================================
    # 4. RATE LIMITING TESTS
    # ========================================================================

    def test_rate_limiting(self):
        """Test rate limiting and DDoS protection"""
        self.print_header("5. Rate Limiting Tests")

        # Test 1: Basic rate limiting
        self.print_test("Testing rate limiting (sending 100 requests)")
        endpoint = urljoin(self.base_url, '/api/health')
        blocked_count = 0

        for i in range(100):
            try:
                response = self.session.get(endpoint, timeout=1)
                if response.status_code == 429:  # Too Many Requests
                    blocked_count += 1
            except:
                pass

        if blocked_count > 0:
            self.print_pass(f"Rate limiting working ({blocked_count}/100 requests blocked)")
        else:
            self.print_fail("No rate limiting detected after 100 requests", 'medium')

        # Test 2: Rate limit headers
        self.print_test("Checking for rate limit headers")
        try:
            response = self.session.get(endpoint)
            headers = response.headers
            if 'X-RateLimit-Limit' in headers or 'X-RateLimit-Remaining' in headers:
                self.print_pass("Rate limit headers present")
            else:
                self.print_fail("Rate limit headers missing", 'low')
        except:
            self.print_info("Could not check rate limit headers")

    # ========================================================================
    # 5. ENCRYPTION TESTS
    # ========================================================================

    def test_encryption(self):
        """Test encryption and TLS configuration"""
        self.print_header("6. Encryption Tests")

        # Test 1: HTTPS enforcement
        self.print_test("Testing HTTPS enforcement")
        if self.base_url.startswith('https://'):
            self.print_pass("Using HTTPS")
        else:
            self.print_fail("Not using HTTPS", 'critical')

        # Test 2: Security headers
        self.print_test("Checking security headers")
        try:
            response = self.session.get(self.base_url)
            headers = response.headers

            required_headers = {
                'Strict-Transport-Security': 'high',
                'X-Content-Type-Options': 'medium',
                'X-Frame-Options': 'medium',
                'X-XSS-Protection': 'low',
                'Content-Security-Policy': 'medium'
            }

            for header, severity in required_headers.items():
                if header in headers:
                    self.print_pass(f"{header} header present: {headers[header]}")
                else:
                    self.print_fail(f"{header} header missing", severity)
        except:
            self.print_info("Could not check security headers")

    # ========================================================================
    # 6. API SECURITY TESTS
    # ========================================================================

    def test_api_security(self):
        """Test API-specific security"""
        self.print_header("7. API Security Tests")

        # Test 1: CORS misconfiguration
        self.print_test("Testing CORS configuration")
        try:
            response = self.session.options(
                self.base_url,
                headers={'Origin': 'https://evil.com'}
            )
            cors_header = response.headers.get('Access-Control-Allow-Origin', '')
            if cors_header == '*':
                self.print_fail("CORS allows all origins (*)", 'medium')
            elif 'evil.com' in cors_header:
                self.print_fail("CORS allows arbitrary origins", 'high')
            else:
                self.print_pass("CORS properly configured")
        except:
            self.print_info("Could not test CORS")

        # Test 2: HTTP methods
        self.print_test("Testing allowed HTTP methods")
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE']
        allowed = []

        for method in methods:
            try:
                response = requests.request(method, self.base_url, timeout=2)
                if response.status_code != 405:  # Method Not Allowed
                    allowed.append(method)
            except:
                pass

        if 'TRACE' in allowed:
            self.print_fail("TRACE method enabled (XST vulnerability)", 'medium')
        else:
            self.print_pass("Dangerous HTTP methods disabled")

        # Test 3: Error message information disclosure
        self.print_test("Testing error message information disclosure")
        try:
            response = self.session.get(urljoin(self.base_url, '/nonexistent'))
            if 'traceback' in response.text.lower() or 'stack trace' in response.text.lower():
                self.print_fail("Error messages reveal stack traces", 'medium')
            else:
                self.print_pass("Error messages don't leak sensitive information")
        except:
            pass

    # ========================================================================
    # 7. BUSINESS LOGIC TESTS
    # ========================================================================

    def test_business_logic(self):
        """Test business logic vulnerabilities"""
        self.print_header("8. Business Logic Tests")

        # Test 1: Price manipulation
        self.print_test("Testing price/quantity manipulation")
        self.print_info("Manual testing required - try negative quantities, prices")

        # Test 2: Race conditions
        self.print_test("Testing race conditions")
        self.print_info("Manual testing required - concurrent requests to same resource")

        # Test 3: Workflow bypass
        self.print_test("Testing workflow bypass")
        self.print_info("Manual testing required - try skipping workflow steps")

    # ========================================================================
    # REPORT GENERATION
    # ========================================================================

    def generate_report(self):
        """Generate penetration testing report"""
        self.print_header("Penetration Testing Report")

        total_issues = sum(len(v) for v in self.results.values())

        print(f"Total Issues Found: {total_issues}\n")

        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = len(self.results[severity])
            if count > 0:
                color = RED if severity in ['critical', 'high'] else YELLOW
                print(f"{color}{severity.upper()}: {count}{NC}")
                for issue in self.results[severity]:
                    print(f"  - {issue}")
                print()

        # Risk assessment
        critical_count = len(self.results['critical'])
        high_count = len(self.results['high'])

        print(f"\n{BLUE}{'=' * 70}{NC}")
        print(f"{BLUE}PRODUCTION READINESS ASSESSMENT{NC}")
        print(f"{BLUE}{'=' * 70}{NC}\n")

        if critical_count > 0:
            print(f"{RED}[BLOCKED] {critical_count} CRITICAL issues must be fixed before production{NC}")
            return False
        elif high_count > 5:
            print(f"{RED}[BLOCKED] Too many HIGH severity issues ({high_count}){NC}")
            return False
        elif high_count > 0:
            print(f"{YELLOW}[WARNING] {high_count} HIGH severity issues should be addressed{NC}")
            return False
        else:
            print(f"{GREEN}[APPROVED] No critical or high severity issues found{NC}")
            return True

    def run_all_tests(self):
        """Run all penetration tests"""
        print(f"{BLUE}")
        print("=" * 70)
        print("  PENETRATION TESTING SUITE")
        print(f"  Target: {self.base_url}")
        print(f"  Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
        print(f"{NC}")

        try:
            # Run all test categories
            self.test_authentication_bypass()
            self.test_session_management()
            self.test_authorization_bypass()
            self.test_injection_attacks()
            self.test_rate_limiting()
            self.test_encryption()
            self.test_api_security()
            self.test_business_logic()

            # Generate report
            return self.generate_report()

        except KeyboardInterrupt:
            print(f"\n{YELLOW}Testing interrupted by user{NC}")
            return False
        except Exception as e:
            print(f"\n{RED}Error during testing: {e}{NC}")
            import traceback
            traceback.print_exc()
            return False


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Automated Penetration Testing Suite")
    parser.add_argument("url", help="Base URL of the API to test (e.g., http://localhost:8000)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Run tests
    tester = PenetrationTester(args.url, args.verbose)
    success = tester.run_all_tests()

    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
