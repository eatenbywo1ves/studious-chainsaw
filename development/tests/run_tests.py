#!/usr/bin/env python3
"""
Test Runner Script for Catalytic Computing System
Provides convenient commands for running different test suites
"""

import sys
import argparse
import subprocess
from pathlib import Path
from typing import List, Optional

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))


class TestRunner:
    """Manages test execution with various options"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.project_root = Path(__file__).parent
        self.test_dir = self.project_root / "tests"

    def run_command(self, cmd: List[str], cwd: Optional[Path] = None) -> int:
        """Run a command and return exit code"""
        if self.verbose:
            print(f"Running: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            cwd=cwd or self.project_root,
            capture_output=not self.verbose
        )

        if not self.verbose and result.returncode != 0:
            print(f"Command failed: {' '.join(cmd)}")
            if result.stdout:
                print(result.stdout.decode())
            if result.stderr:
                print(result.stderr.decode())

        return result.returncode

    def run_all_tests(self, coverage: bool = True) -> int:
        """Run all tests with optional coverage"""
        print("Running all tests...")
        cmd = ["pytest", "-v"]

        if coverage:
            cmd.extend([
                "--cov=.",
                "--cov-report=term-missing",
                "--cov-report=html",
                "--cov-config=.coveragerc"
            ])

        return self.run_command(cmd)

    def run_unit_tests(self, coverage: bool = False) -> int:
        """Run unit tests only"""
        print("Running unit tests...")
        cmd = ["pytest", "tests/unit", "-v"]

        if coverage:
            cmd.extend(["--cov=.", "--cov-report=term"])

        return self.run_command(cmd)

    def run_integration_tests(self) -> int:
        """Run integration tests"""
        print("Running integration tests...")
        cmd = ["pytest", "tests/integration", "-v"]
        return self.run_command(cmd)

    def run_performance_tests(self) -> int:
        """Run performance/benchmark tests"""
        print("Running performance tests...")
        cmd = ["pytest", "tests/performance", "-v", "--benchmark-only"]
        return self.run_command(cmd)

    def run_specific_test(self, test_path: str) -> int:
        """Run a specific test file or test"""
        print(f"Running specific test: {test_path}")
        cmd = ["pytest", test_path, "-v"]
        return self.run_command(cmd)

    def run_tests_with_markers(self, markers: List[str]) -> int:
        """Run tests with specific markers"""
        print(f"Running tests with markers: {', '.join(markers)}")
        cmd = ["pytest", "-v"]

        for marker in markers:
            cmd.extend(["-m", marker])

        return self.run_command(cmd)

    def run_coverage_report(self) -> int:
        """Generate coverage report without running tests"""
        print("Generating coverage report...")

        # Generate terminal report
        self.run_command(["coverage", "report"])

        # Generate HTML report
        self.run_command(["coverage", "html"])

        print("\nCoverage report generated:")
        print("  - Terminal report displayed above")
        print("  - HTML report: htmlcov/index.html")

        return 0

    def run_type_checking(self) -> int:
        """Run mypy type checking"""
        print("Running type checking with mypy...")
        cmd = ["mypy", ".", "--config-file", "pyproject.toml"]
        return self.run_command(cmd)

    def run_linting(self) -> int:
        """Run code linting"""
        print("Running linting...")

        # Run flake8
        print("  Running flake8...")
        ret1 = self.run_command(["flake8", "."])

        # Run pylint
        print("  Running pylint...")
        ret2 = self.run_command(["pylint", "*.py"])

        return ret1 or ret2

    def run_security_check(self) -> int:
        """Run security checks with bandit"""
        print("Running security checks...")
        cmd = ["bandit", "-r", ".", "-f", "screen"]
        return self.run_command(cmd)

    def run_quick_check(self) -> int:
        """Run quick checks (fast unit tests only)"""
        print("Running quick checks...")
        cmd = [
            "pytest",
            "tests/unit",
            "-v",
            "-m", "not slow",
            "--maxfail=1",
            "-x"
        ]
        return self.run_command(cmd)

    def run_ci_suite(self) -> int:
        """Run full CI test suite"""
        print("Running CI test suite...")

        results = []

        # Type checking
        print("\n1. Type Checking")
        results.append(self.run_type_checking())

        # Linting
        print("\n2. Linting")
        results.append(self.run_linting())

        # Security
        print("\n3. Security Check")
        results.append(self.run_security_check())

        # Tests with coverage
        print("\n4. Tests with Coverage")
        results.append(self.run_all_tests(coverage=True))

        # Check if any failed
        if any(results):
            print("\n❌ CI suite failed!")
            return 1
        else:
            print("\n✅ CI suite passed!")
            return 0


def main():
    """Main entry point for test runner"""
    parser = argparse.ArgumentParser(
        description="Test runner for Catalytic Computing System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_tests.py                    # Run all tests with coverage
  python run_tests.py unit               # Run unit tests only
  python run_tests.py integration        # Run integration tests
  python run_tests.py performance        # Run performance tests
  python run_tests.py -m gpu            # Run tests marked with 'gpu'
  python run_tests.py -t tests/unit/test_validation.py  # Run specific test file
  python run_tests.py quick             # Run quick checks
  python run_tests.py ci                # Run full CI suite
        """
    )

    parser.add_argument(
        "suite",
        nargs="?",
        default="all",
        choices=[
            "all", "unit", "integration", "performance",
            "coverage", "type", "lint", "security", "quick", "ci"
        ],
        help="Test suite to run (default: all)"
    )

    parser.add_argument(
        "-t", "--test",
        help="Run specific test file or test"
    )

    parser.add_argument(
        "-m", "--markers",
        nargs="+",
        help="Run tests with specific markers"
    )

    parser.add_argument(
        "--no-coverage",
        action="store_true",
        help="Skip coverage reporting"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    # Create test runner
    runner = TestRunner(verbose=args.verbose)

    # Handle specific test
    if args.test:
        return runner.run_specific_test(args.test)

    # Handle markers
    if args.markers:
        return runner.run_tests_with_markers(args.markers)

    # Handle test suites
    coverage = not args.no_coverage

    if args.suite == "all":
        return runner.run_all_tests(coverage=coverage)
    elif args.suite == "unit":
        return runner.run_unit_tests(coverage=coverage)
    elif args.suite == "integration":
        return runner.run_integration_tests()
    elif args.suite == "performance":
        return runner.run_performance_tests()
    elif args.suite == "coverage":
        return runner.run_coverage_report()
    elif args.suite == "type":
        return runner.run_type_checking()
    elif args.suite == "lint":
        return runner.run_linting()
    elif args.suite == "security":
        return runner.run_security_check()
    elif args.suite == "quick":
        return runner.run_quick_check()
    elif args.suite == "ci":
        return runner.run_ci_suite()
    else:
        print(f"Unknown suite: {args.suite}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
