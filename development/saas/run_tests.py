#!/usr/bin/env python3
"""
DEPLOYMENT TEST VALIDATION RUNNER
Executes comprehensive test suite for pre-deployment validation
"""

import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime

# Change to the saas directory
os.chdir(Path(__file__).parent)

def print_header(text):
    """Print formatted header"""
    print("\n" + "="*80)
    print(f"  {text}")
    print("="*80 + "\n")

def run_pytest(args, description):
    """Run pytest with given arguments and return results"""
    print_header(description)

    cmd = ["python", "-m", "pytest"] + args
    print(f"Command: {' '.join(cmd)}\n")

    result = subprocess.run(
        cmd,
        capture_output=False,
        text=True
    )

    return result.returncode == 0

def main():
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║      DEPLOYMENT TEST VALIDATION - COMPREHENSIVE SUITE         ║
    ║      Security Fixes (SEC-009 to SEC-012) Validation           ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

    print(f"Working Directory: {Path.cwd()}")
    print(f"Python: {sys.version}")
    print(f"Timestamp: {datetime.now().isoformat()}\n")

    results = {}

    # Check if pytest is available
    try:
        subprocess.run(["python", "-m", "pytest", "--version"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("ERROR: pytest not found. Installing dependencies...")
        subprocess.run(["pip", "install", "-r", "requirements-test.txt"], check=True)

    # 1. Unit Tests
    results['unit'] = run_pytest(
        ["tests/unit/", "-v", "--tb=short"],
        "PHASE 1: Unit Tests (Mocked Dependencies)"
    )

    # 2. Integration Tests
    results['integration'] = run_pytest(
        ["tests/integration/", "-v", "--tb=short"],
        "PHASE 2: Integration Tests (Real Redis Required)"
    )

    # 3. Security Tests
    results['security'] = run_pytest(
        ["-m", "security", "-v", "--tb=short"],
        "PHASE 3: Security Tests (SEC-009 to SEC-012)"
    )

    # 4. Race Condition Tests
    results['race_condition'] = run_pytest(
        ["-m", "race_condition", "-v", "-s"],
        "PHASE 4: Race Condition Tests (CRITICAL)"
    )

    # 5. Coverage Report
    results['coverage'] = run_pytest(
        [
            "tests/",
            "--cov=auth",
            "--cov=api",
            "--cov-report=term-missing",
            "--cov-report=html:htmlcov",
            "--cov-fail-under=80"
        ],
        "PHASE 5: Coverage Analysis (Target: >80%)"
    )

    # Generate Summary
    print_header("TEST EXECUTION SUMMARY")

    total = len(results)
    passed = sum(1 for v in results.values() if v)
    failed = total - passed

    print("Results by Phase:")
    for phase, success in results.items():
        status = "PASS" if success else "FAIL"
        symbol = "✅" if success else "❌"
        print(f"  {symbol} {phase.upper():20s}: {status}")

    print(f"\n{'='*80}")
    print(f"Total Phases: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"{'='*80}\n")

    if passed == total:
        print("✅ ALL TESTS PASSED - READY FOR DEPLOYMENT")
        print("\nNext Steps:")
        print("  1. Review coverage report: open htmlcov/index.html")
        print("  2. Create deployment commit")
        print("  3. Deploy to staging environment")
        return 0
    else:
        print(f"❌ {failed} PHASE(S) FAILED - DEPLOYMENT BLOCKED")
        print("\nRequired Actions:")
        print("  1. Review test failures above")
        print("  2. Fix failing tests")
        print("  3. Re-run validation: python run_tests.py")
        return 1

if __name__ == "__main__":
    sys.exit(main())
