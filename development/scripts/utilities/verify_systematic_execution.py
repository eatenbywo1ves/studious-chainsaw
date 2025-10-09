#!/usr/bin/env python3
"""
Systematic Execution Verification Script

Validates that all 6 phases of the systematic execution plan have been
completed successfully by checking for required files and configurations.
"""

import sys
from pathlib import Path
from typing import List, Tuple, Dict

# Color codes for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"


class SystematicExecutionVerifier:
    """Verify all phases of systematic execution plan."""

    def __init__(self, base_path: str = "."):
        self.base_path = Path(base_path)
        self.results: Dict[str, List[Tuple[str, bool, str]]] = {}

    def check_file_exists(self, file_path: str, description: str) -> Tuple[str, bool, str]:
        """Check if a file exists."""
        full_path = self.base_path / file_path
        exists = full_path.exists()
        return (description, exists, str(full_path))

    def check_directory_exists(self, dir_path: str, description: str) -> Tuple[str, bool, str]:
        """Check if a directory exists."""
        full_path = self.base_path / dir_path
        exists = full_path.is_dir()
        return (description, exists, str(full_path))

    def verify_phase1_integration_tests(self) -> List[Tuple[str, bool, str]]:
        """Verify Phase 1: Integration Test Infrastructure."""
        checks = [
            self.check_directory_exists("tests/integration", "Integration tests directory"),
            self.check_file_exists("tests/integration/conftest.py", "Integration test fixtures"),
            self.check_file_exists(
                "tests/integration/test_full_saas_workflow.py", "SaaS workflow tests"
            ),
            self.check_file_exists(
                "tests/integration/test_gpu_saas_integration.py", "GPU integration tests"
            ),
            self.check_file_exists(
                "tests/integration/test_security_integration.py", "Security tests"
            ),
            self.check_file_exists(
                "tests/integration/test_monitoring_integration.py", "Monitoring tests"
            ),
            self.check_file_exists(
                "tests/integration/docker-compose.test.yml", "Test Docker environment"
            ),
            self.check_file_exists("tests/integration/README.md", "Integration test documentation"),
        ]
        self.results["Phase 1: Integration Tests"] = checks
        return checks

    def verify_phase2_api_documentation(self) -> List[Tuple[str, bool, str]]:
        """Verify Phase 2: API Documentation."""
        checks = [
            self.check_directory_exists("docs/api", "API documentation directory"),
            self.check_file_exists("docs/api/openapi_generator.py", "OpenAPI generator"),
            self.check_file_exists("docs/api/openapi.yaml", "OpenAPI YAML specification"),
            self.check_file_exists("docs/api/openapi.json", "OpenAPI JSON specification"),
            self.check_file_exists("saas/api/docs_integration.py", "FastAPI Swagger integration"),
            self.check_file_exists("docs/api/API_DOCUMENTATION.md", "API documentation"),
            self.check_file_exists("docs/api/README.md", "API docs README"),
        ]
        self.results["Phase 2: API Documentation"] = checks
        return checks

    def verify_phase3_e2e_testing(self) -> List[Tuple[str, bool, str]]:
        """Verify Phase 3: E2E Testing Framework."""
        checks = [
            self.check_directory_exists("tests/e2e", "E2E tests directory"),
            self.check_file_exists("tests/e2e/conftest.py", "E2E test fixtures"),
            self.check_file_exists("tests/e2e/test_user_journey.py", "User journey tests"),
            self.check_file_exists("tests/e2e/test_gpu_workflow.py", "GPU workflow tests"),
            self.check_file_exists("tests/e2e/test_webhook_workflow.py", "Webhook tests"),
            self.check_file_exists("tests/e2e/docker-compose.e2e.yml", "E2E Docker environment"),
            self.check_file_exists("tests/e2e/README.md", "E2E test documentation"),
        ]
        self.results["Phase 3: E2E Testing"] = checks
        return checks

    def verify_phase4_load_testing(self) -> List[Tuple[str, bool, str]]:
        """Verify Phase 4: Load Testing Framework."""
        checks = [
            self.check_directory_exists("tests/load", "Load tests directory"),
            self.check_file_exists("tests/load/locustfile.py", "Locust load test scenarios"),
            self.check_file_exists(
                "tests/load/docker-compose.load-test.yml", "Load test Docker environment"
            ),
            self.check_file_exists("tests/load/PERFORMANCE_BASELINES.md", "Performance baselines"),
            self.check_file_exists("tests/load/README.md", "Load test documentation"),
        ]
        self.results["Phase 4: Load Testing"] = checks
        return checks

    def verify_phase5_monitoring(self) -> List[Tuple[str, bool, str]]:
        """Verify Phase 5: Monitoring Validation."""
        checks = [
            self.check_directory_exists("tests/monitoring", "Monitoring tests directory"),
            self.check_directory_exists("docs/monitoring/runbooks", "Alert runbooks directory"),
            self.check_file_exists("docs/monitoring/METRICS_CATALOG.md", "Metrics catalog"),
            self.check_file_exists(
                "docs/monitoring/MONITORING_CHECKLIST.md", "Monitoring checklist"
            ),
        ]
        self.results["Phase 5: Monitoring"] = checks
        return checks

    def verify_phase6_deployment(self) -> List[Tuple[str, bool, str]]:
        """Verify Phase 6: Production Deployment."""
        checks = [
            self.check_directory_exists("kubernetes", "Kubernetes manifests directory"),
            self.check_directory_exists("tests/smoke", "Smoke tests directory"),
            self.check_directory_exists("docs/deployment", "Deployment documentation directory"),
            self.check_file_exists(
                "docs/deployment/PRODUCTION_DEPLOYMENT_GUIDE.md", "Deployment guide"
            ),
            self.check_file_exists(
                "docs/deployment/PRODUCTION_READINESS_CHECKLIST.md", "Readiness checklist"
            ),
            self.check_file_exists("docs/deployment/ROLLBACK_PROCEDURES.md", "Rollback procedures"),
        ]
        self.results["Phase 6: Deployment"] = checks
        return checks

    def print_phase_results(self, phase_name: str, checks: List[Tuple[str, bool, str]]) -> bool:
        """Print results for a phase."""
        all_passed = all(passed for _, passed, _ in checks)
        status_icon = f"{GREEN}✅{RESET}" if all_passed else f"{RED}❌{RESET}"

        print(f"\n{BOLD}{phase_name}{RESET} {status_icon}")
        print("─" * 80)

        for description, passed, path in checks:
            icon = f"{GREEN}✓{RESET}" if passed else f"{RED}✗{RESET}"
            status = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
            print(f"  {icon} {description:<50} [{status}]")
            if not passed:
                print(f"      {YELLOW}Missing: {path}{RESET}")

        return all_passed

    def print_summary(self, all_phases_passed: bool):
        """Print overall summary."""
        print("\n" + "=" * 80)
        print(f"{BOLD}SYSTEMATIC EXECUTION VERIFICATION SUMMARY{RESET}")
        print("=" * 80)

        total_checks = sum(len(checks) for checks in self.results.values())
        passed_checks = sum(
            sum(1 for _, passed, _ in checks if passed) for checks in self.results.values()
        )

        print(f"\nTotal Checks:  {total_checks}")
        print(f"Passed:        {GREEN}{passed_checks}{RESET}")
        print(f"Failed:        {RED}{total_checks - passed_checks}{RESET}")
        print(f"Success Rate:  {GREEN}{passed_checks / total_checks * 100:.1f}%{RESET}")

        if all_phases_passed:
            print(f"\n{GREEN}{BOLD}✅ ALL PHASES VERIFIED - PRODUCTION READY{RESET}")
            print(f"\n{BLUE}Next Steps:{RESET}")
            print("  1. Review docs/deployment/PRODUCTION_DEPLOYMENT_GUIDE.md")
            print("  2. Complete docs/deployment/PRODUCTION_READINESS_CHECKLIST.md")
            print("  3. Run integration tests: cd tests/integration && pytest -v")
            print("  4. Run E2E tests: cd tests/e2e && pytest -v")
            print("  5. Deploy to production: kubectl apply -f kubernetes/")
        else:
            print(f"\n{RED}{BOLD}❌ VERIFICATION FAILED{RESET}")
            print(f"\n{YELLOW}Action Required:{RESET}")
            print("  Review failed checks above and complete missing components")

    def run_verification(self) -> bool:
        """Run complete verification."""
        print(f"{BOLD}{'=' * 80}{RESET}")
        print(f"{BOLD}SYSTEMATIC EXECUTION PLAN VERIFICATION{RESET}")
        print(f"{BOLD}{'=' * 80}{RESET}")
        print(f"\nBase Path: {self.base_path.absolute()}")

        # Run all phase verifications
        [
            self.verify_phase1_integration_tests(),
            self.verify_phase2_api_documentation(),
            self.verify_phase3_e2e_testing(),
            self.verify_phase4_load_testing(),
            self.verify_phase5_monitoring(),
            self.verify_phase6_deployment(),
        ]

        # Print results for each phase
        all_passed = True
        for phase_name, checks in self.results.items():
            phase_passed = self.print_phase_results(phase_name, checks)
            all_passed = all_passed and phase_passed

        # Print summary
        self.print_summary(all_passed)

        return all_passed


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Verify systematic execution plan completion")
    parser.add_argument(
        "--path",
        default=".",
        help="Base path to development directory (default: current directory)",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Only show summary (hide individual checks)"
    )

    args = parser.parse_args()

    verifier = SystematicExecutionVerifier(args.path)

    # Disable colored output on Windows if not supported
    if sys.platform == "win32":
        try:
            import colorama

            colorama.init()
        except ImportError:
            # Disable colors if colorama not available
            globals()["GREEN"] = ""
            globals()["RED"] = ""
            globals()["YELLOW"] = ""
            globals()["BLUE"] = ""
            globals()["RESET"] = ""
            globals()["BOLD"] = ""

    success = verifier.run_verification()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
