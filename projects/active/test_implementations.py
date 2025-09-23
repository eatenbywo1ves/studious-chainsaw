"""
Test script for validating the new architecture implementations
Tests service discovery, configuration management, logging, and API gateway
"""

import asyncio
import sys
from pathlib import Path
from typing import Dict

# Add shared libraries to path
sys.path.append(str(Path(__file__).parent / "shared"))

# Import our new implementations
from utilities.health_checks import get_health_registry, HealthCheckResult
from utilities.logging_utils import (
    setup_service_logging,
    LogLevel,
    LogContext,
    with_context,
)
from libraries.config_manager import get_config_manager
from libraries.service_discovery import (
    Service,
    ServiceType,
    ServiceEndpoint,
    HealthCheck,
    get_service_discovery,
    register_service,
)


class ImplementationTester:
    """Test runner for all new implementations"""

    def __init__(self):
        self.logger = setup_service_logging("implementation_tester", LogLevel.INFO)
        self.test_results: Dict[str, bool] = {}

    def log_test_result(self, test_name: str, success: bool, message: str = ""):
        """Log test result"""
        self.test_results[test_name] = success
        "INFO" if success else "ERROR"
        status = "PASS" if success else "FAIL"

        self.logger.info(
            f"[{status}] {test_name}: {message}",
            extra={"test_name": test_name, "status": status, "success": success},
        )

    async def test_service_discovery(self) -> bool:
        """Test service discovery functionality"""
        self.logger.info("Testing Service Discovery...")

        try:
            # Test 1: Get service discovery instance
            discovery = get_service_discovery()
            self.log_test_result(
                "service_discovery_instance", True, "Got service discovery instance"
            )

            # Test 2: Create and register a test service
            test_service = Service(
                id="test-service-001",
                name="test-service",
                type=ServiceType.AGENT,
                version="1.0.0",
                endpoint=ServiceEndpoint(
                    protocol="http", host="localhost", port=8999, path="/test"
                ),
                health_check=HealthCheck(enabled=True, endpoint="/health", interval=30),
                capabilities=["test", "validation"],
                metadata={"test": True},
            )

            success = register_service(test_service)
            self.log_test_result(
                "service_registration",
                success,
                f"Registered test service: {test_service.id}",
            )

            # Test 3: Discover services
            services = discovery.discover_services(service_type=ServiceType.AGENT)
            found_service = next(
                (s for s in services if s.id == "test-service-001"), None
            )

            self.log_test_result(
                "service_discovery",
                found_service is not None,
                f"Found {len(services)} agent services",
            )

            # Test 4: Get specific service
            retrieved_service = discovery.get_service("test-service-001")
            self.log_test_result(
                "service_retrieval",
                retrieved_service is not None,
                "Retrieved specific service by ID",
            )

            # Test 5: Service statistics
            stats = discovery.get_statistics()
            self.log_test_result(
                "service_statistics",
                stats["total_services"] > 0,
                f"Statistics: {stats}",
            )

            return all(
                [
                    success,
                    found_service is not None,
                    retrieved_service is not None,
                    stats["total_services"] > 0,
                ]
            )

        except Exception as e:
            self.log_test_result(
                "service_discovery_error", False, f"Exception: {str(e)}"
            )
            return False

    async def test_configuration_management(self) -> bool:
        """Test configuration management functionality"""
        self.logger.info("Testing Configuration Management...")

        try:
            # Test 1: Get config manager instance
            config_manager = get_config_manager()
            self.log_test_result(
                "config_manager_instance", True, "Got config manager instance"
            )

            # Test 2: Read configuration values
            logging_config = config_manager.get_logging_config()
            self.log_test_result(
                "config_read",
                isinstance(logging_config, dict),
                f"Logging config: {logging_config}",
            )

            # Test 3: Set configuration value
            config_manager.set("test.value", "test_data")
            retrieved_value = config_manager.get("test.value")
            self.log_test_result(
                "config_set_get",
                retrieved_value == "test_data",
                "Set and retrieved test configuration",
            )

            # Test 4: Get service configuration
            service_config = config_manager.get_service_config("observatory")
            self.log_test_result(
                "service_config",
                isinstance(service_config, dict),
                f"Observatory config: {service_config}",
            )

            # Test 5: Get all configuration
            all_config = config_manager.get_all()
            self.log_test_result(
                "config_all",
                isinstance(all_config, dict) and len(all_config) > 0,
                f"All config keys: {list(all_config.keys())}",
            )

            return True

        except Exception as e:
            self.log_test_result(
                "config_management_error", False, f"Exception: {str(e)}"
            )
            return False

    async def test_structured_logging(self) -> bool:
        """Test structured logging functionality"""
        self.logger.info("Testing Structured Logging...")

        try:
            # Test 1: Create logger with structured format
            test_logger = setup_service_logging("test-service", LogLevel.INFO)
            self.log_test_result("structured_logger", True, "Created structured logger")

            # Test 2: Log with context
            context = LogContext(
                correlation_id="test-123",
                trace_id="trace-456",
                service_name="test-service",
                operation="test_operation",
            )

            with with_context(context):
                test_logger.info(
                    "Test log message with context",
                    extra={"test_field": "test_value", "numeric_field": 42},
                )

            self.log_test_result(
                "contextual_logging", True, "Logged message with context"
            )

            # Test 3: Error logging with exception
            try:
                raise ValueError("Test exception for logging")
            except Exception as e:
                test_logger.error("Test error logging", exc_info=True)

            self.log_test_result(
                "error_logging", True, "Logged error with exception info"
            )

            return True

        except Exception as e:
            self.log_test_result(
                "structured_logging_error", False, f"Exception: {str(e)}"
            )
            return False

    async def test_health_checks(self) -> bool:
        """Test health check functionality"""
        self.logger.info("Testing Health Checks...")

        try:
            # Test 1: Get health registry
            health_registry = get_health_registry()
            self.log_test_result(
                "health_registry", True, "Got health registry instance"
            )

            # Test 2: Register custom health check
            def custom_health_check() -> HealthCheckResult:
                return HealthCheckResult(
                    name="custom_test",
                    status="healthy",
                    message="Custom health check passed",
                    details={"test": True},
                )

            health_registry.register("custom_test", custom_health_check)
            self.log_test_result(
                "health_check_registration", True, "Registered custom health check"
            )

            # Test 3: Run specific health check
            result = await health_registry.run_check("custom_test")
            self.log_test_result(
                "health_check_execution",
                result.status == "healthy",
                f"Health check result: {result.status}",
            )

            # Test 4: Run all health checks
            all_results = await health_registry.run_all_checks()
            self.log_test_result(
                "all_health_checks",
                len(all_results) > 0,
                f"Ran {len(all_results)} health checks",
            )

            return True

        except Exception as e:
            self.log_test_result("health_checks_error", False, f"Exception: {str(e)}")
            return False

    async def test_integration(self) -> bool:
        """Test integration between components"""
        self.logger.info("Testing Component Integration...")

        try:
            # Test 1: Service discovery with configuration
            config_manager = get_config_manager()
            discovery = get_service_discovery()

            # Get service config and create service from it
            observatory_config = config_manager.get_service_config("observatory")
            if observatory_config.get("enabled", False):
                service = Service(
                    id="integration-test-observatory",
                    name="observatory",
                    type=ServiceType.MONITORING,
                    version="1.0.0",
                    endpoint=ServiceEndpoint(port=observatory_config.get("port", 8080)),
                    capabilities=observatory_config.get("capabilities", []),
                )

                register_success = register_service(service)
                self.log_test_result(
                    "config_service_integration",
                    register_success,
                    "Created service from configuration",
                )

            # Test 2: Logging with service discovery context
            services = discovery.discover_services()
            self.logger.info(
                f"Integration test: Found {len(services)} total services",
                extra={
                    "service_count": len(services),
                    "service_types": [s.type.value for s in services],
                },
            )

            self.log_test_result(
                "logging_discovery_integration",
                True,
                "Integrated logging with service discovery data",
            )

            return True

        except Exception as e:
            self.log_test_result("integration_error", False, f"Exception: {str(e)}")
            return False

    def print_summary(self):
        """Print test summary"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() if result)
        failed_tests = total_tests - passed_tests

        print("\n" + "=" * 60)
        print("IMPLEMENTATION TEST SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests / total_tests) * 100:.1f}%")
        print("=" * 60)

        if failed_tests > 0:
            print("\nFAILED TESTS:")
            for test_name, result in self.test_results.items():
                if not result:
                    print(f"  ❌ {test_name}")

        print("\nPASSED TESTS:")
        for test_name, result in self.test_results.items():
            if result:
                print(f"  ✅ {test_name}")

        print("\n" + "=" * 60)

        # Log structured summary
        self.logger.info(
            "Test execution completed",
            extra={
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "success_rate": (passed_tests / total_tests) * 100,
                "test_results": self.test_results,
            },
        )

        return failed_tests == 0

    async def run_all_tests(self) -> bool:
        """Run all implementation tests"""
        self.logger.info("Starting implementation tests...")

        tests = [
            ("Service Discovery", self.test_service_discovery()),
            ("Configuration Management", self.test_configuration_management()),
            ("Structured Logging", self.test_structured_logging()),
            ("Health Checks", self.test_health_checks()),
            ("Integration", self.test_integration()),
        ]

        results = []
        for test_name, test_coro in tests:
            self.logger.info(f"Running {test_name} tests...")
            try:
                result = await test_coro
                results.append(result)
            except Exception as e:
                self.logger.error(f"{test_name} test suite failed: {e}", exc_info=True)
                results.append(False)

        return all(results)


async def main():
    """Main test execution"""
    print("🚀 Starting Architecture Implementation Tests")
    print("=" * 60)

    tester = ImplementationTester()

    try:
        # Run all tests
        await tester.run_all_tests()

        # Print summary
        success = tester.print_summary()

        if success:
            print("🎉 All tests passed! Implementation is ready for use.")
            return 0
        else:
            print("❌ Some tests failed. Please review the implementation.")
            return 1

    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        tester.logger.error(f"Test execution failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
