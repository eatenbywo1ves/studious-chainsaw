"""
Demo script showing the new architecture components in action
"""

import asyncio
import sys
from pathlib import Path

# Add shared libraries to path
sys.path.append(str(Path(__file__).parent / "shared"))

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
    register_service,
    discover_services,
)


async def demo_service_discovery():
    """Demonstrate service discovery functionality"""
    print("\n=== Service Discovery Demo ===")

    # Register a sample service
    sample_service = Service(
        id="demo-service",
        name="demo-api",
        type=ServiceType.AGENT,
        version="1.0.0",
        endpoint=ServiceEndpoint(port=8888),
        capabilities=["demo", "test"],
        metadata={"demo": True},
    )

    # Register the service
    success = register_service(sample_service)
    print(f"Service registration: {'SUCCESS' if success else 'FAILED'}")

    # Discover services
    all_services = discover_services()
    agent_services = discover_services(service_type=ServiceType.AGENT)

    print(f"Total services: {len(all_services)}")
    print(f"Agent services: {len(agent_services)}")

    for service in agent_services:
        print(f"  - {service.name} ({service.type.value}) - {service.status.value}")


def demo_configuration():
    """Demonstrate configuration management"""
    print("\n=== Configuration Management Demo ===")

    config = get_config_manager()

    # Show current environment config
    logging_config = config.get_logging_config()
    monitoring_config = config.get_monitoring_config()

    print(f"Logging level: {logging_config.get('level', 'INFO')}")
    print(f"Metrics enabled: {monitoring_config.get('metrics_enabled', False)}")

    # Show service configurations
    observatory_config = config.get_service_config("observatory")
    print(f"Observatory port: {observatory_config.get('port', 'Not configured')}")

    # Demonstrate dynamic config
    config.set("demo.setting", "test_value")
    retrieved = config.get("demo.setting")
    print(f"Dynamic config test: {retrieved}")


def demo_structured_logging():
    """Demonstrate structured logging"""
    print("\n=== Structured Logging Demo ===")

    # Create a logger
    logger = setup_service_logging("demo-service", LogLevel.INFO)

    # Log some messages
    logger.info("Basic info message")
    logger.warning("Warning message with data", extra={"data": {"test": True}})

    # Log with context
    context = LogContext(
        correlation_id="demo-123",
        service_name="demo-service",
        operation="demo_operation",
    )

    with with_context(context):
        logger.info("Message with correlation context", extra={"step": "demo"})

    print("Check logs above for structured JSON output")


async def demo_health_checks():
    """Demonstrate health check system"""
    print("\n=== Health Check Demo ===")

    # Get health registry
    health_registry = get_health_registry()

    # Register a custom health check
    def custom_demo_check() -> HealthCheckResult:
        return HealthCheckResult(
            name="demo_check",
            status="healthy",
            message="Demo health check passed",
            details={"demo": True, "timestamp": "now"},
        )

    health_registry.register("demo_check", custom_demo_check)

    # Run health checks
    results = await health_registry.run_all_checks()

    print(f"Ran {len(results)} health checks:")
    for result in results:
        print(f"  - {result.name}: {result.status} ({result.message})")


async def main():
    """Main demo execution"""
    print("New Architecture Components Demo")
    print("=" * 50)

    try:
        # Demo each component
        await demo_service_discovery()
        demo_configuration()
        demo_structured_logging()
        await demo_health_checks()

        print("\n" + "=" * 50)
        print("Demo completed successfully!")
        print("\nNext steps:")
        print("1. Review MCP_AGENT_ARCHITECTURE_PLAN.md for full roadmap")
        print("2. Review IMMEDIATE_IMPROVEMENTS.md for implementation details")
        print("3. Start implementing Phase 1 components")
        print("4. Deploy API gateway for unified access")

    except Exception as e:
        print(f"Demo failed: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
