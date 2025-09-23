"""
Integration Test Agent
Demonstrates the new architecture working end-to-end
"""

import asyncio
import sys
from pathlib import Path

# Add shared libraries to path
sys.path.append(str(Path(__file__).parent / "shared"))

# Import required modules
from shared.libraries.service_discovery import discover_services
from agents.templates.enhanced_agent_template.agent import BaseAgent, AgentConfig


class IntegrationTestAgent(BaseAgent):
    """Test agent to demonstrate new architecture"""

    def __init__(self):
        config = AgentConfig(
            name="integration-test-agent",
            type="testing",
            version="2.0.0",
            port=8777,
            capabilities=["integration_test", "architecture_demo", "health_check"],
            health_check_interval=15,
            metrics_interval=5,
            auto_register=True,
        )
        super().__init__(config)
        self.test_counter = 0

    async def run(self):
        """Main agent loop - demonstrates functionality"""
        self.logger.info("Integration Test Agent running with new architecture")

        while self.running and not self.shutdown_requested:
            try:
                # Simulate some work
                await self.perform_integration_test()
                await asyncio.sleep(10)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Test agent error: {e}", exc_info=True)
                await asyncio.sleep(5)

    async def perform_integration_test(self):
        """Perform integration tests"""
        self.test_counter += 1

        self.logger.info(
            f"Running integration test #{self.test_counter}",
            extra={
                "test_number": self.test_counter,
                "test_type": "integration",
                "architecture_version": "2.0.0",
            },
        )

        # Test service discovery
        services = discover_services()

        self.logger.info(
            f"Service discovery test: Found {len(services)} services",
            extra={
                "service_count": len(services),
                "services": [
                    {"name": s.name, "type": s.type.value, "status": s.status.value}
                    for s in services
                ],
            },
        )

        # Test configuration access
        observatory_config = self.config_manager.get_service_config("observatory")

        self.logger.info(
            "Configuration test: Retrieved observatory config",
            extra={
                "observatory_port": observatory_config.get("port", "not_found"),
                "observatory_enabled": observatory_config.get("enabled", False),
            },
        )

        # Test health status
        status = self.get_status()

        self.logger.info(
            "Health status test",
            extra={
                "agent_status": status["status"],
                "uptime": status["uptime"],
                "requests_processed": status["metrics"]["requests_processed"],
            },
        )

    async def handle_request(self, request_data):
        """Handle incoming requests"""
        request_type = request_data.get("type", "unknown")

        if request_type == "integration_test":
            return await self.handle_integration_test_request(request_data)
        elif request_type == "status":
            return self.get_status()
        elif request_type == "architecture_info":
            return {
                "architecture_version": "2.0.0",
                "features": [
                    "service_discovery",
                    "centralized_configuration",
                    "structured_logging",
                    "health_monitoring",
                    "api_gateway_integration",
                ],
                "agent_capabilities": self.config.capabilities,
            }
        else:
            return {"error": f"Unknown request type: {request_type}"}

    async def handle_integration_test_request(self, request_data):
        """Handle integration test requests"""
        test_name = request_data.get("test_name", "generic")

        await self.perform_integration_test()

        return {
            "test_result": "success",
            "test_name": test_name,
            "agent": self.config.name,
            "architecture": "enhanced",
            "timestamp": asyncio.get_event_loop().time(),
        }

    async def custom_health_check(self):
        """Custom health check for integration testing"""
        # Check if we can access other services
        services = discover_services()

        if len(services) == 0:
            raise Exception("No services found in discovery")

        # Check if configuration is accessible
        config_test = self.config_manager.get("services", {})
        if not config_test:
            raise Exception("Configuration not accessible")


# Main entry point
async def main():
    """Main entry point for integration test agent"""
    print("🧪 Starting Integration Test Agent")
    print("This agent demonstrates the new architecture working end-to-end")
    print("=" * 60)

    agent = IntegrationTestAgent()

    try:
        await agent.start()
    except KeyboardInterrupt:
        print("Received keyboard interrupt")
    except Exception as e:
        print(f"Agent failed: {e}")
        agent.logger.error(f"Integration test agent failed: {e}", exc_info=True)
    finally:
        await agent.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
