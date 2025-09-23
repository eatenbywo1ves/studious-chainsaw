"""
Service Registration Helper
Utility for services to register themselves with the service registry
"""

import aiohttp
import asyncio
import logging
from typing import Dict, List

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ServiceRegistrar:
    """Helper class for service registration"""

    def __init__(self, registry_url: str = "http://localhost:8500"):
        self.registry_url = registry_url.rstrip("/")
        self.session = None

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def register(
        self,
        service_id: str,
        name: str,
        service_type: str,
        host: str,
        port: int,
        protocol: str = "http",
        capabilities: List[str] = None,
        metadata: Dict = None,
        health_endpoint: str = "/health",
        version: str = "1.0.0",
    ) -> bool:
        """Register a service with the registry"""

        registration_data = {
            "id": service_id,
            "name": name,
            "type": service_type,
            "host": host,
            "port": port,
            "protocol": protocol,
            "capabilities": capabilities or [],
            "metadata": metadata or {},
            "health_endpoint": health_endpoint,
            "version": version,
        }

        try:
            async with self.session.post(
                f"{self.registry_url}/api/v1/register", json=registration_data
            ) as response:

                if response.status == 200:
                    await response.json()
                    logger.info(f"Successfully registered service: {service_id}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(
                        f"Failed to register service {service_id}: {error_text}"
                    )
                    return False

        except Exception as e:
            logger.error(f"Registration error for {service_id}: {e}")
            return False

    async def deregister(self, service_id: str) -> bool:
        """Deregister a service from the registry"""

        try:
            async with self.session.delete(
                f"{self.registry_url}/api/v1/deregister/{service_id}"
            ) as response:

                if response.status == 200:
                    logger.info(f"Successfully deregistered service: {service_id}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(
                        f"Failed to deregister service {service_id}: {error_text}"
                    )
                    return False

        except Exception as e:
            logger.error(f"Deregistration error for {service_id}: {e}")
            return False

    async def update_health(self, service_id: str, is_healthy: bool) -> bool:
        """Update health status of a service"""

        try:
            async with self.session.post(
                f"{self.registry_url}/api/v1/health/{service_id}",
                json={"healthy": is_healthy},
            ) as response:

                if response.status == 200:
                    logger.debug(f"Health updated for {service_id}: {is_healthy}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(
                        f"Failed to update health for {service_id}: {error_text}"
                    )
                    return False

        except Exception as e:
            logger.error(f"Health update error for {service_id}: {e}")
            return False

    async def discover_services(
        self, name: str = None, capability: str = None
    ) -> List[Dict]:
        """Discover services by name or capability"""

        params = {}
        if name:
            params["name"] = name
        if capability:
            params["capability"] = capability

        try:
            async with self.session.get(
                f"{self.registry_url}/api/v1/discover", params=params
            ) as response:

                if response.status == 200:
                    result = await response.json()
                    return result.get("services", [])
                else:
                    logger.error(
                        f"Failed to discover services: {await response.text()}"
                    )
                    return []

        except Exception as e:
            logger.error(f"Service discovery error: {e}")
            return []


class ServiceHeartbeat:
    """Manages periodic heartbeat for a registered service"""

    def __init__(
        self, service_id: str, registrar: ServiceRegistrar, interval: int = 30
    ):
        self.service_id = service_id
        self.registrar = registrar
        self.interval = interval
        self.running = False
        self.task = None

    async def start(self):
        """Start the heartbeat task"""
        self.running = True
        self.task = asyncio.create_task(self._heartbeat_loop())
        logger.info(f"Started heartbeat for service {self.service_id}")

    async def stop(self):
        """Stop the heartbeat task"""
        self.running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info(f"Stopped heartbeat for service {self.service_id}")

    async def _heartbeat_loop(self):
        """Main heartbeat loop"""
        while self.running:
            try:
                await self.registrar.update_health(self.service_id, True)
                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat error for {self.service_id}: {e}")
                await asyncio.sleep(5)  # Short retry delay


# Pre-configured registration functions for common services
async def register_api_gateway(host: str = "localhost", port: int = 9000):
    """Register the API Gateway service"""
    async with ServiceRegistrar() as registrar:
        return await registrar.register(
            service_id="api-gateway-1",
            name="API Gateway",
            service_type="api",
            host=host,
            port=port,
            capabilities=["routing", "authentication", "load-balancing"],
            metadata={"component": "gateway", "environment": "production"},
        )


async def register_observatory_agent(host: str = "localhost", port: int = 8080):
    """Register the Observatory Agent"""
    async with ServiceRegistrar() as registrar:
        return await registrar.register(
            service_id="observatory-agent-1",
            name="Observatory Agent",
            service_type="agent",
            host=host,
            port=port,
            capabilities=["monitoring", "metrics", "health-checking"],
            metadata={
                "component": "observatory",
                "environment": "production",
                "agent_type": "monitoring",
            },
        )


async def register_von_neumann_agent(host: str = "localhost", port: int = 8081):
    """Register the Von Neumann Agent"""
    async with ServiceRegistrar() as registrar:
        return await registrar.register(
            service_id="von-neumann-agent-1",
            name="Von Neumann Agent",
            service_type="agent",
            host=host,
            port=port,
            capabilities=["self-modification", "problem-solving", "reasoning"],
            metadata={
                "component": "von-neumann",
                "environment": "production",
                "agent_type": "reasoning",
            },
        )


async def register_mcp_server(
    service_id: str, name: str, host: str, port: int, capabilities: List[str]
):
    """Register an MCP server"""
    async with ServiceRegistrar() as registrar:
        return await registrar.register(
            service_id=service_id,
            name=name,
            service_type="mcp",
            host=host,
            port=port,
            capabilities=capabilities,
            metadata={"component": "mcp-server", "environment": "production"},
        )


# Example usage and testing
async def main():
    """Example usage of service registration"""

    # Test registry connection
    async with ServiceRegistrar() as registrar:

        # Register API Gateway
        success = await register_api_gateway()
        if success:
            print("[OK] API Gateway registered successfully")

        # Register Observatory Agent
        success = await register_observatory_agent()
        if success:
            print("[OK] Observatory Agent registered successfully")

        # Test service discovery
        services = await registrar.discover_services(capability="monitoring")
        print(f"Found {len(services)} monitoring services")

        for service in services:
            print(f"  - {service['name']} ({service['id']})")


if __name__ == "__main__":
    asyncio.run(main())
