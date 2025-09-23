"""
Enhanced Observatory Adapter for New Architecture
Integrates the existing observatory system with the new service discovery and configuration management
"""

from utilities.logging_utils import setup_agent_logging, LogLevel
from libraries.config_manager import get_config_manager
from libraries.service_discovery import (
    Service,
    ServiceType,
    ServiceStatus,
    ServiceEndpoint,
    HealthCheck,
    register_service,
    get_service_discovery,
)
import asyncio
import json
import sys
from pathlib import Path
from typing import Dict, Any, Optional
import aiohttp
from datetime import datetime

# Add shared libraries to path
sys.path.append(str(Path(__file__).parent.parent.parent / "shared"))


class EnhancedObservatoryAdapter:
    """Adapter to integrate observatory with new architecture"""

    def __init__(self):
        self.logger = setup_agent_logging("observatory-adapter", LogLevel.INFO)
        self.config_manager = get_config_manager()
        self.service_discovery = get_service_discovery()

        # Observatory configuration
        self.observatory_config = self.config_manager.get_service_config("observatory")
        self.observatory_url = (
            f"http://localhost:{self.observatory_config.get('port', 8080)}"
        )

        # API Gateway configuration
        self.gateway_url = "http://localhost:9000"

        self.running = False
        self.http_session: Optional[aiohttp.ClientSession] = None

    async def start(self):
        """Start the enhanced observatory adapter"""
        self.logger.info("Starting Enhanced Observatory Adapter")

        # Initialize HTTP session
        self.http_session = aiohttp.ClientSession()

        # Register observatory service with service discovery
        await self._register_observatory_service()

        # Start monitoring tasks
        self.running = True
        tasks = [
            asyncio.create_task(self._monitor_service_registry()),
            asyncio.create_task(self._sync_with_gateway()),
            asyncio.create_task(self._collect_enhanced_metrics()),
        ]

        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"Observatory adapter error: {e}", exc_info=True)
        finally:
            await self.shutdown()

    async def _register_observatory_service(self):
        """Register observatory with the new service discovery"""
        try:
            observatory_service = Service(
                id="observatory-enhanced",
                name="observatory",
                type=ServiceType.MONITORING,
                version="2.0.0",
                endpoint=ServiceEndpoint(
                    protocol="http",
                    host="localhost",
                    port=self.observatory_config.get("port", 8080),
                    path="/",
                ),
                health_check=HealthCheck(enabled=True, endpoint="/health", interval=15),
                capabilities=[
                    "monitoring",
                    "metrics",
                    "logging",
                    "alerting",
                    "real_time_dashboard",
                    "agent_tracking",
                ],
                metadata={
                    "type": "enhanced_observatory",
                    "database_type": "sqlite",
                    "real_time": True,
                    "dashboard_url": f"{self.observatory_url}/dashboard",
                },
            )

            success = register_service(observatory_service)

            if success:
                self.logger.info(
                    "Observatory registered with enhanced service discovery"
                )
            else:
                self.logger.error(
                    "Failed to register observatory with service discovery"
                )

        except Exception as e:
            self.logger.error(f"Observatory registration failed: {e}")

    async def _monitor_service_registry(self):
        """Monitor service registry and sync with observatory database"""
        while self.running:
            try:
                # Get all registered services
                services = self.service_discovery.discover_services()

                # Update observatory database with service information
                for service in services:
                    await self._update_observatory_with_service(service)

                await asyncio.sleep(30)  # Check every 30 seconds

            except Exception as e:
                self.logger.error(f"Service registry monitoring error: {e}")
                await asyncio.sleep(30)

    async def _update_observatory_with_service(self, service: Service):
        """Update observatory database with service information"""
        try:
            if not self.http_session:
                return

            # Prepare service data for observatory
            service_data = {
                "name": service.name,
                "type": "agent",  # Observatory expects this format
                "status": (
                    "active" if service.status == ServiceStatus.HEALTHY else "inactive"
                ),
                "metadata": json.dumps(
                    {
                        "service_id": service.id,
                        "service_type": service.type.value,
                        "capabilities": service.capabilities,
                        "endpoint": (
                            service.endpoint.get_url()
                            if service.endpoint.port
                            else None
                        ),
                        "health_status": service.status.value,
                        "last_seen": (
                            service.last_seen.isoformat() if service.last_seen else None
                        ),
                        **service.metadata,
                    }
                ),
            }

            # Register or update in observatory
            async with self.http_session.post(
                f"{self.observatory_url}/api/agents/register",
                json=service_data,
                timeout=aiohttp.ClientTimeout(total=5),
            ) as response:
                if response.status == 200:
                    self.logger.debug(
                        f"Updated observatory with service: {service.name}"
                    )
                else:
                    self.logger.warning(
                        f"Failed to update observatory with service {service.name}: {response.status}"
                    )

        except Exception as e:
            self.logger.error(f"Observatory service update error: {e}")

    async def _sync_with_gateway(self):
        """Sync observatory data with API gateway"""
        while self.running:
            try:
                if not self.http_session:
                    await asyncio.sleep(60)
                    continue

                # Get gateway statistics
                async with self.http_session.get(
                    f"{self.gateway_url}/stats", timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        gateway_stats = await response.json()

                        # Create gateway metrics event for observatory
                        await self._send_gateway_metrics(gateway_stats)

                await asyncio.sleep(60)  # Sync every minute

            except Exception as e:
                self.logger.error(f"Gateway sync error: {e}")
                await asyncio.sleep(60)

    async def _send_gateway_metrics(self, stats: Dict[str, Any]):
        """Send gateway metrics to observatory"""
        try:
            if not self.http_session:
                return

            # Create metrics event
            metrics_event = {
                "agent_name": "api-gateway",
                "event_type": "gateway_metrics",
                "severity": "info",
                "message": f"Gateway processed {stats.get('requests_total', 0)} total requests",
                "data": json.dumps(stats),
                "timestamp": datetime.now().isoformat(),
            }

            async with self.http_session.post(
                f"{self.observatory_url}/api/events",
                json=metrics_event,
                timeout=aiohttp.ClientTimeout(total=5),
            ) as response:
                if response.status == 200:
                    self.logger.debug("Sent gateway metrics to observatory")

        except Exception as e:
            self.logger.error(f"Gateway metrics sending error: {e}")

    async def _collect_enhanced_metrics(self):
        """Collect enhanced metrics from all services"""
        while self.running:
            try:
                services = self.service_discovery.discover_services()

                for service in services:
                    await self._collect_service_metrics(service)

                await asyncio.sleep(30)  # Collect every 30 seconds

            except Exception as e:
                self.logger.error(f"Enhanced metrics collection error: {e}")
                await asyncio.sleep(30)

    async def _collect_service_metrics(self, service: Service):
        """Collect metrics from a specific service"""
        try:
            if not service.endpoint.port or not self.http_session:
                return

            # Try to get service metrics
            metrics_url = f"{service.endpoint.get_url()}/metrics"

            async with self.http_session.get(
                metrics_url, timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    metrics_data = await response.json()

                    # Send metrics to observatory
                    await self._send_service_metrics(service, metrics_data)

        except Exception as e:
            # Service might not have metrics endpoint, which is fine
            self.logger.debug(f"Could not collect metrics from {service.name}: {e}")

    async def _send_service_metrics(self, service: Service, metrics: Dict[str, Any]):
        """Send service metrics to observatory"""
        try:
            if not self.http_session:
                return

            # Convert metrics to observatory format
            timestamp = datetime.now()

            for metric_name, metric_value in metrics.get("metrics", {}).items():
                if isinstance(metric_value, (int, float)):
                    metric_data = {
                        "agent_name": service.name,
                        "metric_name": metric_name,
                        "value": metric_value,
                        "unit": "count",  # Default unit
                        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    }

                    async with self.http_session.post(
                        f"{self.observatory_url}/api/metrics",
                        json=metric_data,
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as response:
                        if response.status != 200:
                            self.logger.debug(
                                f"Failed to send metric {metric_name} for {service.name}"
                            )

        except Exception as e:
            self.logger.error(f"Service metrics sending error: {e}")

    async def get_enhanced_status(self) -> Dict[str, Any]:
        """Get enhanced status combining all systems"""
        try:
            # Get service discovery statistics
            discovery_stats = self.service_discovery.get_statistics()

            # Get gateway statistics
            gateway_stats = {}
            if self.http_session:
                try:
                    async with self.http_session.get(
                        f"{self.gateway_url}/stats",
                        timeout=aiohttp.ClientTimeout(total=2),
                    ) as response:
                        if response.status == 200:
                            gateway_stats = await response.json()
                except Exception:
                    pass

            # Get observatory statistics
            observatory_stats = {}
            if self.http_session:
                try:
                    async with self.http_session.get(
                        f"{self.observatory_url}/health",
                        timeout=aiohttp.ClientTimeout(total=2),
                    ) as response:
                        if response.status == 200:
                            observatory_stats = await response.json()
                except Exception:
                    pass

            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "components": {
                    "service_discovery": discovery_stats,
                    "api_gateway": gateway_stats,
                    "observatory": observatory_stats,
                },
                "architecture_version": "2.0.0",
                "features": [
                    "enhanced_service_discovery",
                    "centralized_configuration",
                    "structured_logging",
                    "unified_api_gateway",
                    "real_time_monitoring",
                ],
            }

        except Exception as e:
            self.logger.error(f"Enhanced status error: {e}")
            return {
                "status": "degraded",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    async def shutdown(self):
        """Shutdown the adapter"""
        self.logger.info("Shutting down Enhanced Observatory Adapter")

        self.running = False

        if self.http_session:
            await self.http_session.close()


# Main entry point
async def main():
    """Main entry point for the enhanced observatory adapter"""
    adapter = EnhancedObservatoryAdapter()

    try:
        await adapter.start()
    except KeyboardInterrupt:
        print("Received keyboard interrupt")
    except Exception as e:
        adapter.logger.error(f"Adapter failed: {e}", exc_info=True)
    finally:
        await adapter.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
