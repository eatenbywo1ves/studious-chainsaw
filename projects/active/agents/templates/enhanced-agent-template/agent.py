"""
Enhanced Agent Template with Best Practices
Provides structured logging, health checks, service discovery, and monitoring
"""

from utilities.logging_utils import (
    setup_agent_logging,
    LogLevel,
    set_correlation_id,
    get_correlation_id,
)
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
import logging
import uuid
import signal
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
from datetime import datetime
import aiohttp
import sys
import os
from pathlib import Path

# Add shared libraries to path
sys.path.append(str(Path(__file__).parent.parent.parent / "shared"))


@dataclass
class AgentConfig:
    """Agent configuration"""

    name: str
    type: str = "utility"
    version: str = "1.0.0"
    port: Optional[int] = None
    capabilities: List[str] = None
    health_check_interval: int = 30
    metrics_interval: int = 5
    observatory_url: str = "http://localhost:8080"
    auto_register: bool = True
    graceful_shutdown_timeout: int = 30

    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = []


@dataclass
class AgentMetrics:
    """Agent performance metrics"""

    requests_processed: int = 0
    errors_count: int = 0
    average_response_time: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    uptime_seconds: float = 0.0
    last_updated: datetime = None

    def __post_init__(self):
        if self.last_updated is None:
            self.last_updated = datetime.now()


class BaseAgent(ABC):
    """Enhanced base class for all agents"""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.agent_id = str(uuid.uuid4())
        self.start_time = datetime.now()
        self.logger = self._setup_logging()
        self.config_manager = get_config_manager()

        # State management
        self.health_status = ServiceStatus.INITIALIZING
        self.running = False
        self.shutdown_requested = False

        # Metrics and monitoring
        self.metrics = AgentMetrics()
        self.request_times: List[float] = []

        # Service discovery
        self.service: Optional[Service] = None

        # Background tasks
        self.background_tasks: List[asyncio.Task] = []

        # HTTP session for external calls
        self.http_session: Optional[aiohttp.ClientSession] = None

        # Setup signal handlers for graceful shutdown
        self._setup_signal_handlers()

        self.logger.info(
            f"Agent {self.config.name} initialized",
            extra={"agent_id": self.agent_id, "config": asdict(self.config)},
        )

    def _setup_logging(self) -> logging.Logger:
        """Setup structured logging for the agent"""
        return setup_agent_logging(
            self.config.name, LogLevel.INFO, enable_file_logging=True
        )

    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""

        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, initiating shutdown")
            asyncio.create_task(self.shutdown())

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    async def start(self):
        """Start the agent with full initialization"""
        try:
            self.logger.info("Starting agent initialization")

            # Initialize HTTP session
            self.http_session = aiohttp.ClientSession()

            # Register with service discovery
            if self.config.auto_register:
                await self._register_service()

            # Start background tasks
            await self._start_background_tasks()

            # Update status
            self.running = True
            self.health_status = ServiceStatus.HEALTHY

            self.logger.info(
                "Agent started successfully",
                extra={"agent_id": self.agent_id, "status": self.health_status.value},
            )

            # Run main agent logic
            await self.run()

        except Exception as e:
            self.logger.error(f"Agent startup failed: {e}", exc_info=True)
            self.health_status = ServiceStatus.UNHEALTHY
            raise
        finally:
            await self.shutdown()

    async def _register_service(self):
        """Register agent with service discovery"""
        try:
            # Create service endpoint if port is configured
            endpoint = None
            if self.config.port:
                endpoint = ServiceEndpoint(
                    protocol="http", host="localhost", port=self.config.port, path="/"
                )

            # Create health check configuration
            health_check = HealthCheck(
                enabled=True,
                endpoint="/health",
                interval=self.config.health_check_interval,
            )

            # Create service instance
            self.service = Service(
                id=self.agent_id,
                name=self.config.name,
                type=ServiceType.AGENT,
                version=self.config.version,
                endpoint=endpoint,
                health_check=health_check,
                capabilities=self.config.capabilities,
                metadata={
                    "agent_type": self.config.type,
                    "start_time": self.start_time.isoformat(),
                    "pid": os.getpid(),
                },
            )

            # Register with discovery service
            success = register_service(self.service)

            if success:
                self.logger.info("Agent registered with service discovery")
            else:
                self.logger.warning("Failed to register with service discovery")

        except Exception as e:
            self.logger.error(f"Service registration failed: {e}")

    async def _start_background_tasks(self):
        """Start background monitoring and maintenance tasks"""
        tasks = [
            self._health_check_loop(),
            self._metrics_collection_loop(),
            self._observatory_reporting_loop(),
        ]

        for task_coro in tasks:
            task = asyncio.create_task(task_coro)
            self.background_tasks.append(task)

        self.logger.info(f"Started {len(self.background_tasks)} background tasks")

    async def _health_check_loop(self):
        """Periodic health check and status updates"""
        while self.running and not self.shutdown_requested:
            try:
                # Perform health check
                await self.health_check()

                # Update service status if registered
                if self.service:
                    self.service.status = self.health_status
                    self.service.last_seen = datetime.now()

                await asyncio.sleep(self.config.health_check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Health check error: {e}")
                self.health_status = ServiceStatus.DEGRADED
                await asyncio.sleep(self.config.health_check_interval)

    async def _metrics_collection_loop(self):
        """Collect and update performance metrics"""
        while self.running and not self.shutdown_requested:
            try:
                await self._update_metrics()
                await asyncio.sleep(self.config.metrics_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(self.config.metrics_interval)

    async def _observatory_reporting_loop(self):
        """Report status and metrics to observatory"""
        while self.running and not self.shutdown_requested:
            try:
                await self._report_to_observatory()
                await asyncio.sleep(30)  # Report every 30 seconds

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Observatory reporting error: {e}")
                await asyncio.sleep(30)

    async def _update_metrics(self):
        """Update performance metrics"""
        import psutil

        process = psutil.Process()

        # Update metrics
        self.metrics.uptime_seconds = (datetime.now() - self.start_time).total_seconds()
        self.metrics.memory_usage_mb = process.memory_info().rss / 1024 / 1024
        self.metrics.cpu_usage_percent = process.cpu_percent()

        # Calculate average response time
        if self.request_times:
            self.metrics.average_response_time = sum(self.request_times) / len(
                self.request_times
            )
            # Keep only recent measurements
            if len(self.request_times) > 100:
                self.request_times = self.request_times[-50:]

        self.metrics.last_updated = datetime.now()

    async def _report_to_observatory(self):
        """Report status and metrics to observatory agent"""
        if not self.http_session:
            return

        try:
            report = {
                "agent_id": self.agent_id,
                "name": self.config.name,
                "status": self.health_status.value,
                "metrics": asdict(self.metrics),
                "timestamp": datetime.now().isoformat(),
            }

            async with self.http_session.post(
                f"{self.config.observatory_url}/api/agents/report",
                json=report,
                timeout=aiohttp.ClientTimeout(total=5),
            ) as response:
                if response.status == 200:
                    self.logger.debug("Status reported to observatory")
                else:
                    self.logger.warning(
                        f"Observatory reporting failed: {response.status}"
                    )

        except asyncio.TimeoutError:
            self.logger.warning("Observatory reporting timeout")
        except Exception as e:
            self.logger.error(f"Observatory reporting error: {e}")

    @abstractmethod
    async def run(self):
        """Main agent logic - must be implemented by subclass"""

    async def health_check(self) -> ServiceStatus:
        """Perform health check - can be overridden by subclass"""
        try:
            # Basic health checks
            if not self.running:
                self.health_status = ServiceStatus.OFFLINE
                return self.health_status

            # Check if we have too many errors
            if self.metrics.errors_count > 10:
                error_rate = self.metrics.errors_count / max(
                    1, self.metrics.requests_processed
                )
                if error_rate > 0.1:  # More than 10% error rate
                    self.health_status = ServiceStatus.DEGRADED
                    return self.health_status

            # Additional custom health checks can be implemented in subclass
            await self.custom_health_check()

            self.health_status = ServiceStatus.HEALTHY
            return self.health_status

        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            self.health_status = ServiceStatus.UNHEALTHY
            return self.health_status

    async def custom_health_check(self):
        """Custom health check logic - override in subclass if needed"""

    async def process_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a request with metrics tracking"""
        correlation_id = get_correlation_id() or str(uuid.uuid4())
        set_correlation_id(correlation_id)

        start_time = asyncio.get_event_loop().time()

        try:
            self.logger.info(
                "Processing request",
                extra={
                    "correlation_id": correlation_id,
                    "request_type": request_data.get("type", "unknown"),
                },
            )

            # Call custom request handler
            result = await self.handle_request(request_data)

            # Update metrics
            self.metrics.requests_processed += 1
            processing_time = asyncio.get_event_loop().time() - start_time
            self.request_times.append(processing_time)

            self.logger.info(
                "Request processed successfully",
                extra={
                    "correlation_id": correlation_id,
                    "processing_time": processing_time,
                },
            )

            return {
                "success": True,
                "result": result,
                "correlation_id": correlation_id,
                "processing_time": processing_time,
            }

        except Exception as e:
            # Update error metrics
            self.metrics.errors_count += 1
            processing_time = asyncio.get_event_loop().time() - start_time

            self.logger.error(
                "Request processing failed",
                extra={
                    "correlation_id": correlation_id,
                    "error": str(e),
                    "processing_time": processing_time,
                },
                exc_info=True,
            )

            return {
                "success": False,
                "error": str(e),
                "correlation_id": correlation_id,
                "processing_time": processing_time,
            }

    @abstractmethod
    async def handle_request(self, request_data: Dict[str, Any]) -> Any:
        """Handle specific request logic - must be implemented by subclass"""

    async def shutdown(self):
        """Graceful shutdown"""
        if self.shutdown_requested:
            return

        self.shutdown_requested = True
        self.logger.info("Initiating graceful shutdown")

        try:
            # Stop accepting new work
            self.running = False
            self.health_status = ServiceStatus.OFFLINE

            # Cancel background tasks
            for task in self.background_tasks:
                if not task.done():
                    task.cancel()

            # Wait for tasks to complete
            if self.background_tasks:
                await asyncio.gather(*self.background_tasks, return_exceptions=True)

            # Unregister from service discovery
            if self.service and self.config.auto_register:
                discovery = get_service_discovery()
                discovery.unregister_service(self.agent_id)

            # Close HTTP session
            if self.http_session:
                await self.http_session.close()

            # Custom shutdown logic
            await self.custom_shutdown()

            self.logger.info("Agent shutdown completed")

        except Exception as e:
            self.logger.error(f"Shutdown error: {e}", exc_info=True)

    async def custom_shutdown(self):
        """Custom shutdown logic - override in subclass if needed"""

    def get_status(self) -> Dict[str, Any]:
        """Get current agent status"""
        return {
            "agent_id": self.agent_id,
            "name": self.config.name,
            "type": self.config.type,
            "version": self.config.version,
            "status": self.health_status.value,
            "uptime": (datetime.now() - self.start_time).total_seconds(),
            "metrics": asdict(self.metrics),
            "capabilities": self.config.capabilities,
            "running": self.running,
        }


# Example implementation
class ExampleAgent(BaseAgent):
    """Example agent implementation"""

    def __init__(self):
        config = AgentConfig(
            name="example-agent",
            type="utility",
            version="1.0.0",
            capabilities=["example_task", "health_check"],
            health_check_interval=30,
            metrics_interval=5,
        )
        super().__init__(config)

    async def run(self):
        """Main agent loop"""
        self.logger.info("Example agent running")

        while self.running and not self.shutdown_requested:
            try:
                # Simulate some work
                await asyncio.sleep(10)

                # Process some example work
                await self.do_example_work()

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Main loop error: {e}", exc_info=True)
                await asyncio.sleep(5)

    async def do_example_work(self):
        """Example work simulation"""
        self.logger.info("Performing example work")

        # Simulate processing time
        await asyncio.sleep(0.1)

        # Random success/failure for demonstration
        import random

        if random.random() < 0.1:  # 10% failure rate
            raise Exception("Simulated work failure")

    async def handle_request(self, request_data: Dict[str, Any]) -> Any:
        """Handle incoming requests"""
        request_type = request_data.get("type", "unknown")

        if request_type == "example_task":
            return await self.handle_example_task(request_data)
        elif request_type == "status":
            return self.get_status()
        else:
            raise ValueError(f"Unknown request type: {request_type}")

    async def handle_example_task(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle example task"""
        data = request_data.get("data", {})

        # Process the data
        result = {
            "processed": True,
            "input_data": data,
            "timestamp": datetime.now().isoformat(),
            "agent": self.config.name,
        }

        return result


# Main entry point
async def main():
    """Main entry point for running the agent"""
    agent = ExampleAgent()

    try:
        await agent.start()
    except KeyboardInterrupt:
        print("Received keyboard interrupt")
    except Exception as e:
        agent.logger.error(f"Agent failed: {e}", exc_info=True)
    finally:
        await agent.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
