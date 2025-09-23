"""
Service Discovery and Registry Enhancement
Provides automatic service registration, health checking, and discovery
"""

import json
import os
import logging
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum


class ServiceType(Enum):
    MCP_SERVER = "mcp_server"
    AGENT = "agent"
    GATEWAY = "gateway"
    MONITORING = "monitoring"
    STORAGE = "storage"


class ServiceStatus(Enum):
    UNKNOWN = "unknown"
    INITIALIZING = "initializing"
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DEGRADED = "degraded"
    OFFLINE = "offline"


@dataclass
class ServiceEndpoint:
    """Represents a service endpoint"""

    protocol: str = "http"
    host: str = "localhost"
    port: Optional[int] = None
    path: str = "/"

    def get_url(self) -> str:
        if self.port:
            return f"{self.protocol}://{self.host}:{self.port}{self.path}"
        return f"{self.protocol}://{self.host}{self.path}"


@dataclass
class HealthCheck:
    """Health check configuration"""

    enabled: bool = True
    endpoint: str = "/health"
    interval: int = 30  # seconds
    timeout: int = 5  # seconds
    retries: int = 3
    last_check: Optional[datetime] = None
    last_status: ServiceStatus = ServiceStatus.UNKNOWN
    consecutive_failures: int = 0


@dataclass
class Service:
    """Represents a discoverable service"""

    id: str
    name: str
    type: ServiceType
    version: str = "1.0.0"
    endpoint: ServiceEndpoint = field(default_factory=ServiceEndpoint)
    health_check: HealthCheck = field(default_factory=HealthCheck)
    capabilities: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    status: ServiceStatus = ServiceStatus.UNKNOWN
    registered_at: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        """Convert service to dictionary"""
        data = asdict(self)
        data["type"] = self.type.value
        data["status"] = self.status.value
        data["registered_at"] = self.registered_at.isoformat()
        data["last_seen"] = self.last_seen.isoformat()
        if self.health_check.last_check:
            data["health_check"][
                "last_check"
            ] = self.health_check.last_check.isoformat()
        data["health_check"]["last_status"] = self.health_check.last_status.value
        return data

    @classmethod
    def from_dict(cls, data: Dict) -> "Service":
        """Create service from dictionary"""
        data = data.copy()
        data["type"] = ServiceType(data["type"])
        data["status"] = ServiceStatus(data.get("status", "unknown"))
        data["endpoint"] = ServiceEndpoint(**data.get("endpoint", {}))

        health_data = data.get("health_check", {})
        if "last_check" in health_data and health_data["last_check"]:
            health_data["last_check"] = datetime.fromisoformat(
                health_data["last_check"]
            )
        if "last_status" in health_data:
            health_data["last_status"] = ServiceStatus(health_data["last_status"])
        data["health_check"] = HealthCheck(**health_data)

        data["registered_at"] = datetime.fromisoformat(
            data.get("registered_at", datetime.now().isoformat())
        )
        data["last_seen"] = datetime.fromisoformat(
            data.get("last_seen", datetime.now().isoformat())
        )

        return cls(**data)


class ServiceDiscovery:
    """Service discovery and registry system"""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize service discovery"""
        self.services: Dict[str, Service] = {}
        self.logger = self._setup_logging()
        self.config_path = config_path or self._get_default_config_path()
        self.health_check_tasks: Dict[str, asyncio.Task] = {}
        self.callbacks: Dict[str, List[Callable]] = {
            "service_registered": [],
            "service_updated": [],
            "service_removed": [],
            "health_changed": [],
        }
        self.running = False
        self._load_services()

    def _setup_logging(self) -> logging.Logger:
        """Setup structured logging"""
        logger = logging.getLogger("ServiceDiscovery")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "component": "ServiceDiscovery", '
                '"level": "%(levelname)s", "message": "%(message)s"}'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _get_default_config_path(self) -> str:
        """Get default configuration path"""
        return os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "configs",
            "service_registry.json",
        )

    def _load_services(self):
        """Load services from configuration file"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    data = json.load(f)
                    for service_data in data.get("services", []):
                        service = Service.from_dict(service_data)
                        self.services[service.id] = service
                self.logger.info(
                    f"Loaded {len(self.services)} services from {self.config_path}"
                )
            except Exception as e:
                self.logger.error(f"Failed to load services: {e}")

    def _save_services(self):
        """Save services to configuration file"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            data = {
                "services": [service.to_dict() for service in self.services.values()],
                "last_updated": datetime.now().isoformat(),
            }
            with open(self.config_path, "w") as f:
                json.dump(data, f, indent=2)
            self.logger.debug(
                f"Saved {len(self.services)} services to {self.config_path}"
            )
        except Exception as e:
            self.logger.error(f"Failed to save services: {e}")

    def register_service(self, service: Service) -> bool:
        """Register a new service"""
        try:
            # Check if service already exists
            if service.id in self.services:
                self.logger.info(f"Updating existing service: {service.id}")
                self._trigger_callbacks("service_updated", service)
            else:
                self.logger.info(f"Registering new service: {service.id}")
                self._trigger_callbacks("service_registered", service)

            # Update service
            service.last_seen = datetime.now()
            service.status = ServiceStatus.INITIALIZING
            self.services[service.id] = service

            # Save to disk
            self._save_services()

            # Start health checking if enabled
            if service.health_check.enabled and self.running:
                asyncio.create_task(self._start_health_check(service.id))

            return True

        except Exception as e:
            self.logger.error(f"Failed to register service {service.id}: {e}")
            return False

    def unregister_service(self, service_id: str) -> bool:
        """Unregister a service"""
        try:
            if service_id in self.services:
                service = self.services[service_id]

                # Stop health checking
                if service_id in self.health_check_tasks:
                    self.health_check_tasks[service_id].cancel()
                    del self.health_check_tasks[service_id]

                # Remove service
                del self.services[service_id]
                self._save_services()

                self.logger.info(f"Unregistered service: {service_id}")
                self._trigger_callbacks("service_removed", service)
                return True

            return False

        except Exception as e:
            self.logger.error(f"Failed to unregister service {service_id}: {e}")
            return False

    def discover_services(
        self,
        service_type: Optional[ServiceType] = None,
        status: Optional[ServiceStatus] = None,
        capabilities: Optional[List[str]] = None,
    ) -> List[Service]:
        """Discover services based on criteria"""
        results = []

        for service in self.services.values():
            # Filter by type
            if service_type and service.type != service_type:
                continue

            # Filter by status
            if status and service.status != status:
                continue

            # Filter by capabilities
            if capabilities:
                if not all(cap in service.capabilities for cap in capabilities):
                    continue

            results.append(service)

        return results

    def get_service(self, service_id: str) -> Optional[Service]:
        """Get a specific service by ID"""
        return self.services.get(service_id)

    async def check_health(self, service_id: str) -> ServiceStatus:
        """Check health of a specific service"""
        service = self.services.get(service_id)
        if not service:
            return ServiceStatus.UNKNOWN

        if not service.health_check.enabled:
            return ServiceStatus.UNKNOWN

        try:
            url = service.endpoint.get_url() + service.health_check.endpoint

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=service.health_check.timeout),
                ) as response:
                    if response.status == 200:
                        # Parse health response if JSON
                        try:
                            data = await response.json()
                            status = ServiceStatus.HEALTHY

                            # Check for degraded status indicators
                            if data.get("status") == "degraded":
                                status = ServiceStatus.DEGRADED
                            elif data.get("healthy") is False:
                                status = ServiceStatus.UNHEALTHY

                        except Exception:
                            # Non-JSON response, assume healthy if 200
                            status = ServiceStatus.HEALTHY
                    else:
                        status = ServiceStatus.UNHEALTHY

                    # Update service health
                    service.health_check.last_check = datetime.now()
                    service.health_check.last_status = status
                    service.health_check.consecutive_failures = 0
                    service.status = status
                    service.last_seen = datetime.now()

                    self._save_services()

                    if status != service.health_check.last_status:
                        self._trigger_callbacks("health_changed", service)

                    return status

        except asyncio.TimeoutError:
            self.logger.warning(f"Health check timeout for {service_id}")
            return await self._handle_health_failure(service)
        except Exception as e:
            self.logger.error(f"Health check failed for {service_id}: {e}")
            return await self._handle_health_failure(service)

    async def _handle_health_failure(self, service: Service) -> ServiceStatus:
        """Handle health check failure"""
        service.health_check.consecutive_failures += 1

        if service.health_check.consecutive_failures >= service.health_check.retries:
            service.status = ServiceStatus.OFFLINE
        else:
            service.status = ServiceStatus.UNHEALTHY

        service.health_check.last_check = datetime.now()
        service.health_check.last_status = service.status

        self._save_services()
        self._trigger_callbacks("health_changed", service)

        return service.status

    async def _start_health_check(self, service_id: str):
        """Start health checking for a service"""
        service = self.services.get(service_id)
        if not service or not service.health_check.enabled:
            return

        self.logger.info(f"Starting health checks for {service_id}")

        while self.running and service_id in self.services:
            try:
                await self.check_health(service_id)
                await asyncio.sleep(service.health_check.interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Health check error for {service_id}: {e}")
                await asyncio.sleep(service.health_check.interval)

    async def start(self):
        """Start service discovery system"""
        self.running = True
        self.logger.info("Service discovery started")

        # Start health checks for all registered services
        for service_id, service in self.services.items():
            if service.health_check.enabled:
                task = asyncio.create_task(self._start_health_check(service_id))
                self.health_check_tasks[service_id] = task

    async def stop(self):
        """Stop service discovery system"""
        self.running = False

        # Cancel all health check tasks
        for task in self.health_check_tasks.values():
            task.cancel()

        # Wait for tasks to complete
        if self.health_check_tasks:
            await asyncio.gather(
                *self.health_check_tasks.values(), return_exceptions=True
            )

        self.health_check_tasks.clear()
        self.logger.info("Service discovery stopped")

    def add_callback(self, event: str, callback: Callable):
        """Add event callback"""
        if event in self.callbacks:
            self.callbacks[event].append(callback)

    def _trigger_callbacks(self, event: str, service: Service):
        """Trigger event callbacks"""
        for callback in self.callbacks.get(event, []):
            try:
                callback(service)
            except Exception as e:
                self.logger.error(f"Callback error for {event}: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get service discovery statistics"""
        total = len(self.services)
        by_type = {}
        by_status = {}

        for service in self.services.values():
            # Count by type
            type_key = service.type.value
            by_type[type_key] = by_type.get(type_key, 0) + 1

            # Count by status
            status_key = service.status.value
            by_status[status_key] = by_status.get(status_key, 0) + 1

        return {
            "total_services": total,
            "by_type": by_type,
            "by_status": by_status,
            "healthy_services": by_status.get("healthy", 0),
            "unhealthy_services": by_status.get("unhealthy", 0)
            + by_status.get("offline", 0),
        }


# Singleton instance
_discovery_instance: Optional[ServiceDiscovery] = None


def get_service_discovery() -> ServiceDiscovery:
    """Get singleton service discovery instance"""
    global _discovery_instance
    if _discovery_instance is None:
        _discovery_instance = ServiceDiscovery()
    return _discovery_instance


# Convenience functions
def register_service(service: Service) -> bool:
    """Register a service with the discovery system"""
    return get_service_discovery().register_service(service)


def discover_services(**kwargs) -> List[Service]:
    """Discover services based on criteria"""
    return get_service_discovery().discover_services(**kwargs)


def get_service(service_id: str) -> Optional[Service]:
    """Get a specific service"""
    return get_service_discovery().get_service(service_id)
