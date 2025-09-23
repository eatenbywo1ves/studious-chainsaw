"""
Enhanced Service Registry with Auto-Discovery
Implements service registration, health checking, and discovery patterns
"""

import json
import asyncio
import aiohttp
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import os
from pathlib import Path


class ServiceStatus(Enum):
    """Service health status enumeration"""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"
    STARTING = "starting"
    STOPPING = "stopping"


@dataclass
class ServiceInfo:
    """Service registration information"""

    id: str
    name: str
    type: str  # 'agent', 'mcp', 'api', 'infrastructure'
    host: str
    port: int
    protocol: str  # 'http', 'https', 'ws', 'wss', 'grpc'
    status: ServiceStatus
    version: str
    capabilities: List[str]
    metadata: Dict[str, Any]
    health_endpoint: str
    last_heartbeat: datetime
    registered_at: datetime

    @property
    def is_healthy(self) -> bool:
        """Check if service is healthy based on status"""
        return self.status == ServiceStatus.HEALTHY

    @is_healthy.setter
    def is_healthy(self, value: bool):
        """Set health status"""
        self.status = ServiceStatus.HEALTHY if value else ServiceStatus.UNHEALTHY

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        result = asdict(self)
        result["status"] = self.status.value
        result["last_heartbeat"] = self.last_heartbeat.isoformat()
        result["registered_at"] = self.registered_at.isoformat()
        return result

    @classmethod
    def from_dict(cls, data: Dict) -> "ServiceInfo":
        """Create from dictionary"""
        data["status"] = ServiceStatus(data["status"])
        data["last_heartbeat"] = datetime.fromisoformat(data["last_heartbeat"])
        data["registered_at"] = datetime.fromisoformat(data["registered_at"])
        return cls(**data)


class ServiceRegistry:
    """
    Enhanced Service Registry with persistence and auto-discovery
    """

    def __init__(self, db_path: str = None, health_check_interval: int = 30):
        """
        Initialize service registry

        Args:
            db_path: Path to SQLite database for persistence
            health_check_interval: Seconds between health checks
        """
        self.services: Dict[str, ServiceInfo] = {}
        self.db_path = db_path or os.path.join(Path(__file__).parent, "registry.db")
        self.health_check_interval = health_check_interval
        self.health_check_timeout = 5
        self.unhealthy_threshold = 3  # Failed checks before marking unhealthy
        self.failed_checks: Dict[str, int] = {}

        # Initialize database
        self._init_database()

        # Load existing services from database
        self._load_from_database()

        # Start health check loop
        self._health_check_task = None

    async def initialize(self):
        """Initialize async components like health checking"""
        if self._health_check_task is None:
            self._health_check_task = asyncio.create_task(self.health_check_loop())

    async def close(self):
        """Clean up async resources"""
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass

    def _init_database(self):
        """Initialize SQLite database for persistence"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS services (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                status TEXT NOT NULL,
                version TEXT,
                capabilities TEXT,
                metadata TEXT,
                health_endpoint TEXT,
                last_heartbeat TEXT,
                registered_at TEXT,
                UNIQUE(name, host, port)
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS service_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT,
                FOREIGN KEY(service_id) REFERENCES services(id)
            )
        """
        )

        conn.commit()
        conn.close()

    def _load_from_database(self):
        """Load services from database on startup"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM services")
        rows = cursor.fetchall()

        for row in rows:
            service_data = {
                "id": row[0],
                "name": row[1],
                "type": row[2],
                "host": row[3],
                "port": row[4],
                "protocol": row[5],
                "status": row[6],
                "version": row[7],
                "capabilities": json.loads(row[8]) if row[8] else [],
                "metadata": json.loads(row[9]) if row[9] else {},
                "health_endpoint": row[10],
                "last_heartbeat": row[11],
                "registered_at": row[12],
            }

            service = ServiceInfo.from_dict(service_data)
            # Mark loaded services as unknown until health checked
            service.status = ServiceStatus.UNKNOWN
            self.services[service.id] = service

        conn.close()
        print(f"Loaded {len(self.services)} services from database")

    async def register_service(self, service_info: ServiceInfo) -> bool:
        """
        Register a new service or update existing

        Args:
            service_info: ServiceInfo object to register

        Returns:
            True if successful, False otherwise
        """
        try:
            # Store service in memory
            self.services[service_info.id] = service_info

            # Persist to database
            self._persist_service(service_info)

            # Log registration event
            self._log_event(
                service_info.id, "registered", {"service": service_info.name}
            )

            print(
                f"Registered service: {service_info.name} at {service_info.host}:{service_info.port}"
            )

            return True
        except Exception as e:
            print(f"Failed to register service {service_info.name}: {e}")
            return False

    def _persist_service(self, service: ServiceInfo):
        """Persist service to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO services VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                service.id,
                service.name,
                service.type,
                service.host,
                service.port,
                service.protocol,
                service.status.value,
                service.version,
                json.dumps(service.capabilities),
                json.dumps(service.metadata),
                service.health_endpoint,
                service.last_heartbeat.isoformat(),
                service.registered_at.isoformat(),
            ),
        )

        conn.commit()
        conn.close()

    async def deregister_service(self, service_id: str) -> bool:
        """
        Deregister a service

        Args:
            service_id: Service identifier
        """
        if service_id in self.services:
            service = self.services[service_id]
            del self.services[service_id]

            # Remove from database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM services WHERE id = ?", (service_id,))
            conn.commit()
            conn.close()

            # Log event
            self._log_event(service_id, "deregistered", {"service": service.name})

            print(f"Deregistered service: {service.name}")
            return True
        return False

    def get_service(self, service_id: str) -> Optional[ServiceInfo]:
        """Get service by ID"""
        return self.services.get(service_id)

    def get_services_by_type(self, service_type: str) -> List[ServiceInfo]:
        """Get all services of a specific type"""
        return [s for s in self.services.values() if s.type == service_type]

    def get_healthy_services(self, service_type: str = None) -> List[ServiceInfo]:
        """Get all healthy services, optionally filtered by type"""
        services = self.services.values()
        if service_type:
            services = [s for s in services if s.type == service_type]
        return [s for s in services if s.status == ServiceStatus.HEALTHY]

    def discover_service(
        self, name: str = None, capability: str = None
    ) -> Optional[ServiceInfo]:
        """
        Discover a service by name or capability

        Args:
            name: Service name to find
            capability: Required capability

        Returns:
            First matching healthy service or None
        """
        candidates = self.get_healthy_services()

        if name:
            candidates = [s for s in candidates if s.name == name]

        if capability:
            candidates = [s for s in candidates if capability in s.capabilities]

        return candidates[0] if candidates else None

    async def discover_by_name(self, name: str) -> List[ServiceInfo]:
        """Discover services by name"""
        return [s for s in self.get_healthy_services() if s.name == name]

    async def discover_by_capability(self, capability: str) -> List[ServiceInfo]:
        """Discover services by capability"""
        return [s for s in self.get_healthy_services() if capability in s.capabilities]

    async def check_health(self, service: ServiceInfo) -> ServiceStatus:
        """
        Check health of a service

        Args:
            service: Service to check

        Returns:
            Service status
        """
        url = f"{service.protocol}://{service.host}:{service.port}{service.health_endpoint}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, timeout=self.health_check_timeout
                ) as response:
                    if response.status == 200:
                        # Reset failed checks counter
                        self.failed_checks[service.id] = 0
                        return ServiceStatus.HEALTHY
                    elif 500 <= response.status < 600:
                        return ServiceStatus.UNHEALTHY
                    else:
                        return ServiceStatus.DEGRADED
        except asyncio.TimeoutError:
            print(f"Health check timeout for {service.name}")
            return ServiceStatus.UNKNOWN
        except Exception as e:
            print(f"Health check failed for {service.name}: {e}")
            return ServiceStatus.UNHEALTHY

    async def health_check_loop(self):
        """Continuous health checking loop"""
        while True:
            try:
                tasks = []
                for service in list(self.services.values()):
                    tasks.append(self._check_and_update_service(service))

                if tasks:
                    await asyncio.gather(*tasks)

                await asyncio.sleep(self.health_check_interval)

            except Exception as e:
                print(f"Error in health check loop: {e}")
                await asyncio.sleep(self.health_check_interval)

    async def _check_and_update_service(self, service: ServiceInfo):
        """Check and update service health status"""
        old_status = service.status
        new_status = await self.check_health(service)

        # Update failed checks counter
        if new_status in [ServiceStatus.UNHEALTHY, ServiceStatus.UNKNOWN]:
            self.failed_checks[service.id] = self.failed_checks.get(service.id, 0) + 1

            # Mark as unhealthy if threshold exceeded
            if self.failed_checks[service.id] >= self.unhealthy_threshold:
                new_status = ServiceStatus.UNHEALTHY

        # Update service status
        if new_status != old_status:
            service.status = new_status
            service.last_heartbeat = datetime.now()
            self._persist_service(service)

            # Log status change
            self._log_event(
                service.id,
                "status_changed",
                {"old_status": old_status.value, "new_status": new_status.value},
            )

            print(
                f"Service {service.name} status changed: {old_status.value} -> {new_status.value}"
            )
        else:
            # Update heartbeat even if status unchanged
            service.last_heartbeat = datetime.now()

    def _log_event(self, service_id: str, event_type: str, details: Dict = None):
        """Log service event to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO service_events (service_id, event_type, timestamp, details)
            VALUES (?, ?, ?, ?)
        """,
            (
                service_id,
                event_type,
                datetime.now().isoformat(),
                json.dumps(details) if details else None,
            ),
        )

        conn.commit()
        conn.close()

    def get_service_events(self, service_id: str, limit: int = 100) -> List[Dict]:
        """Get recent events for a service"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT event_type, timestamp, details
            FROM service_events
            WHERE service_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """,
            (service_id, limit),
        )

        events = []
        for row in cursor.fetchall():
            events.append(
                {
                    "type": row[0],
                    "timestamp": row[1],
                    "details": json.loads(row[2]) if row[2] else {},
                }
            )

        conn.close()
        return events

    def get_registry_stats(self) -> Dict:
        """Get registry statistics"""
        total = len(self.services)
        by_status = {}
        by_type = {}

        for service in self.services.values():
            # Count by status
            status = service.status.value
            by_status[status] = by_status.get(status, 0) + 1

            # Count by type
            by_type[service.type] = by_type.get(service.type, 0) + 1

        return {
            "total_services": total,
            "by_status": by_status,
            "by_type": by_type,
            "healthy_percentage": (
                (by_status.get("healthy", 0) / total * 100) if total > 0 else 0
            ),
        }

    async def start(self):
        """Start the service registry"""
        print("Starting Service Registry...")
        self._health_check_task = asyncio.create_task(self.health_check_loop())
        print("Service Registry started with health checking enabled")

    async def stop(self):
        """Stop the service registry"""
        print("Stopping Service Registry...")
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        print("Service Registry stopped")

    async def get_statistics(self) -> Dict:
        """Get registry statistics"""
        stats = {
            "total_services": len(self.services),
            "healthy_services": len(
                [s for s in self.services.values() if s.status == ServiceStatus.HEALTHY]
            ),
            "unhealthy_services": len(
                [
                    s
                    for s in self.services.values()
                    if s.status == ServiceStatus.UNHEALTHY
                ]
            ),
            "services_by_type": {},
            "services_by_status": {},
            "uptime_info": {},
        }

        # Count by type
        for service in self.services.values():
            stats["services_by_type"][service.type] = (
                stats["services_by_type"].get(service.type, 0) + 1
            )
            stats["services_by_status"][service.status.value] = (
                stats["services_by_status"].get(service.status.value, 0) + 1
            )

        return stats


# Example usage and testing
async def main():
    """Example usage of the service registry"""

    # Create registry
    registry = ServiceRegistry(health_check_interval=10)

    # Register some example services
    registry.register_service(
        {
            "name": "api-gateway",
            "type": "api",
            "host": "localhost",
            "port": 9000,
            "protocol": "http",
            "capabilities": ["routing", "authentication", "rate-limiting"],
            "metadata": {"version": "2.0.0", "environment": "production"},
        }
    )

    registry.register_service(
        {
            "name": "observatory-agent",
            "type": "agent",
            "host": "localhost",
            "port": 8080,
            "protocol": "http",
            "capabilities": ["monitoring", "metrics", "alerting"],
            "metadata": {"agent_type": "observatory"},
        }
    )

    # Start registry with health checking
    await registry.start()

    # Discover services
    api_service = registry.discover_service(name="api-gateway")
    if api_service:
        print(f"Found API Gateway at {api_service.host}:{api_service.port}")

    monitoring_service = registry.discover_service(capability="monitoring")
    if monitoring_service:
        print(f"Found monitoring service: {monitoring_service.name}")

    # Get statistics
    stats = registry.get_registry_stats()
    print(f"Registry stats: {json.dumps(stats, indent=2)}")

    # Keep running for demo
    try:
        await asyncio.sleep(60)
    except KeyboardInterrupt:
        pass
    finally:
        await registry.stop()


if __name__ == "__main__":
    asyncio.run(main())
