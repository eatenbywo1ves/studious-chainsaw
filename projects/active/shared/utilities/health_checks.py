"""
Health Check Utilities
Provides standardized health check endpoints and monitoring
"""

from utilities.logging_utils import setup_service_logging, LogLevel
import asyncio
import time
import psutil
from datetime import datetime
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, asdict
from aiohttp import web
import sys
from pathlib import Path

# Add shared libraries to path
sys.path.append(str(Path(__file__).parent.parent))


@dataclass
class HealthCheckResult:
    """Result of a health check"""

    name: str
    status: str  # "healthy", "unhealthy", "degraded"
    message: str = ""
    details: Dict[str, Any] = None
    duration_ms: float = 0.0
    timestamp: datetime = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}
        if self.timestamp is None:
            self.timestamp = datetime.now()


@dataclass
class SystemMetrics:
    """System performance metrics"""

    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_total_mb: float = 0.0
    memory_available_mb: float = 0.0
    disk_usage_percent: float = 0.0
    process_count: int = 0
    uptime_seconds: float = 0.0
    load_average: List[float] = None

    def __post_init__(self):
        if self.load_average is None:
            self.load_average = [0.0, 0.0, 0.0]


class HealthCheckRegistry:
    """Registry for health check functions"""

    def __init__(self):
        self.checks: Dict[str, Callable[[], HealthCheckResult]] = {}
        self.logger = setup_service_logging("health_checks", LogLevel.INFO)

    def register(self, name: str, check_func: Callable[[], HealthCheckResult]):
        """Register a health check function"""
        self.checks[name] = check_func
        self.logger.info(f"Registered health check: {name}")

    def unregister(self, name: str):
        """Unregister a health check"""
        if name in self.checks:
            del self.checks[name]
            self.logger.info(f"Unregistered health check: {name}")

    async def run_check(self, name: str) -> HealthCheckResult:
        """Run a specific health check"""
        if name not in self.checks:
            return HealthCheckResult(
                name=name,
                status="unhealthy",
                message=f"Health check '{name}' not found",
            )

        start_time = time.time()

        try:
            if asyncio.iscoroutinefunction(self.checks[name]):
                result = await self.checks[name]()
            else:
                result = self.checks[name]()

            result.duration_ms = (time.time() - start_time) * 1000
            return result

        except Exception as e:
            return HealthCheckResult(
                name=name,
                status="unhealthy",
                message=f"Health check failed: {str(e)}",
                duration_ms=(time.time() - start_time) * 1000,
            )

    async def run_all_checks(self) -> List[HealthCheckResult]:
        """Run all registered health checks"""
        results = []

        for name in self.checks.keys():
            result = await self.run_check(name)
            results.append(result)

        return results


class HealthCheckServer:
    """HTTP server for health check endpoints"""

    def __init__(
        self, port: int = 8090, registry: Optional[HealthCheckRegistry] = None
    ):
        self.port = port
        self.registry = registry or HealthCheckRegistry()
        self.logger = setup_service_logging("health_server", LogLevel.INFO)
        self.start_time = datetime.now()

        # Register default health checks
        self._register_default_checks()

    def _register_default_checks(self):
        """Register default system health checks"""
        self.registry.register("system", self._system_health_check)
        self.registry.register("memory", self._memory_health_check)
        self.registry.register("disk", self._disk_health_check)

    def _system_health_check(self) -> HealthCheckResult:
        """Basic system health check"""
        try:
            metrics = self._get_system_metrics()

            status = "healthy"
            message = "System is healthy"

            # Check for concerning metrics
            if metrics.cpu_percent > 90:
                status = "degraded"
                message = f"High CPU usage: {metrics.cpu_percent:.1f}%"
            elif metrics.memory_percent > 90:
                status = "degraded"
                message = f"High memory usage: {metrics.memory_percent:.1f}%"
            elif metrics.disk_usage_percent > 90:
                status = "degraded"
                message = f"High disk usage: {metrics.disk_usage_percent:.1f}%"

            return HealthCheckResult(
                name="system", status=status, message=message, details=asdict(metrics)
            )

        except Exception as e:
            return HealthCheckResult(
                name="system",
                status="unhealthy",
                message=f"System check failed: {str(e)}",
            )

    def _memory_health_check(self) -> HealthCheckResult:
        """Memory-specific health check"""
        try:
            memory = psutil.virtual_memory()

            status = "healthy"
            message = f"Memory usage: {memory.percent:.1f}%"

            if memory.percent > 95:
                status = "unhealthy"
                message = f"Critical memory usage: {memory.percent:.1f}%"
            elif memory.percent > 85:
                status = "degraded"
                message = f"High memory usage: {memory.percent:.1f}%"

            return HealthCheckResult(
                name="memory",
                status=status,
                message=message,
                details={
                    "percent": memory.percent,
                    "total_mb": memory.total / (1024 * 1024),
                    "available_mb": memory.available / (1024 * 1024),
                    "used_mb": memory.used / (1024 * 1024),
                },
            )

        except Exception as e:
            return HealthCheckResult(
                name="memory",
                status="unhealthy",
                message=f"Memory check failed: {str(e)}",
            )

    def _disk_health_check(self) -> HealthCheckResult:
        """Disk space health check"""
        try:
            disk = psutil.disk_usage("/")
            percent_used = (disk.used / disk.total) * 100

            status = "healthy"
            message = f"Disk usage: {percent_used:.1f}%"

            if percent_used > 95:
                status = "unhealthy"
                message = f"Critical disk usage: {percent_used:.1f}%"
            elif percent_used > 85:
                status = "degraded"
                message = f"High disk usage: {percent_used:.1f}%"

            return HealthCheckResult(
                name="disk",
                status=status,
                message=message,
                details={
                    "percent_used": percent_used,
                    "total_gb": disk.total / (1024 * 1024 * 1024),
                    "used_gb": disk.used / (1024 * 1024 * 1024),
                    "free_gb": disk.free / (1024 * 1024 * 1024),
                },
            )

        except Exception as e:
            return HealthCheckResult(
                name="disk", status="unhealthy", message=f"Disk check failed: {str(e)}"
            )

    def _get_system_metrics(self) -> SystemMetrics:
        """Get current system metrics"""
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        # Get load average (Unix-like systems)
        load_avg = [0.0, 0.0, 0.0]
        try:
            load_avg = list(psutil.getloadavg())
        except AttributeError:
            # Windows doesn't have load average
            pass

        return SystemMetrics(
            cpu_percent=psutil.cpu_percent(interval=0.1),
            memory_percent=memory.percent,
            memory_total_mb=memory.total / (1024 * 1024),
            memory_available_mb=memory.available / (1024 * 1024),
            disk_usage_percent=(disk.used / disk.total) * 100,
            process_count=len(psutil.pids()),
            uptime_seconds=(datetime.now() - self.start_time).total_seconds(),
            load_average=load_avg,
        )

    async def health_endpoint(self, request: web.Request) -> web.Response:
        """Main health check endpoint"""
        try:
            # Run all health checks
            results = await self.registry.run_all_checks()

            # Determine overall status
            overall_status = "healthy"
            unhealthy_count = 0
            degraded_count = 0

            for result in results:
                if result.status == "unhealthy":
                    unhealthy_count += 1
                elif result.status == "degraded":
                    degraded_count += 1

            if unhealthy_count > 0:
                overall_status = "unhealthy"
            elif degraded_count > 0:
                overall_status = "degraded"

            # Build response
            response = {
                "status": overall_status,
                "timestamp": datetime.now().isoformat(),
                "uptime_seconds": (datetime.now() - self.start_time).total_seconds(),
                "checks": [asdict(result) for result in results],
                "summary": {
                    "total": len(results),
                    "healthy": len([r for r in results if r.status == "healthy"]),
                    "degraded": degraded_count,
                    "unhealthy": unhealthy_count,
                },
            }

            # Set HTTP status code based on health
            status_code = 200
            if overall_status == "degraded":
                status_code = 200  # Still operational
            elif overall_status == "unhealthy":
                status_code = 503  # Service unavailable

            return web.json_response(response, status=status_code)

        except Exception as e:
            self.logger.error(f"Health check endpoint error: {e}", exc_info=True)
            return web.json_response(
                {
                    "status": "unhealthy",
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e),
                },
                status=503,
            )

    async def readiness_endpoint(self, request: web.Request) -> web.Response:
        """Readiness probe endpoint (for Kubernetes)"""
        try:
            # Quick readiness check - just ensure basic functionality
            basic_result = await self.registry.run_check("system")

            if basic_result.status in ["healthy", "degraded"]:
                return web.json_response(
                    {"status": "ready", "timestamp": datetime.now().isoformat()}
                )
            else:
                return web.json_response(
                    {
                        "status": "not_ready",
                        "timestamp": datetime.now().isoformat(),
                        "reason": basic_result.message,
                    },
                    status=503,
                )

        except Exception as e:
            return web.json_response(
                {
                    "status": "not_ready",
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e),
                },
                status=503,
            )

    async def liveness_endpoint(self, request: web.Request) -> web.Response:
        """Liveness probe endpoint (for Kubernetes)"""
        # Simple liveness check - just respond that we're alive
        return web.json_response(
            {
                "status": "alive",
                "timestamp": datetime.now().isoformat(),
                "uptime_seconds": (datetime.now() - self.start_time).total_seconds(),
            }
        )

    async def metrics_endpoint(self, request: web.Request) -> web.Response:
        """System metrics endpoint"""
        try:
            metrics = self._get_system_metrics()

            return web.json_response(
                {"timestamp": datetime.now().isoformat(), "metrics": asdict(metrics)}
            )

        except Exception as e:
            self.logger.error(f"Metrics endpoint error: {e}", exc_info=True)
            return web.json_response({"error": str(e)}, status=500)

    async def start(self):
        """Start the health check server"""
        app = web.Application()

        # Add routes
        app.router.add_get("/health", self.health_endpoint)
        app.router.add_get("/health/readiness", self.readiness_endpoint)
        app.router.add_get("/health/liveness", self.liveness_endpoint)
        app.router.add_get("/metrics", self.metrics_endpoint)

        # Start server
        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(runner, "localhost", self.port)
        await site.start()

        self.logger.info(f"Health check server started on port {self.port}")

        # Keep running
        try:
            await asyncio.Future()
        except KeyboardInterrupt:
            self.logger.info("Health check server stopping")


# Global registry instance
_health_registry = HealthCheckRegistry()


def get_health_registry() -> HealthCheckRegistry:
    """Get the global health registry"""
    return _health_registry


def register_health_check(name: str, check_func: Callable[[], HealthCheckResult]):
    """Register a health check (convenience function)"""
    _health_registry.register(name, check_func)


def create_health_check_routes(
    app: web.Application, registry: Optional[HealthCheckRegistry] = None
):
    """Add health check routes to an existing aiohttp application"""
    server = HealthCheckServer(registry=registry or _health_registry)

    app.router.add_get("/health", server.health_endpoint)
    app.router.add_get("/health/readiness", server.readiness_endpoint)
    app.router.add_get("/health/liveness", server.liveness_endpoint)
    app.router.add_get("/metrics", server.metrics_endpoint)


# Convenience functions for common health checks
def database_health_check(db_connection_func: Callable) -> HealthCheckResult:
    """Generic database health check"""
    try:
        start_time = time.time()

        # Test database connection
        db_connection_func()

        duration_ms = (time.time() - start_time) * 1000

        return HealthCheckResult(
            name="database",
            status="healthy",
            message="Database connection successful",
            duration_ms=duration_ms,
        )

    except Exception as e:
        return HealthCheckResult(
            name="database",
            status="unhealthy",
            message=f"Database connection failed: {str(e)}",
        )


def service_health_check(service_url: str, timeout: float = 5.0) -> HealthCheckResult:
    """Generic external service health check"""
    import aiohttp
    import asyncio

    async def _check():
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as session:
                async with session.get(f"{service_url}/health") as response:
                    if response.status == 200:
                        return HealthCheckResult(
                            name=f"service_{service_url}",
                            status="healthy",
                            message="External service is healthy",
                        )
                    else:
                        return HealthCheckResult(
                            name=f"service_{service_url}",
                            status="degraded",
                            message=f"Service returned status {response.status}",
                        )
        except Exception as e:
            return HealthCheckResult(
                name=f"service_{service_url}",
                status="unhealthy",
                message=f"Service check failed: {str(e)}",
            )

    # Run async function
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_check())


# Main entry point for standalone health server
async def main():
    """Main entry point for standalone health check server"""
    server = HealthCheckServer(port=8090)
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())
