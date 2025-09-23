"""
Registry API Server
Provides REST endpoints for service registration and discovery
"""

from registry.service_registry import ServiceRegistry, ServiceInfo, ServiceStatus
from aiohttp import web
import asyncio
import logging
from datetime import datetime
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class RegistryAPIServer:
    """REST API server for service registry"""

    def __init__(
        self, registry: ServiceRegistry, host: str = "0.0.0.0", port: int = 8500
    ):
        self.registry = registry
        self.host = host
        self.port = port
        self.app = web.Application()
        self.setup_routes()
        self.setup_middleware()

    def setup_routes(self):
        """Configure API routes"""
        self.app.router.add_post("/api/v1/register", self.handle_register)
        self.app.router.add_delete(
            "/api/v1/deregister/{service_id}", self.handle_deregister
        )
        self.app.router.add_get("/api/v1/services", self.handle_list_services)
        self.app.router.add_get(
            "/api/v1/services/{service_id}", self.handle_get_service
        )
        self.app.router.add_get("/api/v1/discover", self.handle_discover)
        self.app.router.add_post(
            "/api/v1/health/{service_id}", self.handle_health_update
        )
        self.app.router.add_get("/api/v1/health/{service_id}", self.handle_health_check)
        self.app.router.add_get("/api/v1/stats", self.handle_stats)
        self.app.router.add_get("/health", self.handle_server_health)

    def setup_middleware(self):
        """Configure middleware"""

        @web.middleware
        async def cors_middleware(request, handler):
            """Add CORS headers"""
            response = await handler(request)
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = (
                "GET, POST, DELETE, OPTIONS"
            )
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"
            return response

        @web.middleware
        async def error_middleware(request, handler):
            """Handle errors gracefully"""
            try:
                response = await handler(request)
                return response
            except web.HTTPException:
                raise
            except Exception as e:
                logger.error(f"Unhandled error: {e}")
                return web.json_response({"error": str(e)}, status=500)

        self.app.middlewares.append(cors_middleware)
        self.app.middlewares.append(error_middleware)

    async def handle_register(self, request: web.Request) -> web.Response:
        """Register a new service"""
        try:
            data = await request.json()

            # Create ServiceInfo from request data
            service_info = ServiceInfo(
                id=data["id"],
                name=data["name"],
                type=data["type"],
                host=data["host"],
                port=data["port"],
                protocol=data.get("protocol", "http"),
                status=ServiceStatus.STARTING,
                capabilities=data.get("capabilities", []),
                metadata=data.get("metadata", {}),
                health_endpoint=data.get("health_endpoint", "/health"),
                version=data.get("version", "1.0.0"),
                last_heartbeat=datetime.utcnow(),
                registered_at=datetime.utcnow(),
            )

            # Register the service
            success = await self.registry.register_service(service_info)

            if success:
                logger.info(f"Service registered: {service_info.id}")
                return web.json_response(
                    {
                        "status": "success",
                        "message": f"Service {service_info.id} registered",
                        "service": service_info.to_dict(),
                    }
                )
            else:
                return web.json_response(
                    {"status": "error", "message": "Failed to register service"},
                    status=400,
                )

        except Exception as e:
            logger.error(f"Registration error: {e}")
            return web.json_response({"status": "error", "message": str(e)}, status=400)

    async def handle_deregister(self, request: web.Request) -> web.Response:
        """Deregister a service"""
        service_id = request.match_info["service_id"]

        success = await self.registry.deregister_service(service_id)

        if success:
            logger.info(f"Service deregistered: {service_id}")
            return web.json_response(
                {"status": "success", "message": f"Service {service_id} deregistered"}
            )
        else:
            return web.json_response(
                {"status": "error", "message": f"Service {service_id} not found"},
                status=404,
            )

    async def handle_list_services(self, request: web.Request) -> web.Response:
        """List all registered services"""
        service_type = request.query.get("type")
        status = request.query.get("status")

        services = list(self.registry.services.values())

        # Filter by type if specified
        if service_type:
            services = [s for s in services if s.type == service_type]

        # Filter by status if specified
        if status:
            if status == "healthy":
                services = [s for s in services if s.is_healthy]
            elif status == "unhealthy":
                services = [s for s in services if not s.is_healthy]

        return web.json_response(
            {"total": len(services), "services": [s.to_dict() for s in services]}
        )

    async def handle_get_service(self, request: web.Request) -> web.Response:
        """Get details of a specific service"""
        service_id = request.match_info["service_id"]

        service = self.registry.services.get(service_id)

        if service:
            return web.json_response(service.to_dict())
        else:
            return web.json_response(
                {"error": f"Service {service_id} not found"}, status=404
            )

    async def handle_discover(self, request: web.Request) -> web.Response:
        """Discover services by name or capability"""
        name = request.query.get("name")
        capability = request.query.get("capability")

        if name:
            services = await self.registry.discover_by_name(name)
        elif capability:
            services = await self.registry.discover_by_capability(capability)
        else:
            return web.json_response(
                {"error": "Must specify either name or capability parameter"},
                status=400,
            )

        return web.json_response(
            {"total": len(services), "services": [s.to_dict() for s in services]}
        )

    async def handle_health_update(self, request: web.Request) -> web.Response:
        """Update health status of a service"""
        service_id = request.match_info["service_id"]

        try:
            data = await request.json()
            is_healthy = data.get("healthy", True)

            service = self.registry.services.get(service_id)
            if service:
                service.is_healthy = is_healthy
                service.last_heartbeat = datetime.utcnow()

                logger.info(f"Health updated for {service_id}: {is_healthy}")

                return web.json_response(
                    {
                        "status": "success",
                        "service_id": service_id,
                        "healthy": is_healthy,
                    }
                )
            else:
                return web.json_response(
                    {"error": f"Service {service_id} not found"}, status=404
                )

        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def handle_health_check(self, request: web.Request) -> web.Response:
        """Check health of a specific service"""
        service_id = request.match_info["service_id"]

        service = self.registry.services.get(service_id)
        if service:
            # Perform active health check
            is_healthy = await self.registry._check_service_health(service)

            return web.json_response(
                {
                    "service_id": service_id,
                    "healthy": is_healthy,
                    "last_heartbeat": (
                        service.last_heartbeat.isoformat()
                        if service.last_heartbeat
                        else None
                    ),
                }
            )
        else:
            return web.json_response(
                {"error": f"Service {service_id} not found"}, status=404
            )

    async def handle_stats(self, request: web.Request) -> web.Response:
        """Get registry statistics"""
        stats = await self.registry.get_statistics()
        return web.json_response(stats)

    async def handle_server_health(self, request: web.Request) -> web.Response:
        """Health check for the registry server itself"""
        return web.json_response(
            {
                "status": "healthy",
                "service": "registry-api",
                "timestamp": datetime.utcnow().isoformat(),
                "registered_services": len(self.registry.services),
            }
        )

    async def start(self):
        """Start the API server"""
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()

        logger.info(f"Registry API Server started on {self.host}:{self.port}")
        logger.info(f"Health endpoint: http://{self.host}:{self.port}/health")
        logger.info(f"API documentation: http://{self.host}:{self.port}/api/v1/")

        # Keep the server running
        while True:
            await asyncio.sleep(3600)


async def main():
    """Main entry point"""
    # Create service registry with SQLite persistence
    registry = ServiceRegistry(db_path="registry.db", health_check_interval=30)

    # Initialize the registry
    await registry.initialize()

    # Create and start API server
    server = RegistryAPIServer(registry, port=8500)

    try:
        await server.start()
    except KeyboardInterrupt:
        logger.info("Shutting down registry server...")
    finally:
        await registry.close()


if __name__ == "__main__":
    asyncio.run(main())
