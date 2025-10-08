"""
Example: How to integrate OptimizedRedisPool into existing code

This shows how to update jwt_auth.py, mock_auth_server_redis.py, etc.
"""

from redis_connection_pool_optimized import (
    OptimizedRedisPool,
    DeploymentEnvironment,
    get_optimized_redis_pool,
    log_pool_metrics,
)

# ============================================================================
# EXAMPLE 1: Replace jwt_auth.py Redis client
# ============================================================================

def example_jwt_auth_integration():
    """
    Replace the current redis_manager in jwt_auth.py with OptimizedRedisPool
    """

    # OLD CODE (in jwt_auth.py):
    """
    from redis_manager import RedisConnectionManager
    redis_manager = RedisConnectionManager(
        max_connections=100,
        socket_timeout=5,
        socket_connect_timeout=5,
        enable_fallback=True
    )
    redis_client = redis_manager.client
    """

    # NEW CODE (optimized):
    redis_pool = get_optimized_redis_pool(
        environment=DeploymentEnvironment.PRODUCTION  # Auto-detects from env
    )
    redis_client = redis_pool.client

    # Use exactly as before - fully compatible API!
    redis_client.setex("test_key", 60, "test_value")
    value = redis_client.get("test_key")
    print(f"Retrieved: {value}")

    # BONUS: Monitor pool health
    status = redis_pool.get_pool_status()
    print(f"Pool Status: {status}")


# ============================================================================
# EXAMPLE 2: Update mock_auth_server_redis.py
# ============================================================================

def example_mock_server_integration():
    """
    Replace ConnectionPool in mock_auth_server_redis.py
    """

    # OLD CODE:
    """
    from redis import ConnectionPool
    import redis

    pool_kwargs = {
        "host": "localhost",
        "port": 6379,
        "max_connections": 100,
        "decode_responses": True,
        "socket_keepalive": True,
        "socket_timeout": 5,
        "retry_on_timeout": True
    }
    redis_pool = ConnectionPool(**pool_kwargs)
    redis_client = redis.Redis(connection_pool=redis_pool)
    """

    # NEW CODE (optimized):
    import os

    # Set environment for load testing
    os.environ["DEPLOYMENT_ENV"] = "production"  # Test production settings

    redis_pool = get_optimized_redis_pool()
    redis_client = redis_pool.client

    # Everything works the same!
    redis_client.ping()  # Test connection
    print(f"Pool configured for {redis_pool.target_users} concurrent users")


# ============================================================================
# EXAMPLE 3: Add pool monitoring to FastAPI app
# ============================================================================

def example_fastapi_health_endpoint():
    """
    Add pool health monitoring to your FastAPI health endpoint
    """

    from fastapi import FastAPI

    app = FastAPI()

    @app.get("/health/redis")
    async def redis_health():
        """Enhanced health check with pool metrics"""
        redis_pool = get_optimized_redis_pool()

        # Perform health check
        is_healthy = redis_pool.health_check()

        # Get detailed status
        status = redis_pool.get_pool_status()

        return {
            "healthy": is_healthy,
            "pool": status,
            "recommendations": _generate_recommendations(status),
        }

    def _generate_recommendations(status: dict) -> list:
        """Generate optimization recommendations based on pool status"""
        recommendations = []

        util = status.get("utilization_percent", 0)
        if util > 80:
            recommendations.append(
                "CRITICAL: Pool utilization > 80%. Increase max_connections."
            )
        elif util > 60:
            recommendations.append(
                "WARNING: Pool utilization > 60%. Monitor for growth."
            )

        if status.get("metrics", {}).get("pool_exhausted_count", 0) > 0:
            recommendations.append(
                "CRITICAL: Pool exhaustion detected. Increase pool size immediately."
            )

        if status.get("metrics", {}).get("connection_errors", 0) > 10:
            recommendations.append(
                "WARNING: High connection error rate. Check Redis server health."
            )

        if not recommendations:
            recommendations.append("Pool operating optimally.")

        return recommendations

    return app


# ============================================================================
# EXAMPLE 4: Environment-specific configuration
# ============================================================================

def example_environment_configuration():
    """
    Show how to configure for different environments
    """

    import os

    # DEVELOPMENT (single worker, low load)
    os.environ["DEPLOYMENT_ENV"] = "development"
    dev_pool = get_optimized_redis_pool()
    print(f"Dev: {dev_pool.max_connections} connections for {dev_pool.target_users} users")
    # Output: Dev: 20 connections for 100 users

    # STAGING (2 workers, 1K users)
    os.environ["DEPLOYMENT_ENV"] = "staging"
    staging_pool = OptimizedRedisPool(environment=DeploymentEnvironment.STAGING)
    print(
        f"Staging: {staging_pool.max_connections} connections for {staging_pool.target_users} users"
    )
    # Output: Staging: 60 connections for 1000 users

    # PRODUCTION (4 workers, 10K users)
    os.environ["DEPLOYMENT_ENV"] = "production"
    prod_pool = OptimizedRedisPool(environment=DeploymentEnvironment.PRODUCTION)
    print(
        f"Production: {prod_pool.max_connections} connections for {prod_pool.target_users} users"
    )
    # Output: Production: 160 connections for 10000 users


# ============================================================================
# EXAMPLE 5: Monitoring loop for production
# ============================================================================

def example_monitoring_loop():
    """
    Background monitoring task for production deployments
    """

    import asyncio
    import logging

    logger = logging.getLogger(__name__)

    async def monitor_redis_pool():
        """Monitor Redis pool health every 60 seconds"""
        redis_pool = get_optimized_redis_pool()

        while True:
            try:
                # Log metrics
                status = log_pool_metrics(redis_pool)

                # Alert if pool utilization is high
                if status["utilization_percent"] > 80:
                    logger.critical(
                        f"🚨 ALERT: Redis pool at {status['utilization_percent']}% utilization!"
                    )
                    # Here you would integrate with your alerting system (PagerDuty, Slack, etc.)

                # Wait 60 seconds before next check
                await asyncio.sleep(60)

            except Exception as e:
                logger.error(f"Error in Redis pool monitoring: {e}")
                await asyncio.sleep(60)  # Continue monitoring even on errors

    # Start monitoring in FastAPI on startup:
    """
    from fastapi import FastAPI
    import asyncio

    app = FastAPI()

    @app.on_event("startup")
    async def startup_event():
        asyncio.create_task(monitor_redis_pool())
    """


# ============================================================================
# EXAMPLE 6: Load testing with optimized pool
# ============================================================================

def example_load_testing_setup():
    """
    Configure for load testing with production settings
    """

    import os

    # Set production environment for realistic load testing
    os.environ["DEPLOYMENT_ENV"] = "production"
    os.environ["REDIS_HOST"] = "localhost"
    os.environ["REDIS_PORT"] = "6379"
    os.environ["REDIS_PASSWORD"] = "RLr5E73KjlPcAghcLXjBEdWJzqFVeV3EQ1GyQzqoOxo="

    # Get optimized pool
    redis_pool = get_optimized_redis_pool()

    print("=" * 80)
    print("LOAD TESTING CONFIGURATION")
    print("=" * 80)
    print(f"Environment: {redis_pool.environment.value}")
    print(f"Target Users: {redis_pool.target_users}")
    print(f"Workers: {redis_pool.workers}")
    print(f"Max Connections: {redis_pool.max_connections}")
    print(f"Connections per Worker: {redis_pool.max_connections // redis_pool.workers}")
    print("=" * 80)
    print("Pool Features:")
    print("  ✅ Exponential backoff retry (3 attempts)")
    print("  ✅ Health check interval: 30 seconds")
    print("  ✅ Socket keepalive enabled")
    print("  ✅ Connection pool monitoring")
    print("=" * 80)

    # Start load test server with optimized pool:
    """
    uvicorn mock_auth_server_redis:app \\
        --host 0.0.0.0 \\
        --port 8000 \\
        --workers 4 \\
        --log-level info
    """


# ============================================================================
# MAIN: Run examples
# ============================================================================

if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("OPTIMIZED REDIS POOL INTEGRATION EXAMPLES")
    print("=" * 80 + "\n")

    print("Example 1: JWT Auth Integration")
    print("-" * 80)
    example_jwt_auth_integration()

    print("\n\nExample 2: Mock Server Integration")
    print("-" * 80)
    example_mock_server_integration()

    print("\n\nExample 4: Environment Configuration")
    print("-" * 80)
    example_environment_configuration()

    print("\n\nExample 6: Load Testing Setup")
    print("-" * 80)
    example_load_testing_setup()

    print("\n" + "=" * 80)
    print("INTEGRATION EXAMPLES COMPLETE")
    print("=" * 80)
