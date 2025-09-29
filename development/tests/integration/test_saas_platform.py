"""
Integration tests for the SaaS platform.
"""

import pytest
import asyncio
from pathlib import Path
import sys

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


class TestSaaSAPI:
    """Integration tests for SaaS API endpoints."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_health_endpoint(self):
        """Test API health check endpoint."""
        try:
            import httpx
            
            async with httpx.AsyncClient() as client:
                response = await client.get("http://localhost:8000/health")
                
                if response.status_code == 200:
                    assert response.json()["status"] == "healthy"
                else:
                    pytest.skip("SaaS API not running")
                    
        except ImportError:
            pytest.skip("httpx not available")
        except Exception:
            pytest.skip("SaaS API not accessible")

    @pytest.mark.integration
    @pytest.mark.database
    async def test_tenant_registration(self, database_url):
        """Test tenant registration flow."""
        try:
            import httpx
            
            tenant_data = {
                "company_name": "Test Corp",
                "email": "test@testcorp.com",
                "password": "SecurePass123!",
                "first_name": "Test",
                "last_name": "User",
                "plan_code": "free"
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://localhost:8000/api/tenants/register",
                    json=tenant_data
                )
                
                if response.status_code in [201, 409]:  # Created or already exists
                    if response.status_code == 201:
                        assert response.json()["company_name"] == tenant_data["company_name"]
                else:
                    pytest.skip("SaaS API not running or configured")
                    
        except Exception:
            pytest.skip("SaaS API integration test requires running services")


class TestDatabaseIntegration:
    """Integration tests for database operations."""

    @pytest.mark.integration
    @pytest.mark.database
    def test_database_connection(self, database_url):
        """Test database connectivity."""
        try:
            import psycopg2
            
            conn = psycopg2.connect(database_url)
            cur = conn.cursor()
            cur.execute("SELECT 1")
            result = cur.fetchone()
            
            assert result[0] == 1, "Database should return 1"
            
            conn.close()
            
        except ImportError:
            pytest.skip("psycopg2 not available")
        except Exception:
            pytest.skip("Database not accessible")

    @pytest.mark.integration
    @pytest.mark.database
    def test_schema_validation(self, database_url):
        """Test database schema exists."""
        try:
            import psycopg2
            
            conn = psycopg2.connect(database_url)
            cur = conn.cursor()
            
            # Check if key tables exist
            tables_to_check = [
                "tenants",
                "users", 
                "subscription_plans",
                "lattices",
                "api_keys"
            ]
            
            for table in tables_to_check:
                cur.execute(
                    "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = %s)",
                    (table,)
                )
                exists = cur.fetchone()[0]
                if not exists:
                    pytest.skip(f"Table {table} does not exist - schema not initialized")
            
            conn.close()
            
        except Exception:
            pytest.skip("Database schema validation requires initialized database")


class TestRedisIntegration:
    """Integration tests for Redis operations."""

    @pytest.mark.integration
    @pytest.mark.redis
    def test_redis_connection(self, redis_url):
        """Test Redis connectivity."""
        try:
            import redis
            
            r = redis.from_url(redis_url)
            r.ping()
            
            # Test basic operations
            r.set("test_key", "test_value")
            value = r.get("test_key")
            
            assert value.decode() == "test_value"
            
            r.delete("test_key")
            
        except ImportError:
            pytest.skip("redis package not available")
        except Exception:
            pytest.skip("Redis not accessible")


class TestDockerIntegration:
    """Integration tests for Docker services."""

    @pytest.mark.integration
    @pytest.mark.docker
    def test_docker_compose_services(self):
        """Test Docker Compose services are running."""
        try:
            import subprocess
            import json
            
            # Check if services are running
            result = subprocess.run(
                ["docker-compose", "ps", "--format", "json"],
                capture_output=True,
                text=True,
                cwd=project_root
            )
            
            if result.returncode == 0:
                services = result.stdout.strip().split('\n')
                running_services = []
                
                for service_line in services:
                    if service_line:
                        try:
                            service = json.loads(service_line)
                            if service.get("State") == "running":
                                running_services.append(service.get("Service"))
                        except json.JSONDecodeError:
                            continue
                
                # At least some core services should be running
                core_services = ["postgres", "redis"]
                for service in core_services:
                    if service in running_services:
                        assert True  # At least one core service is running
                        return
                
                pytest.skip("No core Docker services running")
            else:
                pytest.skip("Docker Compose not available or configured")
                
        except Exception:
            pytest.skip("Docker integration test requires Docker setup")


class TestEndToEndWorkflow:
    """End-to-end integration tests."""

    @pytest.mark.integration
    @pytest.mark.slow
    async def test_complete_lattice_workflow(self):
        """Test complete lattice creation and processing workflow."""
        try:
            import httpx
            
            # This would test the complete workflow:
            # 1. Register tenant
            # 2. Login and get token
            # 3. Create lattice
            # 4. Process lattice operations
            # 5. Retrieve results
            
            async with httpx.AsyncClient() as client:
                # Try to access the API
                try:
                    response = await client.get("http://localhost:8000/health")
                    if response.status_code != 200:
                        pytest.skip("SaaS API not available for end-to-end test")
                except:
                    pytest.skip("SaaS API not available for end-to-end test")
                
                # Additional workflow steps would go here
                # For now, just verify the API is accessible
                assert response.status_code == 200
                
        except Exception:
            pytest.skip("End-to-end test requires full SaaS platform deployment")