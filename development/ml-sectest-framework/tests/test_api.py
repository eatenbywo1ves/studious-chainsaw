"""
Test suite for ML-SecTest REST API
===================================
Tests for FastAPI endpoints, request validation, and response handling.
"""

import pytest
from fastapi.testclient import TestClient
from api.main import app
import json

client = TestClient(app)


class TestHealthEndpoint:
    """Tests for /health endpoint."""

    def test_health_check_success(self):
        """Test health check returns 200 OK."""
        response = client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "agents_available" in data
        assert data["agents_available"] >= 0

    def test_health_check_structure(self):
        """Test health check response structure."""
        response = client.get("/health")
        data = response.json()

        required_fields = ["status", "version", "agents_available", "timestamp"]
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"


class TestRootEndpoint:
    """Tests for root endpoint."""

    def test_root_endpoint(self):
        """Test root endpoint returns API information."""
        response = client.get("/")
        assert response.status_code == 200

        data = response.json()
        assert "name" in data
        assert "version" in data
        assert "documentation" in data


class TestScanEndpoints:
    """Tests for scan-related endpoints."""

    def test_create_scan_success(self):
        """Test successful scan creation."""
        payload = {
            "target_url": "http://example.com/api",
            "challenge_name": "test_challenge",
            "parallel": False,
            "report_format": "json"
        }

        response = client.post("/api/v1/scan", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert "scan_id" in data
        assert data["status"] == "queued"
        assert "created_at" in data

    def test_create_scan_invalid_url(self):
        """Test scan creation with invalid URL."""
        payload = {
            "target_url": "not-a-valid-url",
            "challenge_name": "test"
        }

        response = client.post("/api/v1/scan", json=payload)
        assert response.status_code == 422  # Validation error

    def test_create_scan_with_specific_agents(self):
        """Test scan creation with specific agents."""
        payload = {
            "target_url": "http://example.com/api",
            "challenge_name": "custom",
            "agents": ["prompt_injection", "model_inversion"],
            "parallel": True
        }

        response = client.post("/api/v1/scan", json=payload)
        assert response.status_code == 200

    def test_get_scan_status_not_found(self):
        """Test getting status for non-existent scan."""
        response = client.get("/api/v1/scan/nonexistent-scan-id")
        assert response.status_code == 404

    def test_list_scans(self):
        """Test listing all scans."""
        response = client.get("/api/v1/scans")
        assert response.status_code == 200

        data = response.json()
        assert "total" in data
        assert "scans" in data
        assert isinstance(data["scans"], list)

    def test_list_scans_with_limit(self):
        """Test listing scans with limit parameter."""
        response = client.get("/api/v1/scans?limit=5")
        assert response.status_code == 200

        data = response.json()
        assert len(data["scans"]) <= 5


class TestAgentsEndpoint:
    """Tests for agents endpoint."""

    def test_list_agents(self):
        """Test listing available agents."""
        response = client.get("/api/v1/agents")
        assert response.status_code == 200

        data = response.json()
        assert "total" in data
        assert "agents" in data
        assert data["total"] >= 0

    def test_agents_structure(self):
        """Test agent list structure."""
        response = client.get("/api/v1/agents")
        data = response.json()

        if data["total"] > 0:
            agent = data["agents"][0]
            assert "name" in agent
            assert "description" in agent


class TestRequestValidation:
    """Tests for request validation."""

    def test_scan_timeout_min_validation(self):
        """Test timeout minimum value validation."""
        payload = {
            "target_url": "http://example.com",
            "timeout": 5  # Below minimum of 10
        }

        response = client.post("/api/v1/scan", json=payload)
        assert response.status_code == 422

    def test_scan_timeout_max_validation(self):
        """Test timeout maximum value validation."""
        payload = {
            "target_url": "http://example.com",
            "timeout": 4000  # Above maximum of 3600
        }

        response = client.post("/api/v1/scan", json=payload)
        assert response.status_code == 422

    def test_invalid_report_format(self):
        """Test invalid report format."""
        payload = {
            "target_url": "http://example.com",
            "report_format": "xml"  # Not in allowed values
        }

        response = client.post("/api/v1/scan", json=payload)
        assert response.status_code == 422


class TestCORSHeaders:
    """Tests for CORS configuration."""

    def test_cors_middleware_configured(self):
        """Test CORS middleware is properly configured in the app."""
        from fastapi.middleware.cors import CORSMiddleware

        # Check that CORSMiddleware is in the app's middleware stack
        # app.user_middleware contains Middleware objects with a .cls attribute
        middleware_classes = [m.cls for m in app.user_middleware]
        assert CORSMiddleware in middleware_classes, "CORS middleware not configured"


class TestErrorHandling:
    """Tests for error handling."""

    def test_404_not_found(self):
        """Test 404 handling for non-existent endpoints."""
        response = client.get("/nonexistent/endpoint")
        assert response.status_code == 404

    def test_method_not_allowed(self):
        """Test 405 for wrong HTTP method."""
        response = client.put("/api/v1/scan/test-id")
        assert response.status_code == 405


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
