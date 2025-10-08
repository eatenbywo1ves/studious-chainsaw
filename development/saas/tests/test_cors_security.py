"""
CORS Security Tests
Validates that CORS configuration prevents security vulnerabilities
"""

import pytest
import os
from unittest.mock import patch
from auth.middleware import get_cors_config


class TestCORSConfiguration:
    """Test CORS configuration security"""

    def test_cors_no_wildcard_origin(self):
        """CRITICAL: Ensure CORS does not allow wildcard (*) origins"""
        cors_config = get_cors_config()

        assert "allow_origins" in cors_config
        assert "*" not in cors_config["allow_origins"], \
            "CRITICAL SECURITY ISSUE: CORS allows all origins (wildcard)"

    def test_cors_explicit_origins(self):
        """Verify CORS uses explicit origin whitelist"""
        cors_config = get_cors_config()

        # Should be a list of specific origins
        assert isinstance(cors_config["allow_origins"], list)
        assert len(cors_config["allow_origins"]) > 0

        # All origins should be valid HTTP(S) URLs
        for origin in cors_config["allow_origins"]:
            assert origin.startswith("http://") or origin.startswith("https://"), \
                f"Invalid origin format: {origin}"

    def test_cors_reads_from_env(self):
        """Verify CORS configuration reads from environment variable"""
        test_origins = "https://app.example.com,https://admin.example.com"

        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": test_origins}):
            cors_config = get_cors_config()

            expected_origins = test_origins.split(",")
            assert cors_config["allow_origins"] == expected_origins

    def test_cors_default_localhost_only(self):
        """Verify default CORS allows only localhost for development"""
        # Clear environment to test default
        with patch.dict(os.environ, {}, clear=True):
            cors_config = get_cors_config()

            # Default should only allow localhost
            for origin in cors_config["allow_origins"]:
                assert "localhost" in origin or "127.0.0.1" in origin, \
                    f"Default CORS should only allow localhost, found: {origin}"

    def test_cors_credentials_enabled(self):
        """Verify CORS allows credentials for authentication"""
        cors_config = get_cors_config()

        assert cors_config["allow_credentials"] is True, \
            "CORS must allow credentials for JWT/API key auth"

    def test_cors_explicit_methods(self):
        """Verify CORS uses explicit HTTP methods (no wildcard)"""
        cors_config = get_cors_config()

        assert "allow_methods" in cors_config
        assert "*" not in cors_config["allow_methods"], \
            "CORS should use explicit methods, not wildcard"

        # Verify common methods are included
        expected_methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        for method in expected_methods:
            assert method in cors_config["allow_methods"], \
                f"CORS missing expected method: {method}"

    def test_cors_security_headers_allowed(self):
        """Verify CORS allows necessary security headers"""
        cors_config = get_cors_config()

        required_headers = [
            "Authorization",
            "Content-Type",
            "X-API-Key",
            "X-Tenant-ID"
        ]

        for header in required_headers:
            assert header in cors_config["allow_headers"], \
                f"CORS missing required header: {header}"

    def test_cors_rate_limit_headers_exposed(self):
        """Verify CORS exposes rate limit headers to clients"""
        cors_config = get_cors_config()

        rate_limit_headers = [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset"
        ]

        for header in rate_limit_headers:
            assert header in cors_config["expose_headers"], \
                f"CORS should expose rate limit header: {header}"

    def test_cors_no_sensitive_origins(self):
        """Verify CORS does not include obviously malicious patterns"""
        cors_config = get_cors_config()

        dangerous_patterns = ["*", "null", "file://", "data:"]

        for origin in cors_config["allow_origins"]:
            for pattern in dangerous_patterns:
                assert pattern not in origin.lower(), \
                    f"CORS contains dangerous pattern '{pattern}' in origin: {origin}"


@pytest.mark.security
@pytest.mark.cors
class TestCORSProductionReadiness:
    """Test CORS configuration for production deployment"""

    def test_cors_production_origins(self):
        """Verify production CORS configuration"""
        # Simulate production environment
        prod_origins = "https://app.catalyticcomputing.com,https://api.catalyticcomputing.com"

        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": prod_origins}):
            cors_config = get_cors_config()

            # All origins should use HTTPS in production
            for origin in cors_config["allow_origins"]:
                if "localhost" not in origin and "127.0.0.1" not in origin:
                    assert origin.startswith("https://"), \
                        f"Production origin should use HTTPS: {origin}"

    def test_cors_no_development_origins_in_production(self):
        """Ensure development origins are not leaked to production"""
        prod_origins = "https://app.catalyticcomputing.com"

        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": prod_origins}):
            cors_config = get_cors_config()

            dev_patterns = ["localhost", "127.0.0.1", "0.0.0.0", ".local"]

            for origin in cors_config["allow_origins"]:
                for pattern in dev_patterns:
                    if pattern in origin:
                        pytest.fail(
                            f"Production CORS contains development origin: {origin}"
                        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
