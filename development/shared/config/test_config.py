"""
Configuration System Tests

Run with: python -m pytest shared/config/test_config.py -v
"""

import os
import pytest
from pathlib import Path
from pydantic import ValidationError

from .settings import (
    Settings,
    get_settings,
    Environment,
    SecurityLevel,
    DatabaseConfig,
    RedisConfig,
    AuthConfig,
)


class TestDatabaseConfig:
    """Test database configuration"""
    
    def test_default_sqlite_url(self):
        """Default should be SQLite"""
        config = DatabaseConfig()
        assert config.is_sqlite
        assert not config.is_postgresql
        assert "sqlite" in config.url
    
    def test_postgresql_detection(self):
        """PostgreSQL URL should be detected"""
        config = DatabaseConfig(url="postgresql://user:pass@localhost/db")
        assert config.is_postgresql
        assert not config.is_sqlite
    
    def test_sqlite_rejected_in_production(self, monkeypatch):
        """SQLite should be rejected in production"""
        monkeypatch.setenv("DEPLOYMENT_ENV", "production")
        
        with pytest.raises(ValidationError) as exc_info:
            DatabaseConfig(url="sqlite:///./test.db")
        
        assert "SQLite not allowed in production" in str(exc_info.value)
    
    def test_pool_size_validation(self):
        """Pool size should be validated"""
        # Valid
        config = DatabaseConfig(pool_size=20)
        assert config.pool_size == 20
        
        # Invalid (too low)
        with pytest.raises(ValidationError):
            DatabaseConfig(pool_size=0)
        
        # Invalid (too high)
        with pytest.raises(ValidationError):
            DatabaseConfig(pool_size=101)


class TestRedisConfig:
    """Test Redis configuration"""
    
    def test_default_values(self):
        """Test default Redis configuration"""
        config = RedisConfig()
        assert config.host == "localhost"
        assert config.port == 6379
        assert config.db == 0
        assert config.decode_responses is True
    
    def test_connection_url_without_password(self):
        """Connection URL without password"""
        config = RedisConfig(host="redis.example.com", port=6380)
        assert config.connection_url == "redis://redis.example.com:6380/0"
    
    def test_connection_url_with_password(self):
        """Connection URL with password"""
        config = RedisConfig(
            host="redis.example.com",
            password="secret123"
        )
        # Password should be in URL
        assert ":secret123@" in config.connection_url
    
    def test_circuit_breaker_defaults(self):
        """Circuit breaker should be enabled by default"""
        config = RedisConfig()
        assert config.circuit_breaker_enabled is True
        assert config.circuit_breaker_failure_threshold == 5
        assert config.circuit_breaker_recovery_timeout == 60


class TestAuthConfig:
    """Test authentication configuration"""
    
    def test_jwt_secret_required_in_production(self, monkeypatch):
        """JWT secret should be required in production"""
        monkeypatch.setenv("DEPLOYMENT_ENV", "production")
        
        with pytest.raises(ValidationError) as exc_info:
            AuthConfig(jwt_secret_key=None)
        
        assert "REQUIRED in production" in str(exc_info.value)
    
    def test_jwt_secret_optional_in_development(self, monkeypatch):
        """JWT secret should be optional in development"""
        monkeypatch.setenv("DEPLOYMENT_ENV", "development")
        
        # Should not raise
        config = AuthConfig(jwt_secret_key=None)
        assert config.jwt_secret_key is None
    
    def test_private_key_path_validation(self, tmp_path):
        """Private key path should be validated"""
        # Non-existent path should fail
        with pytest.raises(ValidationError) as exc_info:
            AuthConfig(jwt_private_key_path="/nonexistent/key.pem")
        
        assert "not found" in str(exc_info.value)
        
        # Existing path should work
        key_file = tmp_path / "test_key.pem"
        key_file.write_text("test key content")
        
        config = AuthConfig(jwt_private_key_path=key_file)
        assert config.jwt_private_key_path == key_file
    
    def test_token_expiration_bounds(self):
        """Token expiration should have reasonable bounds"""
        # Valid values
        config = AuthConfig(
            access_token_expire_minutes=15,
            refresh_token_expire_days=30
        )
        assert config.access_token_expire_minutes == 15
        assert config.refresh_token_expire_days == 30
        
        # Too long access token (> 24 hours)
        with pytest.raises(ValidationError):
            AuthConfig(access_token_expire_minutes=1441)
        
        # Too long refresh token (> 90 days)
        with pytest.raises(ValidationError):
            AuthConfig(refresh_token_expire_days=91)


class TestSettings:
    """Test main Settings class"""
    
    def test_settings_initialization(self):
        """Settings should initialize all subconfigs"""
        settings = Settings()
        
        assert settings.app is not None
        assert settings.database is not None
        assert settings.redis is not None
        assert settings.auth is not None
        assert settings.security is not None
        assert settings.cors is not None
        assert settings.email is not None
        assert settings.stripe is not None
    
    def test_get_settings_cached(self):
        """get_settings should return cached instance"""
        settings1 = get_settings()
        settings2 = get_settings()
        
        # Should be the exact same instance
        assert settings1 is settings2
    
    def test_environment_sync(self):
        """DEPLOYMENT_ENV should sync with app.env"""
        settings = Settings(deployment_env=Environment.PRODUCTION)
        assert settings.deployment_env == Environment.PRODUCTION
    
    def test_debug_disabled_in_production(self):
        """Debug should be disabled in production"""
        settings = Settings(
            deployment_env=Environment.PRODUCTION,
            app={"env": Environment.PRODUCTION, "debug": True}
        )
        
        # Debug should be forced to False
        assert settings.app.debug is False
    
    def test_cors_origins_parsing(self):
        """CORS origins should parse from string"""
        settings = Settings(
            cors={"allowed_origins": "http://localhost:3000,http://example.com"}
        )
        
        assert len(settings.cors.allowed_origins) == 2
        assert "http://localhost:3000" in settings.cors.allowed_origins
        assert "http://example.com" in settings.cors.allowed_origins


class TestEmailConfig:
    """Test email configuration"""
    
    def test_provider_detection_sendgrid(self):
        """Should detect SendGrid provider"""
        from .settings import EmailConfig
        
        config = EmailConfig(sendgrid_api_key="SG.test_key")
        assert config.provider == "sendgrid"
    
    def test_provider_detection_ses(self):
        """Should detect AWS SES provider"""
        from .settings import EmailConfig
        
        config = EmailConfig(
            aws_access_key_id="AKIA...",
            aws_secret_access_key="secret"
        )
        assert config.provider == "ses"
    
    def test_provider_detection_smtp(self):
        """Should detect SMTP provider"""
        from .settings import EmailConfig
        
        config = EmailConfig(smtp_host="smtp.example.com")
        assert config.provider == "smtp"
    
    def test_provider_none(self):
        """Should return none if no provider configured"""
        from .settings import EmailConfig
        
        config = EmailConfig()
        assert config.provider == "none"


class TestStripeConfig:
    """Test Stripe configuration"""
    
    def test_test_mode_detection(self):
        """Should detect test vs live mode"""
        from .settings import StripeConfig
        
        # Test mode
        config = StripeConfig(secret_key="sk_test_123456")
        assert config.is_test_mode is True
        
        # Live mode
        config = StripeConfig(secret_key="sk_live_123456")
        assert config.is_test_mode is False
        
        # No key
        config = StripeConfig()
        assert config.is_test_mode is True  # Default to safe


class TestSecurityFeatures:
    """Test security features of configuration"""
    
    def test_secret_str_not_logged(self):
        """SecretStr should not appear in logs"""
        from .settings import AuthConfig
        
        config = AuthConfig(jwt_secret_key="super_secret_key_123")
        
        # repr should hide the secret
        config_repr = repr(config)
        assert "super_secret_key_123" not in config_repr
        assert "SecretStr" in config_repr
    
    def test_secret_str_get_value(self):
        """Should be able to get secret value when needed"""
        from .settings import AuthConfig
        
        config = AuthConfig(jwt_secret_key="super_secret_key_123")
        assert config.jwt_secret_key.get_secret_value() == "super_secret_key_123"


# Integration test
def test_full_configuration_load(monkeypatch, tmp_path):
    """Test loading full configuration from environment"""
    
    # Set environment variables
    monkeypatch.setenv("APP_ENV", "staging")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/db")
    monkeypatch.setenv("REDIS_HOST", "redis.example.com")
    monkeypatch.setenv("REDIS_PASSWORD", "redis_secret")
    monkeypatch.setenv("JWT_SECRET_KEY", "jwt_secret_key_123")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "http://app1.com,http://app2.com")
    
    # Clear cache to force reload
    get_settings.cache_clear()
    
    # Load settings
    settings = get_settings()
    
    # Verify configuration
    assert settings.app.env == Environment.STAGING
    assert settings.database.url == "postgresql://user:pass@localhost/db"
    assert settings.database.is_postgresql
    assert settings.redis.host == "redis.example.com"
    assert settings.redis.password.get_secret_value() == "redis_secret"
    assert settings.auth.jwt_secret_key.get_secret_value() == "jwt_secret_key_123"
    assert len(settings.cors.allowed_origins) == 2


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])
