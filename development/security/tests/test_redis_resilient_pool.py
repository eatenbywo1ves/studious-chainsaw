"""
Tests for Resilient Redis Pool
Validates graceful degradation and fault tolerance
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from redis.exceptions import ConnectionError, TimeoutError

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from application.redis_resilient_pool import (
    ResilientRedisPool,
    with_redis_fallback,
)
from application.redis_circuit_breaker import CircuitBreakerOpenError, CircuitState
from application.redis_pool_protocol import DeploymentEnvironment


@pytest.fixture
def mock_redis_pool():
    """Create mock base Redis pool"""
    with patch('application.redis_resilient_pool.OptimizedRedisPool') as MockPool:
        mock_instance = MagicMock()
        mock_instance.is_available = True
        mock_instance.client = MagicMock()
        mock_instance.get_pool_status.return_value = {
            "status": "healthy",
            "max_connections": 20,
            "utilization_percent": 10.0,
        }
        MockPool.return_value = mock_instance
        yield mock_instance


class TestResilientRedisPoolInitialization:
    """Test resilient pool initialization"""

    def test_initializes_with_circuit_breaker(self, mock_redis_pool):
        """Test pool initializes with circuit breaker enabled"""
        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
            enable_circuit_breaker=True,
        )

        assert pool.enable_circuit_breaker is True
        assert pool._circuit_breaker is not None
        assert pool.is_available is True

    def test_initializes_without_circuit_breaker(self, mock_redis_pool):
        """Test pool can be initialized without circuit breaker"""
        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
            enable_circuit_breaker=False,
        )

        assert pool.enable_circuit_breaker is False
        assert pool._circuit_breaker is None

    def test_handles_base_pool_initialization_failure(self):
        """Test graceful handling when base pool fails to initialize"""
        with patch('application.redis_resilient_pool.OptimizedRedisPool') as MockPool:
            MockPool.side_effect = ConnectionError("Redis unavailable")

            pool = ResilientRedisPool(
                environment=DeploymentEnvironment.DEVELOPMENT,
            )

            assert pool.is_available is False
            assert pool._base_pool is None


class TestResilientRedisPoolOperations:
    """Test Redis operations with circuit breaker protection"""

    def test_get_operation_success(self, mock_redis_pool):
        """Test successful GET operation"""
        mock_redis_pool.client.get.return_value = "test_value"

        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
        )

        result = pool.get("test_key")
        assert result == "test_value"
        mock_redis_pool.client.get.assert_called_once_with("test_key")

    def test_set_operation_success(self, mock_redis_pool):
        """Test successful SET operation"""
        mock_redis_pool.client.set.return_value = True

        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
        )

        result = pool.set("test_key", "test_value")
        assert result is True
        mock_redis_pool.client.set.assert_called_once()

    def test_delete_operation_success(self, mock_redis_pool):
        """Test successful DELETE operation"""
        mock_redis_pool.client.delete.return_value = 1

        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
        )

        result = pool.delete("test_key")
        assert result == 1
        mock_redis_pool.client.delete.assert_called_once_with("test_key")

    def test_operations_raise_on_failure_with_circuit_breaker(self, mock_redis_pool):
        """Test operations raise exceptions when circuit is closed"""
        mock_redis_pool.client.get.side_effect = ConnectionError("Redis down")

        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
        )

        with pytest.raises(ConnectionError):
            pool.get("test_key")


class TestGracefulDegradation:
    """Test graceful degradation with fallback methods"""

    def test_get_with_fallback_returns_value(self, mock_redis_pool):
        """Test get_with_fallback returns Redis value when available"""
        mock_redis_pool.client.get.return_value = "redis_value"

        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
        )

        result = pool.get_with_fallback("test_key", default="fallback")
        assert result == "redis_value"

    def test_get_with_fallback_returns_default_on_failure(self, mock_redis_pool):
        """Test get_with_fallback returns default on Redis failure"""
        mock_redis_pool.client.get.side_effect = ConnectionError("Redis down")

        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
            fallback_mode="silent",
        )

        result = pool.get_with_fallback("test_key", default="fallback_value")
        assert result == "fallback_value"

    def test_get_with_fallback_returns_default_on_circuit_open(self, mock_redis_pool):
        """Test get_with_fallback returns default when circuit is open"""
        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
            fallback_mode="silent",
        )

        # Force circuit open
        if pool._circuit_breaker:
            pool._circuit_breaker.force_open()

        result = pool.get_with_fallback("test_key", default="circuit_open_fallback")
        assert result == "circuit_open_fallback"

    def test_set_with_fallback_returns_false_on_failure(self, mock_redis_pool):
        """Test set_with_fallback returns False on Redis failure"""
        mock_redis_pool.client.set.side_effect = ConnectionError("Redis down")

        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
            fallback_mode="silent",
        )

        result = pool.set_with_fallback("test_key", "value")
        assert result is False

    def test_fallback_count_incremented(self, mock_redis_pool):
        """Test fallback count is tracked"""
        mock_redis_pool.client.get.side_effect = ConnectionError("Redis down")

        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
            fallback_mode="silent",
        )

        pool.get_with_fallback("key1", default="fallback1")
        pool.get_with_fallback("key2", default="fallback2")

        status = pool.get_status()
        assert status["fallback_count"] == 2


class TestFallbackModes:
    """Test different fallback logging modes"""

    def test_silent_fallback_mode(self, mock_redis_pool, caplog):
        """Test silent fallback mode uses debug logging"""
        mock_redis_pool.client.get.side_effect = ConnectionError("Redis down")

        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
            fallback_mode="silent",
        )

        with caplog.at_level("DEBUG"):
            pool.get_with_fallback("test_key", default="fallback")

        # Should log at debug level
        assert any("fallback" in record.message.lower() for record in caplog.records)

    def test_warn_fallback_mode(self, mock_redis_pool, caplog):
        """Test warn fallback mode uses warning logging"""
        mock_redis_pool.client.get.side_effect = ConnectionError("Redis down")

        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
            fallback_mode="warn",
        )

        with caplog.at_level("WARNING"):
            pool.get_with_fallback("test_key", default="fallback")

        # Should log at warning level
        assert any(
            "fallback" in record.message.lower() and record.levelname == "WARNING"
            for record in caplog.records
        )

    def test_error_fallback_mode(self, mock_redis_pool, caplog):
        """Test error fallback mode uses error logging"""
        mock_redis_pool.client.get.side_effect = ConnectionError("Redis down")

        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
            fallback_mode="error",
        )

        with caplog.at_level("ERROR"):
            pool.get_with_fallback("test_key", default="fallback")

        # Should log at error level
        assert any(
            "fallback" in record.message.lower() and record.levelname == "ERROR"
            for record in caplog.records
        )


class TestCircuitBreakerIntegration:
    """Test circuit breaker integration"""

    def test_circuit_opens_after_failures(self, mock_redis_pool):
        """Test circuit opens after repeated failures"""
        mock_redis_pool.client.get.side_effect = ConnectionError("Redis down")

        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
        )

        # Trigger failures to open circuit (development has threshold=3)
        for _ in range(3):
            try:
                pool.get("test_key")
            except (ConnectionError, CircuitBreakerOpenError):
                pass

        # Circuit should be open
        circuit_state = pool.get_circuit_state()
        assert circuit_state == CircuitState.OPEN

    def test_rejected_calls_with_open_circuit(self, mock_redis_pool):
        """Test calls are rejected when circuit is open"""
        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
        )

        # Force circuit open
        pool.force_circuit_open()

        # Calls should be rejected
        with pytest.raises(CircuitBreakerOpenError):
            pool.get("test_key")

    def test_manual_circuit_reset(self, mock_redis_pool):
        """Test manual circuit breaker reset"""
        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
        )

        # Force open
        pool.force_circuit_open()
        assert pool.get_circuit_state() == CircuitState.OPEN

        # Manual reset
        pool.reset_circuit_breaker()
        assert pool.get_circuit_state() == CircuitState.CLOSED


class TestStatusAndMonitoring:
    """Test status reporting and monitoring"""

    def test_get_status_includes_circuit_breaker(self, mock_redis_pool):
        """Test status includes circuit breaker metrics"""
        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
        )

        status = pool.get_status()

        assert "circuit_breaker" in status
        assert "pool" in status
        assert "available" in status
        assert status["circuit_breaker_enabled"] is True

    def test_get_status_includes_pool_metrics(self, mock_redis_pool):
        """Test status includes base pool metrics"""
        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
        )

        status = pool.get_status()

        assert "pool" in status
        assert status["pool"]["status"] == "healthy"

    def test_get_circuit_state(self, mock_redis_pool):
        """Test get_circuit_state returns current state"""
        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
        )

        state = pool.get_circuit_state()
        assert state == CircuitState.CLOSED

        # Force open
        pool.force_circuit_open()
        state = pool.get_circuit_state()
        assert state == CircuitState.OPEN


class TestFallbackDecorator:
    """Test with_redis_fallback decorator"""

    def test_decorator_returns_value_on_success(self):
        """Test decorator returns value on successful operation"""
        @with_redis_fallback(default_value="fallback")
        def get_data():
            return "success"

        result = get_data()
        assert result == "success"

    def test_decorator_returns_default_on_connection_error(self):
        """Test decorator returns default on ConnectionError"""
        @with_redis_fallback(default_value="fallback")
        def failing_operation():
            raise ConnectionError("Redis down")

        result = failing_operation()
        assert result == "fallback"

    def test_decorator_returns_default_on_circuit_open(self):
        """Test decorator returns default on CircuitBreakerOpenError"""
        @with_redis_fallback(default_value="circuit_fallback")
        def circuit_open_operation():
            raise CircuitBreakerOpenError("Circuit is open")

        result = circuit_open_operation()
        assert result == "circuit_fallback"

    def test_decorator_handles_timeout_error(self):
        """Test decorator handles TimeoutError"""
        @with_redis_fallback(default_value="timeout_fallback")
        def timeout_operation():
            raise TimeoutError("Operation timed out")

        result = timeout_operation()
        assert result == "timeout_fallback"


class TestContextManager:
    """Test context manager functionality"""

    def test_with_fallback_context_manager(self, mock_redis_pool):
        """Test with_fallback context manager"""
        mock_redis_pool.client.get.side_effect = ConnectionError("Redis down")

        pool = ResilientRedisPool(
            environment=DeploymentEnvironment.DEVELOPMENT,
        )

        with pool.with_fallback(default_value={"default": "value"}):
            # Should not raise, returns default_value
            pool.get("test_key")

    def test_pool_context_manager(self, mock_redis_pool):
        """Test pool can be used as context manager"""
        with ResilientRedisPool(environment=DeploymentEnvironment.DEVELOPMENT) as pool:
            assert pool.is_available is True

        # Pool should be closed after context
        # (In real implementation, this would close connections)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
