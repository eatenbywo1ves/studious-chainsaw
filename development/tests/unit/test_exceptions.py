"""
Unit Tests for Exceptions Module
Tests custom exception classes and error handling utilities
"""

import pytest
import json
from typing import Dict, Any

from libs.utils.exceptions import (
    # Base exception
    CatalyticException,
    ErrorCode,
    
    # Lattice exceptions
    LatticeException,
    LatticeCreationError,
    LatticeNotFoundError,
    LatticeLimitExceededError,
    InvalidDimensionsError,
    PathNotFoundException,
    
    # GPU exceptions
    GPUException,
    GPUNotAvailableError,
    GPUMemoryError,
    ComputationTimeoutError,
    
    # API exceptions
    APIException,
    ValidationError,
    AuthenticationError,
    RateLimitExceededError,
    
    # Webhook exceptions
    WebhookException,
    WebhookRegistrationError,
    WebhookDeliveryError,
    WebhookSignatureError,
    
    # Database exceptions
    DatabaseException,
    DatabaseConnectionError,
    DatabaseQueryError,
    
    # Memory exceptions
    MemoryException,
    MemoryAllocationError,
    MemoryLimitExceededError,
    
    # Utility function
    handle_exception
)


class TestCatalyticException:
    """Test base CatalyticException class"""
    
    def test_basic_exception_creation(self):
        """Test creating a basic exception"""
        exc = CatalyticException(
            message="Test error",
            error_code=ErrorCode.UNKNOWN_ERROR
        )
        
        assert str(exc) == "[UNKNOWN_ERROR] Test error"
        assert exc.message == "Test error"
        assert exc.error_code == ErrorCode.UNKNOWN_ERROR
        assert exc.details == {}
        assert exc.cause is None
    
    def test_exception_with_details(self):
        """Test exception with additional details"""
        details = {"field": "test", "value": 42}
        exc = CatalyticException(
            message="Detailed error",
            error_code=ErrorCode.VALIDATION_ERROR,
            details=details
        )
        
        assert exc.details == details
        assert exc.details["field"] == "test"
        assert exc.details["value"] == 42
    
    def test_exception_with_cause(self):
        """Test exception with a cause"""
        original_error = ValueError("Original error")
        exc = CatalyticException(
            message="Wrapped error",
            error_code=ErrorCode.UNKNOWN_ERROR,
            cause=original_error
        )
        
        assert exc.cause == original_error
        assert exc.details["cause"] == "Original error"
        assert exc.details["cause_type"] == "ValueError"
    
    def test_exception_to_dict(self):
        """Test converting exception to dictionary"""
        exc = CatalyticException(
            message="API error",
            error_code=ErrorCode.INVALID_REQUEST,
            details={"endpoint": "/api/test"}
        )
        
        result = exc.to_dict()
        
        assert "error" in result
        assert result["error"]["code"] == ErrorCode.INVALID_REQUEST.value
        assert result["error"]["name"] == "INVALID_REQUEST"
        assert result["error"]["message"] == "API error"
        assert result["error"]["details"]["endpoint"] == "/api/test"
    
    def test_exception_to_json(self):
        """Test converting exception to JSON"""
        exc = CatalyticException(
            message="JSON error",
            error_code=ErrorCode.DATABASE_QUERY_ERROR,
            details={"query": "SELECT * FROM test"}
        )
        
        json_str = exc.to_json()
        parsed = json.loads(json_str)
        
        assert parsed["error"]["message"] == "JSON error"
        assert parsed["error"]["code"] == ErrorCode.DATABASE_QUERY_ERROR.value
        assert parsed["error"]["details"]["query"] == "SELECT * FROM test"
    
    def test_exception_repr(self):
        """Test exception representation"""
        exc = CatalyticException(
            message="Test",
            error_code=ErrorCode.UNKNOWN_ERROR,
            details={"key": "value"}
        )
        
        repr_str = repr(exc)
        assert "CatalyticException" in repr_str
        assert "code=1000" in repr_str  # UNKNOWN_ERROR = 1000
        assert "message='Test'" in repr_str


class TestErrorCodes:
    """Test ErrorCode enum values"""
    
    def test_error_code_ranges(self):
        """Test that error codes are in expected ranges"""
        # General errors (1000-1099)
        assert 1000 <= ErrorCode.UNKNOWN_ERROR.value < 1100
        assert 1000 <= ErrorCode.VALIDATION_ERROR.value < 1100
        
        # Lattice errors (2000-2099)
        assert 2000 <= ErrorCode.LATTICE_CREATION_ERROR.value < 2100
        assert 2000 <= ErrorCode.LATTICE_NOT_FOUND.value < 2100
        
        # GPU errors (3000-3099)
        assert 3000 <= ErrorCode.GPU_NOT_AVAILABLE.value < 3100
        assert 3000 <= ErrorCode.GPU_MEMORY_ERROR.value < 3100
        
        # API errors (4000-4099)
        assert 4000 <= ErrorCode.INVALID_REQUEST.value < 4100
        assert 4000 <= ErrorCode.RATE_LIMIT_EXCEEDED.value < 4100
        
        # Webhook errors (5000-5099)
        assert 5000 <= ErrorCode.WEBHOOK_REGISTRATION_FAILED.value < 5100
        assert 5000 <= ErrorCode.WEBHOOK_TIMEOUT.value < 5100
        
        # Database errors (6000-6099)
        assert 6000 <= ErrorCode.DATABASE_CONNECTION_ERROR.value < 6100
        assert 6000 <= ErrorCode.DATABASE_TIMEOUT.value < 6100
        
        # Memory errors (7000-7099)
        assert 7000 <= ErrorCode.MEMORY_ALLOCATION_ERROR.value < 7100
        assert 7000 <= ErrorCode.MEMORY_LIMIT_EXCEEDED.value < 7100
    
    def test_error_code_uniqueness(self):
        """Test that all error codes are unique"""
        codes = [code.value for code in ErrorCode]
        assert len(codes) == len(set(codes)), "Error codes must be unique"


class TestLatticeExceptions:
    """Test lattice-related exceptions"""
    
    def test_lattice_creation_error(self):
        """Test LatticeCreationError"""
        exc = LatticeCreationError(
            message="Failed to create lattice",
            dimensions=5,
            size=10
        )
        
        assert exc.error_code == ErrorCode.LATTICE_CREATION_ERROR
        assert exc.details["dimensions"] == 5
        assert exc.details["size"] == 10
        assert isinstance(exc, LatticeException)
    
    def test_lattice_not_found_error(self):
        """Test LatticeNotFoundError"""
        exc = LatticeNotFoundError(lattice_id="abc123")
        
        assert exc.error_code == ErrorCode.LATTICE_NOT_FOUND
        assert "abc123" in exc.message
        assert exc.details["lattice_id"] == "abc123"
    
    def test_lattice_limit_exceeded_error(self):
        """Test LatticeLimitExceededError"""
        exc = LatticeLimitExceededError(current=101, maximum=100)
        
        assert exc.error_code == ErrorCode.LATTICE_LIMIT_EXCEEDED
        assert "101/100" in exc.message
        assert exc.details["current_count"] == 101
        assert exc.details["maximum_allowed"] == 100
    
    def test_invalid_dimensions_error(self):
        """Test InvalidDimensionsError"""
        exc = InvalidDimensionsError(dimensions=15, min_dims=1, max_dims=10)
        
        assert exc.error_code == ErrorCode.INVALID_DIMENSIONS
        assert "15" in exc.message
        assert "between 1 and 10" in exc.message
        assert exc.details["provided_dimensions"] == 15
    
    def test_path_not_found_exception(self):
        """Test PathNotFoundException"""
        exc = PathNotFoundException(start=0, end=99)
        
        assert exc.error_code == ErrorCode.PATH_NOT_FOUND
        assert "0" in exc.message
        assert "99" in exc.message
        assert exc.details["start"] == "0"
        assert exc.details["end"] == "99"


class TestGPUExceptions:
    """Test GPU-related exceptions"""
    
    def test_gpu_not_available_error(self):
        """Test GPUNotAvailableError"""
        exc = GPUNotAvailableError()
        
        assert exc.error_code == ErrorCode.GPU_NOT_AVAILABLE
        assert "CUDA" in exc.message
        assert isinstance(exc, GPUException)
    
    def test_gpu_not_available_with_reason(self):
        """Test GPUNotAvailableError with custom reason"""
        exc = GPUNotAvailableError(reason="Incompatible driver version")
        
        assert exc.message == "Incompatible driver version"
    
    def test_gpu_memory_error(self):
        """Test GPUMemoryError"""
        exc = GPUMemoryError(required_mb=4096.5, available_mb=2048.0)
        
        assert exc.error_code == ErrorCode.GPU_MEMORY_ERROR
        assert "4096.50MB required" in exc.message
        assert "2048.00MB available" in exc.message
        assert exc.details["required_memory_mb"] == 4096.5
        assert exc.details["available_memory_mb"] == 2048.0
    
    def test_computation_timeout_error(self):
        """Test ComputationTimeoutError"""
        exc = ComputationTimeoutError(operation="matrix_multiply", timeout_seconds=30.5)
        
        assert exc.error_code == ErrorCode.COMPUTATION_TIMEOUT
        assert "matrix_multiply" in exc.message
        assert "30.5 seconds" in exc.message
        assert exc.details["operation"] == "matrix_multiply"
        assert exc.details["timeout_seconds"] == 30.5


class TestAPIExceptions:
    """Test API-related exceptions"""
    
    def test_api_exception_status_codes(self):
        """Test that API exceptions map to correct HTTP status codes"""
        test_cases = [
            (ErrorCode.INVALID_REQUEST, 400),
            (ErrorCode.AUTHENTICATION_FAILED, 401),
            (ErrorCode.AUTHORIZATION_FAILED, 403),
            (ErrorCode.RESOURCE_NOT_FOUND, 404),
            (ErrorCode.METHOD_NOT_ALLOWED, 405),
            (ErrorCode.RATE_LIMIT_EXCEEDED, 429),
            (ErrorCode.VALIDATION_ERROR, 422),
        ]
        
        for error_code, expected_status in test_cases:
            exc = APIException("Test", error_code=error_code)
            assert exc.status_code == expected_status
    
    def test_validation_error(self):
        """Test ValidationError"""
        exc = ValidationError(
            field="email",
            value="invalid@",
            reason="Invalid email format"
        )
        
        assert exc.error_code == ErrorCode.VALIDATION_ERROR
        assert "email" in exc.message
        assert exc.details["field"] == "email"
        assert exc.details["value"] == "invalid@"
        assert exc.details["reason"] == "Invalid email format"
        assert exc.status_code == 422
    
    def test_authentication_error(self):
        """Test AuthenticationError"""
        exc = AuthenticationError()
        
        assert exc.error_code == ErrorCode.AUTHENTICATION_FAILED
        assert "API key" in exc.message
        assert exc.details["auth_method"] == "API key"
        assert exc.status_code == 401
    
    def test_authentication_error_custom_method(self):
        """Test AuthenticationError with custom method"""
        exc = AuthenticationError(method="JWT token")
        
        assert "JWT token" in exc.message
        assert exc.details["auth_method"] == "JWT token"
    
    def test_rate_limit_exceeded_error(self):
        """Test RateLimitExceededError"""
        exc = RateLimitExceededError(limit=100, window="minute", retry_after=30)
        
        assert exc.error_code == ErrorCode.RATE_LIMIT_EXCEEDED
        assert "100 requests per minute" in exc.message
        assert exc.details["limit"] == 100
        assert exc.details["window"] == "minute"
        assert exc.details["retry_after_seconds"] == 30
        assert exc.status_code == 429


class TestWebhookExceptions:
    """Test webhook-related exceptions"""
    
    def test_webhook_registration_error(self):
        """Test WebhookRegistrationError"""
        exc = WebhookRegistrationError(
            url="https://example.com/hook",
            reason="Connection refused"
        )
        
        assert exc.error_code == ErrorCode.WEBHOOK_REGISTRATION_FAILED
        assert "https://example.com/hook" in exc.message
        assert "Connection refused" in exc.message
        assert exc.details["url"] == "https://example.com/hook"
        assert exc.details["reason"] == "Connection refused"
    
    def test_webhook_delivery_error(self):
        """Test WebhookDeliveryError"""
        exc = WebhookDeliveryError(url="https://api.example.com", status_code=500)
        
        assert exc.error_code == ErrorCode.WEBHOOK_DELIVERY_FAILED
        assert "https://api.example.com" in exc.message
        assert "status: 500" in exc.message
        assert exc.details["url"] == "https://api.example.com"
        assert exc.details["response_status"] == 500
    
    def test_webhook_signature_error(self):
        """Test WebhookSignatureError"""
        exc = WebhookSignatureError()
        
        assert exc.error_code == ErrorCode.WEBHOOK_SIGNATURE_INVALID
        assert "signature validation failed" in exc.message.lower()


class TestDatabaseExceptions:
    """Test database-related exceptions"""
    
    def test_database_connection_error(self):
        """Test DatabaseConnectionError"""
        exc = DatabaseConnectionError(database_url="postgresql://localhost:5432/test")
        
        assert exc.error_code == ErrorCode.DATABASE_CONNECTION_ERROR
        assert "postgresql://localhost:5432/test" in exc.message
        assert exc.details["database_url"] == "postgresql://localhost:5432/test"
    
    def test_database_query_error(self):
        """Test DatabaseQueryError"""
        long_query = "SELECT * FROM very_long_table_name " + "WHERE " * 100
        exc = DatabaseQueryError(query=long_query)
        
        assert exc.error_code == ErrorCode.DATABASE_QUERY_ERROR
        assert exc.details["query"] == long_query[:200]  # Should truncate


class TestMemoryExceptions:
    """Test memory-related exceptions"""
    
    def test_memory_allocation_error(self):
        """Test MemoryAllocationError"""
        exc = MemoryAllocationError(size_mb=1024.5)
        
        assert exc.error_code == ErrorCode.MEMORY_ALLOCATION_ERROR
        assert "1024.50MB" in exc.message
        assert exc.details["requested_size_mb"] == 1024.5
    
    def test_memory_limit_exceeded_error(self):
        """Test MemoryLimitExceededError"""
        exc = MemoryLimitExceededError(used_mb=8192.0, limit_mb=4096.0)
        
        assert exc.error_code == ErrorCode.MEMORY_LIMIT_EXCEEDED
        assert "8192.00MB used" in exc.message
        assert "4096.00MB limit" in exc.message
        assert exc.details["used_memory_mb"] == 8192.0
        assert exc.details["memory_limit_mb"] == 4096.0


class TestHandleException:
    """Test handle_exception utility function"""
    
    def test_handle_catalytic_exception(self):
        """Test handling of CatalyticException"""
        original = LatticeCreationError("Test error", dimensions=3, size=10)
        handled = handle_exception(original)
        
        assert handled is original  # Should return same exception
        assert isinstance(handled, CatalyticException)
    
    def test_handle_value_error(self):
        """Test handling of ValueError"""
        original = ValueError("Invalid value")
        handled = handle_exception(original)
        
        assert isinstance(handled, ValidationError)
        assert handled.cause is original
        assert handled.details["original_type"] == "ValueError"
    
    def test_handle_memory_error(self):
        """Test handling of MemoryError"""
        original = MemoryError("Out of memory")
        handled = handle_exception(original)
        
        assert isinstance(handled, MemoryAllocationError)
        assert handled.cause is original
    
    def test_handle_timeout_error(self):
        """Test handling of TimeoutError"""
        original = TimeoutError("Operation timed out")
        handled = handle_exception(original)
        
        assert isinstance(handled, ComputationTimeoutError)
        assert handled.cause is original
    
    def test_handle_connection_error(self):
        """Test handling of ConnectionError"""
        original = ConnectionError("Connection failed")
        handled = handle_exception(original)
        
        assert isinstance(handled, DatabaseConnectionError)
        assert handled.cause is original
    
    def test_handle_unknown_exception(self):
        """Test handling of unknown exception types"""
        original = RuntimeError("Unknown error")
        handled = handle_exception(original)
        
        assert isinstance(handled, CatalyticException)
        assert handled.error_code == ErrorCode.UNKNOWN_ERROR
        assert handled.message == "Unknown error"
        assert handled.details["original_type"] == "RuntimeError"
        assert handled.cause is original


class TestExceptionInheritance:
    """Test exception inheritance hierarchy"""
    
    def test_lattice_exception_hierarchy(self):
        """Test that lattice exceptions inherit correctly"""
        exc = LatticeCreationError("Test", dimensions=3, size=10)
        
        assert isinstance(exc, LatticeException)
        assert isinstance(exc, CatalyticException)
        assert isinstance(exc, Exception)
    
    def test_gpu_exception_hierarchy(self):
        """Test that GPU exceptions inherit correctly"""
        exc = GPUMemoryError(required_mb=100, available_mb=50)
        
        assert isinstance(exc, GPUException)
        assert isinstance(exc, CatalyticException)
        assert isinstance(exc, Exception)
    
    def test_api_exception_hierarchy(self):
        """Test that API exceptions inherit correctly"""
        exc = RateLimitExceededError(limit=100)
        
        assert isinstance(exc, APIException)
        assert isinstance(exc, CatalyticException)
        assert isinstance(exc, Exception)
        
        # Check status code property exists
        assert hasattr(exc, "status_code")
        assert exc.status_code == 429


class TestExceptionSerialization:
    """Test exception serialization for API responses"""
    
    def test_serialize_simple_exception(self):
        """Test serializing a simple exception"""
        exc = CatalyticException("Simple error", ErrorCode.UNKNOWN_ERROR)
        serialized = exc.to_dict()
        
        # Should be JSON-serializable
        json_str = json.dumps(serialized)
        deserialized = json.loads(json_str)
        
        assert deserialized["error"]["code"] == 1000
        assert deserialized["error"]["message"] == "Simple error"
    
    def test_serialize_complex_exception(self):
        """Test serializing exception with complex details"""
        exc = ValidationError(
            field="data",
            value={"nested": {"key": [1, 2, 3]}},
            reason="Complex validation failure"
        )
        
        serialized = exc.to_dict()
        json_str = json.dumps(serialized)
        deserialized = json.loads(json_str)
        
        assert deserialized["error"]["code"] == ErrorCode.VALIDATION_ERROR.value
        assert deserialized["error"]["details"]["field"] == "data"
    
    def test_exception_with_non_serializable_details(self):
        """Test exception with non-JSON-serializable details"""
        import datetime
        
        exc = CatalyticException(
            "Error with date",
            ErrorCode.UNKNOWN_ERROR,
            details={"timestamp": datetime.datetime.now()}
        )
        
        # to_dict should work, but JSON serialization would fail
        dict_form = exc.to_dict()
        assert "timestamp" in dict_form["error"]["details"]
        
        # Convert datetime to string for JSON
        exc.details["timestamp"] = str(exc.details["timestamp"])
        json_str = exc.to_json()
        assert json_str is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=exceptions"])