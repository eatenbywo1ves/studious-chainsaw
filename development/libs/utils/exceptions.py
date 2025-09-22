"""
Custom Exception Classes for Catalytic Computing System
Provides structured error handling with proper error codes and messages
"""

from typing import Optional, Dict, Any
from enum import Enum
import traceback
import json


class ErrorCode(Enum):
    """Standardized error codes for the system"""
    
    # General errors (1000-1099)
    UNKNOWN_ERROR = 1000
    VALIDATION_ERROR = 1001
    CONFIGURATION_ERROR = 1002
    INITIALIZATION_ERROR = 1003
    
    # Lattice computing errors (2000-2099)
    LATTICE_CREATION_ERROR = 2000
    LATTICE_NOT_FOUND = 2001
    LATTICE_LIMIT_EXCEEDED = 2002
    INVALID_DIMENSIONS = 2003
    INVALID_COORDINATES = 2004
    PATH_NOT_FOUND = 2005
    
    # GPU/Computing errors (3000-3099)
    GPU_NOT_AVAILABLE = 3000
    GPU_MEMORY_ERROR = 3001
    CUDA_ERROR = 3002
    COMPUTATION_TIMEOUT = 3003
    PARALLEL_EXECUTION_ERROR = 3004
    
    # API errors (4000-4099)
    INVALID_REQUEST = 4000
    AUTHENTICATION_FAILED = 4001
    AUTHORIZATION_FAILED = 4002
    RATE_LIMIT_EXCEEDED = 4003
    RESOURCE_NOT_FOUND = 4004
    METHOD_NOT_ALLOWED = 4005
    
    # Webhook errors (5000-5099)
    WEBHOOK_REGISTRATION_FAILED = 5000
    WEBHOOK_DELIVERY_FAILED = 5001
    WEBHOOK_TIMEOUT = 5002
    WEBHOOK_SIGNATURE_INVALID = 5003
    WEBHOOK_NOT_FOUND = 5004
    
    # Database errors (6000-6099)
    DATABASE_CONNECTION_ERROR = 6000
    DATABASE_QUERY_ERROR = 6001
    DATABASE_INTEGRITY_ERROR = 6002
    DATABASE_TIMEOUT = 6003
    
    # Memory/Performance errors (7000-7099)
    MEMORY_ALLOCATION_ERROR = 7000
    MEMORY_LIMIT_EXCEEDED = 7001
    CACHE_ERROR = 7002
    PERFORMANCE_DEGRADATION = 7003


class CatalyticException(Exception):
    """Base exception class for all catalytic computing errors"""
    
    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.UNKNOWN_ERROR,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        """
        Initialize exception with structured error information
        
        Args:
            message: Human-readable error message
            error_code: Standardized error code
            details: Additional error details
            cause: Original exception that caused this error
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.cause = cause
        
        # Add traceback if cause is provided
        if cause:
            self.details['cause'] = str(cause)
            self.details['cause_type'] = type(cause).__name__
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for API responses"""
        return {
            'error': {
                'code': self.error_code.value,
                'name': self.error_code.name,
                'message': self.message,
                'details': self.details
            }
        }
    
    def to_json(self) -> str:
        """Convert exception to JSON string"""
        return json.dumps(self.to_dict(), indent=2)
    
    def __str__(self) -> str:
        """String representation of the exception"""
        return f"[{self.error_code.name}] {self.message}"
    
    def __repr__(self) -> str:
        """Detailed representation for debugging"""
        return f"{self.__class__.__name__}(code={self.error_code.value}, message='{self.message}', details={self.details})"


# === Specific Exception Classes ===

class LatticeException(CatalyticException):
    """Base exception for lattice-related errors"""
    pass


class LatticeCreationError(LatticeException):
    """Raised when lattice creation fails"""
    
    def __init__(self, message: str, dimensions: int = None, size: int = None, **kwargs):
        details = kwargs.get('details', {})
        if dimensions:
            details['dimensions'] = dimensions
        if size:
            details['size'] = size
        kwargs['details'] = details
        super().__init__(message, ErrorCode.LATTICE_CREATION_ERROR, **kwargs)


class LatticeNotFoundError(LatticeException):
    """Raised when a lattice ID is not found"""
    
    def __init__(self, lattice_id: str, **kwargs):
        message = f"Lattice with ID '{lattice_id}' not found"
        details = kwargs.get('details', {})
        details['lattice_id'] = lattice_id
        kwargs['details'] = details
        super().__init__(message, ErrorCode.LATTICE_NOT_FOUND, **kwargs)


class LatticeLimitExceededError(LatticeException):
    """Raised when maximum lattice limit is exceeded"""
    
    def __init__(self, current: int, maximum: int, **kwargs):
        message = f"Maximum lattice limit exceeded: {current}/{maximum}"
        details = kwargs.get('details', {})
        details['current_count'] = current
        details['maximum_allowed'] = maximum
        kwargs['details'] = details
        super().__init__(message, ErrorCode.LATTICE_LIMIT_EXCEEDED, **kwargs)


class InvalidDimensionsError(LatticeException):
    """Raised when invalid dimensions are provided"""
    
    def __init__(self, dimensions: int, min_dims: int = 1, max_dims: int = 10, **kwargs):
        message = f"Invalid dimensions: {dimensions}. Must be between {min_dims} and {max_dims}"
        details = kwargs.get('details', {})
        details['provided_dimensions'] = dimensions
        details['min_dimensions'] = min_dims
        details['max_dimensions'] = max_dims
        kwargs['details'] = details
        super().__init__(message, ErrorCode.INVALID_DIMENSIONS, **kwargs)


class PathNotFoundException(LatticeException):
    """Raised when no path exists between two points"""
    
    def __init__(self, start: Any, end: Any, **kwargs):
        message = f"No path found from {start} to {end}"
        details = kwargs.get('details', {})
        details['start'] = str(start)
        details['end'] = str(end)
        kwargs['details'] = details
        super().__init__(message, ErrorCode.PATH_NOT_FOUND, **kwargs)


# === GPU/Computing Exceptions ===

class GPUException(CatalyticException):
    """Base exception for GPU-related errors"""
    pass


class GPUNotAvailableError(GPUException):
    """Raised when GPU is required but not available"""
    
    def __init__(self, reason: str = "No CUDA-capable GPU detected", **kwargs):
        super().__init__(reason, ErrorCode.GPU_NOT_AVAILABLE, **kwargs)


class GPUMemoryError(GPUException):
    """Raised when GPU memory is insufficient"""
    
    def __init__(self, required_mb: float, available_mb: float, **kwargs):
        message = f"Insufficient GPU memory: {required_mb:.2f}MB required, {available_mb:.2f}MB available"
        details = kwargs.get('details', {})
        details['required_memory_mb'] = required_mb
        details['available_memory_mb'] = available_mb
        kwargs['details'] = details
        super().__init__(message, ErrorCode.GPU_MEMORY_ERROR, **kwargs)


class ComputationTimeoutError(CatalyticException):
    """Raised when computation exceeds timeout"""
    
    def __init__(self, operation: str, timeout_seconds: float, **kwargs):
        message = f"Operation '{operation}' timed out after {timeout_seconds} seconds"
        details = kwargs.get('details', {})
        details['operation'] = operation
        details['timeout_seconds'] = timeout_seconds
        kwargs['details'] = details
        super().__init__(message, ErrorCode.COMPUTATION_TIMEOUT, **kwargs)


# === API Exceptions ===

class APIException(CatalyticException):
    """Base exception for API-related errors"""
    
    @property
    def status_code(self) -> int:
        """Map error codes to HTTP status codes"""
        status_map = {
            ErrorCode.INVALID_REQUEST: 400,
            ErrorCode.AUTHENTICATION_FAILED: 401,
            ErrorCode.AUTHORIZATION_FAILED: 403,
            ErrorCode.RESOURCE_NOT_FOUND: 404,
            ErrorCode.METHOD_NOT_ALLOWED: 405,
            ErrorCode.RATE_LIMIT_EXCEEDED: 429,
            ErrorCode.VALIDATION_ERROR: 422,
        }
        return status_map.get(self.error_code, 500)


class ValidationError(APIException):
    """Raised when request validation fails"""
    
    def __init__(self, field: str, value: Any, reason: str, **kwargs):
        message = f"Validation failed for field '{field}': {reason}"
        details = kwargs.get('details', {})
        details['field'] = field
        details['value'] = str(value)
        details['reason'] = reason
        kwargs['details'] = details
        super().__init__(message, ErrorCode.VALIDATION_ERROR, **kwargs)


class AuthenticationError(APIException):
    """Raised when authentication fails"""
    
    def __init__(self, method: str = "API key", **kwargs):
        message = f"Authentication failed: Invalid {method}"
        details = kwargs.get('details', {})
        details['auth_method'] = method
        kwargs['details'] = details
        super().__init__(message, ErrorCode.AUTHENTICATION_FAILED, **kwargs)


class RateLimitExceededError(APIException):
    """Raised when rate limit is exceeded"""
    
    def __init__(self, limit: int, window: str = "minute", retry_after: int = None, **kwargs):
        message = f"Rate limit exceeded: {limit} requests per {window}"
        details = kwargs.get('details', {})
        details['limit'] = limit
        details['window'] = window
        if retry_after:
            details['retry_after_seconds'] = retry_after
        kwargs['details'] = details
        super().__init__(message, ErrorCode.RATE_LIMIT_EXCEEDED, **kwargs)


# === Webhook Exceptions ===

class WebhookException(CatalyticException):
    """Base exception for webhook-related errors"""
    pass


class WebhookRegistrationError(WebhookException):
    """Raised when webhook registration fails"""
    
    def __init__(self, url: str, reason: str, **kwargs):
        message = f"Failed to register webhook for {url}: {reason}"
        details = kwargs.get('details', {})
        details['url'] = url
        details['reason'] = reason
        kwargs['details'] = details
        super().__init__(message, ErrorCode.WEBHOOK_REGISTRATION_FAILED, **kwargs)


class WebhookDeliveryError(WebhookException):
    """Raised when webhook delivery fails"""
    
    def __init__(self, url: str, status_code: int = None, **kwargs):
        message = f"Failed to deliver webhook to {url}"
        if status_code:
            message += f" (status: {status_code})"
        details = kwargs.get('details', {})
        details['url'] = url
        if status_code:
            details['response_status'] = status_code
        kwargs['details'] = details
        super().__init__(message, ErrorCode.WEBHOOK_DELIVERY_FAILED, **kwargs)


class WebhookSignatureError(WebhookException):
    """Raised when webhook signature validation fails"""
    
    def __init__(self, **kwargs):
        message = "Webhook signature validation failed"
        super().__init__(message, ErrorCode.WEBHOOK_SIGNATURE_INVALID, **kwargs)


# === Database Exceptions ===

class DatabaseException(CatalyticException):
    """Base exception for database-related errors"""
    pass


class DatabaseConnectionError(DatabaseException):
    """Raised when database connection fails"""
    
    def __init__(self, database_url: str = None, **kwargs):
        message = "Failed to connect to database"
        if database_url:
            message += f": {database_url}"
        details = kwargs.get('details', {})
        if database_url:
            details['database_url'] = database_url
        kwargs['details'] = details
        super().__init__(message, ErrorCode.DATABASE_CONNECTION_ERROR, **kwargs)


class DatabaseQueryError(DatabaseException):
    """Raised when database query fails"""
    
    def __init__(self, query: str = None, **kwargs):
        message = "Database query failed"
        details = kwargs.get('details', {})
        if query:
            details['query'] = query[:200]  # Truncate long queries
        kwargs['details'] = details
        super().__init__(message, ErrorCode.DATABASE_QUERY_ERROR, **kwargs)


# === Memory/Performance Exceptions ===

class MemoryException(CatalyticException):
    """Base exception for memory-related errors"""
    pass


class MemoryAllocationError(MemoryException):
    """Raised when memory allocation fails"""
    
    def __init__(self, size_mb: float, **kwargs):
        message = f"Failed to allocate {size_mb:.2f}MB of memory"
        details = kwargs.get('details', {})
        details['requested_size_mb'] = size_mb
        kwargs['details'] = details
        super().__init__(message, ErrorCode.MEMORY_ALLOCATION_ERROR, **kwargs)


class MemoryLimitExceededError(MemoryException):
    """Raised when memory limit is exceeded"""
    
    def __init__(self, used_mb: float, limit_mb: float, **kwargs):
        message = f"Memory limit exceeded: {used_mb:.2f}MB used, {limit_mb:.2f}MB limit"
        details = kwargs.get('details', {})
        details['used_memory_mb'] = used_mb
        details['memory_limit_mb'] = limit_mb
        kwargs['details'] = details
        super().__init__(message, ErrorCode.MEMORY_LIMIT_EXCEEDED, **kwargs)


# === Utility Functions ===

def handle_exception(exc: Exception) -> CatalyticException:
    """
    Convert any exception to a CatalyticException
    
    Args:
        exc: The exception to convert
        
    Returns:
        CatalyticException instance
    """
    if isinstance(exc, CatalyticException):
        return exc
    
    # Map common exceptions to our custom exceptions
    exception_map = {
        ValueError: ValidationError,
        MemoryError: MemoryAllocationError,
        TimeoutError: ComputationTimeoutError,
        ConnectionError: DatabaseConnectionError,
    }
    
    exc_type = type(exc)
    if exc_type in exception_map:
        return exception_map[exc_type](
            str(exc),
            cause=exc
        )
    
    # Default to unknown error
    return CatalyticException(
        message=str(exc),
        error_code=ErrorCode.UNKNOWN_ERROR,
        details={'original_type': exc_type.__name__},
        cause=exc
    )


# Export all exception classes
__all__ = [
    'ErrorCode',
    'CatalyticException',
    'LatticeException',
    'LatticeCreationError',
    'LatticeNotFoundError',
    'LatticeLimitExceededError',
    'InvalidDimensionsError',
    'PathNotFoundException',
    'GPUException',
    'GPUNotAvailableError',
    'GPUMemoryError',
    'ComputationTimeoutError',
    'APIException',
    'ValidationError',
    'AuthenticationError',
    'RateLimitExceededError',
    'WebhookException',
    'WebhookRegistrationError',
    'WebhookDeliveryError',
    'WebhookSignatureError',
    'DatabaseException',
    'DatabaseConnectionError',
    'DatabaseQueryError',
    'MemoryException',
    'MemoryAllocationError',
    'MemoryLimitExceededError',
    'handle_exception',
]