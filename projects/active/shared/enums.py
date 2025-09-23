#!/usr/bin/env python3
"""
Enumeration classes for consistent status and state values across the codebase.
This module provides standard Enum types to replace hardcoded string literals.
"""

from enum import Enum, auto


class HealthStatus(Enum):
    """Health status for system diagnostics"""
    HEALTHY = "HEALTHY"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class CircuitBreakerState(Enum):
    """Circuit breaker states for API gateway"""
    OPEN = "open"
    CLOSED = "closed"
    HALF_OPEN = "half_open"


class ServiceStatus(Enum):
    """Service operation status"""
    SUCCESS = "success"
    FAILURE = "failure"
    PENDING = "pending"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class ProjectionStatus(Enum):
    """Event sourcing projection status"""
    CREATED = "created"
    RUNNING = "running"
    STOPPED = "stopped"
    DELETED = "deleted"
    PAUSED = "paused"
    FAILED = "failed"


class LogLevel(Enum):
    """Logging levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ConnectionState(Enum):
    """Network connection states"""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    RECONNECTING = "reconnecting"
    ERROR = "error"


class AuthenticationStatus(Enum):
    """Authentication status"""
    AUTHENTICATED = "authenticated"
    UNAUTHENTICATED = "unauthenticated"
    EXPIRED = "expired"
    INVALID = "invalid"
    PENDING = "pending"


class OperationMode(Enum):
    """System operation modes"""
    NORMAL = "normal"
    MAINTENANCE = "maintenance"
    READONLY = "readonly"
    EMERGENCY = "emergency"
    DEBUG = "debug"


# Utility functions for enum handling
def get_enum_value(enum_class: Enum, value: str, default=None):
    """
    Safely get an enum value from a string.
    
    Args:
        enum_class: The Enum class to search in
        value: The string value to convert
        default: Default value if not found
        
    Returns:
        The matching enum value or default
    """
    try:
        return enum_class(value)
    except ValueError:
        # Try case-insensitive match
        for member in enum_class:
            if member.value.upper() == value.upper():
                return member
        return default


def is_valid_enum(enum_class: Enum, value: str) -> bool:
    """
    Check if a string is a valid enum value.
    
    Args:
        enum_class: The Enum class to check against
        value: The string value to validate
        
    Returns:
        True if valid, False otherwise
    """
    return any(member.value == value for member in enum_class)