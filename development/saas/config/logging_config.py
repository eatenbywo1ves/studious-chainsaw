"""
Centralized Logging Configuration for SaaS Platform

Provides structured logging with different levels for development and production.
Includes request tracking, performance metrics, and error reporting.

Usage:
    from config.logging_config import get_logger

    logger = get_logger(__name__)
    logger.info("User created", extra={"user_id": user.id, "tenant_id": tenant.id})
"""

import logging
import sys
import os
from datetime import datetime
from typing import Optional

# ============================================================================
# LOG FORMAT CONFIGURATION
# ============================================================================

# Production format: JSON-like structured logging
PRODUCTION_FORMAT = '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s", "extra": %(extra)s}'

# Development format: Human-readable with colors
DEVELOPMENT_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging(
    level: str = None,
    environment: str = None,
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    Configure application-wide logging.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        environment: Deployment environment (development, production)
        log_file: Optional file path for log output

    Returns:
        Configured logger instance
    """
    # Determine environment and log level
    if environment is None:
        environment = os.getenv("DEPLOYMENT_ENV", "development")

    if level is None:
        level = os.getenv("LOG_LEVEL", "INFO" if environment == "production" else "DEBUG")

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Clear existing handlers
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)

    # Use appropriate format
    if environment == "production":
        formatter = StructuredFormatter(PRODUCTION_FORMAT)
    else:
        formatter = logging.Formatter(
            DEVELOPMENT_FORMAT,
            datefmt="%Y-%m-%d %H:%M:%S"
        )

    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    # Reduce noise from third-party libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    return root_logger


class StructuredFormatter(logging.Formatter):
    """
    Formatter for structured JSON-like logging in production.
    Handles extra fields properly.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Extract extra fields
        extra_fields = {}
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'created', 'filename', 'funcName',
                          'levelname', 'levelno', 'lineno', 'module', 'msecs',
                          'message', 'pathname', 'process', 'processName',
                          'relativeCreated', 'thread', 'threadName', 'exc_info',
                          'exc_text', 'stack_info', 'asctime']:
                extra_fields[key] = value

        # Add extra fields to record for formatting
        record.extra = extra_fields if extra_fields else {}

        return super().format(record)


# ============================================================================
# LOGGER FACTORY
# ============================================================================

_loggers = {}

def get_logger(name: str) -> logging.Logger:
    """
    Get or create a logger for a specific module.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance

    Example:
        logger = get_logger(__name__)
        logger.info("Processing request", extra={"user_id": "123"})
    """
    if name not in _loggers:
        logger = logging.getLogger(name)
        _loggers[name] = logger

    return _loggers[name]


# ============================================================================
# CONTEXT LOGGING HELPERS
# ============================================================================

class RequestContext:
    """
    Context manager for request-scoped logging.
    Automatically adds request metadata to all log messages.
    """

    def __init__(self, logger: logging.Logger, request_id: str, **context):
        self.logger = logger
        self.request_id = request_id
        self.context = context
        self.start_time = datetime.utcnow()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration_ms = (datetime.utcnow() - self.start_time).total_seconds() * 1000
        if exc_type:
            self.logger.error(
                f"Request failed: {exc_type.__name__}",
                extra={
                    "request_id": self.request_id,
                    "duration_ms": duration_ms,
                    "error": str(exc_val),
                    **self.context
                }
            )
        else:
            self.logger.info(
                "Request completed",
                extra={
                    "request_id": self.request_id,
                    "duration_ms": duration_ms,
                    **self.context
                }
            )

    def log_info(self, message: str, **extra):
        """Log info message with request context"""
        self.logger.info(
            message,
            extra={
                "request_id": self.request_id,
                **self.context,
                **extra
            }
        )

    def log_warning(self, message: str, **extra):
        """Log warning message with request context"""
        self.logger.warning(
            message,
            extra={
                "request_id": self.request_id,
                **self.context,
                **extra
            }
        )

    def log_error(self, message: str, **extra):
        """Log error message with request context"""
        self.logger.error(
            message,
            extra={
                "request_id": self.request_id,
                **self.context,
                **extra
            }
        )


# ============================================================================
# PERFORMANCE LOGGING
# ============================================================================

def log_performance(logger: logging.Logger, operation: str):
    """
    Decorator for logging operation performance.

    Usage:
        @log_performance(logger, "create_lattice")
        def create_lattice(...):
            pass
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = datetime.utcnow()
            try:
                result = func(*args, **kwargs)
                duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                logger.info(
                    f"{operation} completed",
                    extra={"operation": operation, "duration_ms": duration_ms}
                )
                return result
            except Exception as e:
                duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                logger.error(
                    f"{operation} failed",
                    extra={"operation": operation, "duration_ms": duration_ms, "error": str(e)}
                )
                raise
        return wrapper
    return decorator


# ============================================================================
# INITIALIZE LOGGING ON IMPORT
# ============================================================================

# Setup logging when module is imported
setup_logging()
