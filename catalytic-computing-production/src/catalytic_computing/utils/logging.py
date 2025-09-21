"""
Production-grade logging configuration with structured logging support
"""

import sys
import logging
import structlog
from typing import Optional, Dict, Any
from pathlib import Path
import json
from datetime import datetime


def setup_logging(
    level: str = "INFO",
    log_file: Optional[Path] = None,
    json_format: bool = True,
    service_name: str = "catalytic-computing"
) -> None:
    """
    Configure structured logging for production environment

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output
        json_format: Whether to use JSON formatting
        service_name: Name of the service for log identification
    """

    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.CallsiteParameterAdder(
                parameters=[
                    structlog.processors.CallsiteParameter.FILENAME,
                    structlog.processors.CallsiteParameter.FUNC_NAME,
                    structlog.processors.CallsiteParameter.LINENO,
                ]
            ),
            structlog.processors.dict_tracebacks,
            structlog.processors.EventRenamer("message"),
            structlog.processors.JSONRenderer() if json_format else structlog.dev.ConsoleRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure standard logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper()),
    )

    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, level.upper()))
        logging.getLogger().addHandler(file_handler)

    # Add service metadata
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(
        service=service_name,
        environment="production",
        version="1.0.0",
    )


class CatalyticLogger:
    """
    Enhanced logger with performance tracking and error handling
    """

    def __init__(self, name: str):
        self.logger = structlog.get_logger(name)
        self._performance_data: Dict[str, Any] = {}

    def log_operation(self, operation: str, **kwargs):
        """Log a catalytic operation with metadata"""
        self.logger.info(
            "catalytic_operation",
            operation=operation,
            timestamp=datetime.utcnow().isoformat(),
            **kwargs
        )

    def log_performance(self, operation: str, duration_ms: float, memory_saved: int = 0):
        """Log performance metrics"""
        self.logger.info(
            "performance_metric",
            operation=operation,
            duration_ms=duration_ms,
            memory_saved_bytes=memory_saved,
            efficiency_ratio=memory_saved / max(duration_ms, 1)
        )

    def log_error(self, error: Exception, operation: str, **context):
        """Log error with full context"""
        self.logger.error(
            "catalytic_error",
            error_type=type(error).__name__,
            error_message=str(error),
            operation=operation,
            **context,
            exc_info=True
        )

    def log_catalyst_state(self, catalyst_id: str, state: str, integrity_check: bool):
        """Log catalyst memory state changes"""
        self.logger.debug(
            "catalyst_state",
            catalyst_id=catalyst_id,
            state=state,
            integrity_check="passed" if integrity_check else "failed",
            timestamp=datetime.utcnow().isoformat()
        )


def get_logger(name: str) -> CatalyticLogger:
    """Get a configured logger instance"""
    return CatalyticLogger(name)