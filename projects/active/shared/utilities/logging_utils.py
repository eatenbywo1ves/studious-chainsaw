"""
Structured Logging Infrastructure
Provides centralized, configurable logging with correlation IDs and distributed tracing
"""

import json
import logging
import sys
import os
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import threading
from contextvars import ContextVar
from dataclasses import dataclass
from enum import Enum
import traceback


class LogLevel(Enum):
    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class LogContext:
    """Context information for structured logging"""

    correlation_id: str = ""
    trace_id: str = ""
    span_id: str = ""
    user_id: str = ""
    session_id: str = ""
    service_name: str = ""
    operation: str = ""
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if not self.correlation_id:
            self.correlation_id = str(uuid.uuid4())
        if self.metadata is None:
            self.metadata = {}


# Context variables for request tracking
correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")
trace_id: ContextVar[str] = ContextVar("trace_id", default="")
span_id: ContextVar[str] = ContextVar("span_id", default="")


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging"""

    def __init__(self, service_name: str = "", include_traceback: bool = True):
        super().__init__()
        self.service_name = service_name
        self.include_traceback = include_traceback

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON"""
        # Base log entry
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add service information
        if self.service_name:
            log_entry["service"] = self.service_name

        # Add process information
        log_entry["process"] = {
            "pid": os.getpid(),
            "thread": threading.current_thread().name,
            "thread_id": threading.get_ident(),
        }

        # Add correlation IDs from context
        try:
            if correlation_id.get():
                log_entry["correlation_id"] = correlation_id.get()
            if trace_id.get():
                log_entry["trace_id"] = trace_id.get()
            if span_id.get():
                log_entry["span_id"] = span_id.get()
        except LookupError:
            pass

        # Add extra fields from record
        extra_fields = {}
        for key, value in record.__dict__.items():
            if key not in [
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "getMessage",
            ]:
                extra_fields[key] = value

        if extra_fields:
            log_entry["extra"] = extra_fields

        # Add exception information
        if record.exc_info and self.include_traceback:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info),
            }

        return json.dumps(log_entry, default=str)


class LoggerManager:
    """Centralized logger management"""

    def __init__(self):
        self.loggers: Dict[str, logging.Logger] = {}
        self.handlers: Dict[str, logging.Handler] = {}
        self.config: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def setup_logger(
        self,
        name: str,
        service_name: str = "",
        level: LogLevel = LogLevel.INFO,
        config: Optional[Dict[str, Any]] = None,
    ) -> logging.Logger:
        """Setup a structured logger"""

        with self._lock:
            if name in self.loggers:
                return self.loggers[name]

            # Create logger
            logger = logging.getLogger(name)
            logger.setLevel(getattr(logging, level.value))

            # Clear existing handlers
            logger.handlers.clear()

            # Use provided config or default
            logger_config = config or self._get_default_config()

            # Setup handlers based on configuration
            if "console" in logger_config.get("destinations", ["console"]):
                console_handler = self._create_console_handler(service_name)
                logger.addHandler(console_handler)

            if "file" in logger_config.get("destinations", []):
                file_handler = self._create_file_handler(
                    name, service_name, logger_config.get("file", {})
                )
                logger.addHandler(file_handler)

            # Prevent propagation to avoid duplicate logs
            logger.propagate = False

            self.loggers[name] = logger
            return logger

    def _create_console_handler(self, service_name: str) -> logging.Handler:
        """Create console handler"""
        handler = logging.StreamHandler(sys.stdout)
        formatter = StructuredFormatter(service_name=service_name)
        handler.setFormatter(formatter)
        return handler

    def _create_file_handler(
        self, logger_name: str, service_name: str, file_config: Dict[str, Any]
    ) -> logging.Handler:
        """Create file handler with rotation"""

        # Ensure log directory exists
        log_path = Path(file_config.get("path", "logs"))
        log_path.mkdir(parents=True, exist_ok=True)

        # Create log file path
        log_file = log_path / f"{logger_name}.log"

        # Setup rotation
        rotation_config = file_config.get("rotation", {})

        if rotation_config.get("enabled", True):
            if rotation_config.get("type", "size") == "size":
                handler = RotatingFileHandler(
                    log_file,
                    maxBytes=self._parse_size(rotation_config.get("max_size", "10MB")),
                    backupCount=rotation_config.get("max_files", 5),
                )
            else:
                handler = TimedRotatingFileHandler(
                    log_file,
                    when=rotation_config.get("when", "midnight"),
                    interval=rotation_config.get("interval", 1),
                    backupCount=rotation_config.get("max_files", 30),
                )
        else:
            handler = logging.FileHandler(log_file)

        # Set formatter
        formatter = StructuredFormatter(service_name=service_name)
        handler.setFormatter(formatter)

        return handler

    def _parse_size(self, size_str: str) -> int:
        """Parse size string like '10MB' into bytes"""
        size_str = size_str.upper()
        if size_str.endswith("KB"):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith("MB"):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith("GB"):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default logging configuration"""
        return {
            "level": "INFO",
            "destinations": ["console"],
            "file": {
                "path": "logs",
                "rotation": {"enabled": True, "max_size": "10MB", "max_files": 5},
            },
        }

    def get_logger(self, name: str) -> Optional[logging.Logger]:
        """Get existing logger"""
        return self.loggers.get(name)

    def update_level(self, name: str, level: LogLevel):
        """Update logger level"""
        if name in self.loggers:
            self.loggers[name].setLevel(getattr(logging, level.value))

    def add_handler(self, logger_name: str, handler: logging.Handler):
        """Add handler to logger"""
        if logger_name in self.loggers:
            self.loggers[logger_name].addHandler(handler)


# Global logger manager instance
_logger_manager = LoggerManager()


def setup_logging(
    name: str,
    service_name: str = "",
    level: LogLevel = LogLevel.INFO,
    config: Optional[Dict[str, Any]] = None,
) -> logging.Logger:
    """Setup a structured logger (convenience function)"""
    return _logger_manager.setup_logger(name, service_name, level, config)


def get_logger(name: str) -> Optional[logging.Logger]:
    """Get existing logger (convenience function)"""
    return _logger_manager.get_logger(name)


def set_correlation_id(id: str):
    """Set correlation ID for current context"""
    correlation_id.set(id)


def get_correlation_id() -> str:
    """Get correlation ID from current context"""
    try:
        return correlation_id.get()
    except LookupError:
        return ""


def set_trace_id(id: str):
    """Set trace ID for current context"""
    trace_id.set(id)


def get_trace_id() -> str:
    """Get trace ID from current context"""
    try:
        return trace_id.get()
    except LookupError:
        return ""


def set_span_id(id: str):
    """Set span ID for current context"""
    span_id.set(id)


def get_span_id() -> str:
    """Get span ID from current context"""
    try:
        return span_id.get()
    except LookupError:
        return ""


def log_with_context(
    logger: logging.Logger,
    level: LogLevel,
    message: str,
    context: Optional[LogContext] = None,
    **kwargs,
):
    """Log with additional context"""
    if context:
        # Set context variables
        if context.correlation_id:
            correlation_id.set(context.correlation_id)
        if context.trace_id:
            trace_id.set(context.trace_id)
        if context.span_id:
            span_id.set(context.span_id)

    # Add extra fields
    log_method = getattr(logger, level.value.lower())
    log_method(message, extra=kwargs)


class LoggingContextManager:
    """Context manager for setting logging context"""

    def __init__(self, context: LogContext):
        self.context = context
        self.old_correlation_id = ""
        self.old_trace_id = ""
        self.old_span_id = ""

    def __enter__(self):
        # Save old values
        try:
            self.old_correlation_id = correlation_id.get()
        except LookupError:
            pass

        try:
            self.old_trace_id = trace_id.get()
        except LookupError:
            pass

        try:
            self.old_span_id = span_id.get()
        except LookupError:
            pass

        # Set new values
        if self.context.correlation_id:
            correlation_id.set(self.context.correlation_id)
        if self.context.trace_id:
            trace_id.set(self.context.trace_id)
        if self.context.span_id:
            span_id.set(self.context.span_id)

        return self.context

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore old values
        correlation_id.set(self.old_correlation_id)
        trace_id.set(self.old_trace_id)
        span_id.set(self.old_span_id)


def with_context(context: LogContext):
    """Context manager for logging context"""
    return LoggingContextManager(context)


# Convenience functions for common logging patterns
def setup_agent_logging(
    agent_name: str, level: LogLevel = LogLevel.INFO, enable_file_logging: bool = True
) -> logging.Logger:
    """Setup logging for an agent"""
    config = {
        "level": level.value,
        "destinations": ["console"] + (["file"] if enable_file_logging else []),
        "file": {
            "path": "logs/agents",
            "rotation": {"enabled": True, "max_size": "50MB", "max_files": 10},
        },
    }

    return setup_logging(f"agent.{agent_name}", agent_name, level, config)


def setup_mcp_logging(
    server_name: str, level: LogLevel = LogLevel.INFO, enable_file_logging: bool = True
) -> logging.Logger:
    """Setup logging for an MCP server"""
    config = {
        "level": level.value,
        "destinations": ["console"] + (["file"] if enable_file_logging else []),
        "file": {
            "path": "logs/mcp",
            "rotation": {"enabled": True, "max_size": "50MB", "max_files": 10},
        },
    }

    return setup_logging(f"mcp.{server_name}", f"mcp-{server_name}", level, config)


def setup_service_logging(
    service_name: str, level: LogLevel = LogLevel.INFO, enable_file_logging: bool = True
) -> logging.Logger:
    """Setup logging for a service"""
    config = {
        "level": level.value,
        "destinations": ["console"] + (["file"] if enable_file_logging else []),
        "file": {
            "path": "logs/services",
            "rotation": {"enabled": True, "max_size": "50MB", "max_files": 10},
        },
    }

    return setup_logging(f"service.{service_name}", service_name, level, config)


def setup_system_logging(
    component_name: str, level: str = "INFO", enable_file_logging: bool = True
) -> logging.Logger:
    """Setup logging for system components like initializer"""
    log_level = LogLevel(level)
    config = {
        "level": log_level.value,
        "destinations": ["console"] + (["file"] if enable_file_logging else []),
        "file": {
            "path": "logs/system",
            "rotation": {"enabled": True, "max_size": "50MB", "max_files": 10},
        },
    }

    return setup_logging(
        f"SYS-{component_name.upper()}", component_name, log_level, config
    )
