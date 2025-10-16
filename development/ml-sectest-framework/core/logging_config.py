"""
Centralized Logging Configuration
==================================
Unified logging setup for all ML-SecTest components.

Eliminates 13 duplicate _setup_logger() implementations across:
- BaseSecurityAgent
- SecurityOrchestrator
- AgentCoordinator
- UnifiedHTTPClient
- All 9 individual agents

Features:
- Consistent log formatting across all components
- Structured JSON logging option for production
- Log level configuration per component
- File and console output handlers
- Automatic log rotation
"""

import logging
import logging.handlers
from typing import Optional, Dict
from pathlib import Path
from enum import Enum
import json
from datetime import datetime


class LogLevel(Enum):
    """Log levels for configuration."""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


class LogFormat(Enum):
    """Log output formats."""
    STANDARD = "standard"  # Human-readable format
    JSON = "json"  # Structured JSON for log aggregation
    DETAILED = "detailed"  # Includes file/line information


class JSONFormatter(logging.Formatter):
    """
    Custom formatter for JSON-structured logs.

    Useful for production environments with log aggregation tools
    like ELK stack, Splunk, or CloudWatch.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields if present
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)

        return json.dumps(log_data)


class LoggingConfig:
    """
    Centralized logging configuration for ML-SecTest framework.

    Usage:
        # Basic setup (console only)
        LoggingConfig.setup()

        # Advanced setup with file logging
        LoggingConfig.setup(
            log_level=LogLevel.DEBUG,
            log_format=LogFormat.JSON,
            log_file="mlsectest.log",
            enable_rotation=True
        )

        # Get logger for component
        logger = LoggingConfig.get_logger("PromptInjectionAgent")
    """

    _configured = False
    _loggers: Dict[str, logging.Logger] = {}

    @classmethod
    def setup(
        cls,
        log_level: LogLevel = LogLevel.INFO,
        log_format: LogFormat = LogFormat.STANDARD,
        log_file: Optional[str] = None,
        enable_rotation: bool = False,
        max_bytes: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 5,
        console_output: bool = True
    ) -> None:
        """
        Configure logging for the entire framework.

        Args:
            log_level: Minimum log level to capture
            log_format: Log output format
            log_file: Optional file path for log output
            enable_rotation: Enable log file rotation
            max_bytes: Maximum file size before rotation
            backup_count: Number of backup files to keep
            console_output: Enable console output
        """
        if cls._configured:
            return  # Already configured

        # Get root logger for ML-SecTest
        root_logger = logging.getLogger("MLSecTest")
        root_logger.setLevel(log_level.value)
        root_logger.handlers.clear()  # Remove any existing handlers

        # Create formatter based on selected format
        formatter = cls._create_formatter(log_format)

        # Add console handler if enabled
        if console_output:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(log_level.value)
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)

        # Add file handler if log file specified
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            if enable_rotation:
                file_handler = logging.handlers.RotatingFileHandler(
                    filename=log_file,
                    maxBytes=max_bytes,
                    backupCount=backup_count,
                    encoding='utf-8'
                )
            else:
                file_handler = logging.FileHandler(
                    filename=log_file,
                    mode='a',
                    encoding='utf-8'
                )

            file_handler.setLevel(log_level.value)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)

        cls._configured = True

        root_logger.info("=" * 70)
        root_logger.info("ML-SecTest Logging Initialized")
        root_logger.info(f"Log Level: {log_level.name}")
        root_logger.info(f"Log Format: {log_format.name}")
        if log_file:
            root_logger.info(f"Log File: {log_file}")
        root_logger.info("=" * 70)

    @classmethod
    def _create_formatter(cls, log_format: LogFormat) -> logging.Formatter:
        """
        Create formatter based on selected format type.

        Args:
            log_format: Format type to create

        Returns:
            Configured logging.Formatter instance
        """
        if log_format == LogFormat.JSON:
            return JSONFormatter()

        elif log_format == LogFormat.DETAILED:
            return logging.Formatter(
                fmt='[%(asctime)s] [%(name)s] [%(levelname)s] '
                    '[%(filename)s:%(lineno)d - %(funcName)s()] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )

        else:  # STANDARD format
            return logging.Formatter(
                fmt='[%(asctime)s] [%(name)s] %(levelname)s: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )

    @classmethod
    def get_logger(cls, component_name: str) -> logging.Logger:
        """
        Get or create a logger for a specific component.

        This method ensures consistent naming and configuration across
        all framework components.

        Args:
            component_name: Name of the component (e.g., "PromptInjectionAgent")

        Returns:
            Configured logger instance

        Example:
            logger = LoggingConfig.get_logger("PromptInjectionAgent")
            logger.info("Starting security analysis")
        """
        # Ensure logging is configured
        if not cls._configured:
            cls.setup()

        # Create logger with MLSecTest namespace
        logger_name = f"MLSecTest.{component_name}"

        # Return cached logger if exists
        if logger_name in cls._loggers:
            return cls._loggers[logger_name]

        # Create new logger
        logger = logging.getLogger(logger_name)

        # Cache and return
        cls._loggers[logger_name] = logger
        return logger

    @classmethod
    def set_level(cls, component_name: str, level: LogLevel) -> None:
        """
        Set log level for a specific component.

        Args:
            component_name: Component to configure
            level: Log level to set

        Example:
            # Set agent to DEBUG while keeping others at INFO
            LoggingConfig.set_level("PromptInjectionAgent", LogLevel.DEBUG)
        """
        logger = cls.get_logger(component_name)
        logger.setLevel(level.value)

    @classmethod
    def disable_component(cls, component_name: str) -> None:
        """
        Disable logging for a specific component.

        Args:
            component_name: Component to disable

        Example:
            LoggingConfig.disable_component("HTTPClient")
        """
        logger = cls.get_logger(component_name)
        logger.setLevel(logging.CRITICAL + 1)  # Higher than CRITICAL

    @classmethod
    def reset(cls) -> None:
        """Reset logging configuration."""
        root_logger = logging.getLogger("MLSecTest")
        root_logger.handlers.clear()
        cls._configured = False
        cls._loggers.clear()


# Convenience functions for backward compatibility
def setup_logging(
    log_level: LogLevel = LogLevel.INFO,
    log_format: LogFormat = LogFormat.STANDARD,
    log_file: Optional[str] = None
) -> None:
    """
    Convenience function for basic logging setup.

    Args:
        log_level: Minimum log level
        log_format: Log format type
        log_file: Optional log file path
    """
    LoggingConfig.setup(
        log_level=log_level,
        log_format=log_format,
        log_file=log_file
    )


def get_logger(component_name: str) -> logging.Logger:
    """
    Convenience function to get a component logger.

    Args:
        component_name: Component name

    Returns:
        Configured logger instance
    """
    return LoggingConfig.get_logger(component_name)


# Pre-configured logger instances for common components
def get_agent_logger(agent_id: str) -> logging.Logger:
    """Get logger for a security agent."""
    return LoggingConfig.get_logger(agent_id)


def get_orchestrator_logger() -> logging.Logger:
    """Get logger for orchestrator."""
    return LoggingConfig.get_logger("Orchestrator")


def get_coordinator_logger() -> logging.Logger:
    """Get logger for coordinator."""
    return LoggingConfig.get_logger("AgentCoordinator")


def get_http_client_logger() -> logging.Logger:
    """Get logger for HTTP client."""
    return LoggingConfig.get_logger("HTTPClient")
