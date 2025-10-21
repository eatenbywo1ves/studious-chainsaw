#!/usr/bin/env python3
"""
Workspace Logger - Structured logging for workspace manager

Provides JSON-structured logging with per-service log files and centralized log aggregation.
"""

import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional
import sys


class WorkspaceLogger:
    """Structured logging for workspace manager with per-service log capture"""

    def __init__(self, log_dir: Path):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Main log file with date rotation
        today = datetime.now().strftime('%Y%m%d')
        self.main_log = self.log_dir / f"workspace_{today}.log"

        # Configure root logger
        self._configure_logging()

        self.logger = logging.getLogger('workspace_manager')
        self.logger.info("Workspace logger initialized", extra={
            'log_dir': str(self.log_dir),
            'main_log': str(self.main_log)
        })

    def _configure_logging(self):
        """Configure Python logging with JSON formatter"""

        # Custom JSON formatter
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                log_data = {
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'level': record.levelname,
                    'logger': record.name,
                    'message': record.getMessage(),
                }

                # Add extra fields if present
                if hasattr(record, '__dict__'):
                    for key, value in record.__dict__.items():
                        if key not in ['name', 'msg', 'args', 'created', 'filename', 'funcName',
                                       'levelname', 'levelno', 'lineno', 'module', 'msecs',
                                       'pathname', 'process', 'processName', 'relativeCreated',
                                       'thread', 'threadName', 'exc_info', 'exc_text', 'stack_info']:
                            log_data[key] = value

                # Add exception info if present
                if record.exc_info:
                    log_data['exception'] = self.formatException(record.exc_info)

                return json.dumps(log_data)

        # File handler with JSON formatting
        file_handler = logging.FileHandler(self.main_log, encoding='utf-8')
        file_handler.setFormatter(JSONFormatter())
        file_handler.setLevel(logging.INFO)

        # Console handler with standard formatting
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        console_handler.setLevel(logging.INFO)

        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        root_logger.handlers = []  # Clear existing handlers
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)

    def log_service_start(self, service_key: str, command: str, directory: str):
        """Log service startup attempt"""
        self.logger.info(
            f"Starting service: {service_key}",
            extra={
                'event': 'service_start',
                'service': service_key,
                'command': command,
                'directory': directory,
            }
        )

    def log_service_success(self, service_key: str, duration_ms: float, port: Optional[int] = None):
        """Log successful service startup"""
        extra = {
            'event': 'service_ready',
            'service': service_key,
            'startup_duration_ms': round(duration_ms, 2),
        }
        if port:
            extra['port'] = port

        self.logger.info(
            f"Service ready: {service_key} ({duration_ms:.0f}ms)",
            extra=extra
        )

    def log_service_failure(self, service_key: str, error: Exception, attempt: int = 1):
        """Log service startup failure"""
        self.logger.error(
            f"Service failed: {service_key} - {str(error)}",
            extra={
                'event': 'service_failed',
                'service': service_key,
                'error': str(error),
                'error_type': type(error).__name__,
                'attempt': attempt,
            },
            exc_info=True
        )

    def log_service_stop(self, service_key: str, graceful: bool = True):
        """Log service shutdown"""
        self.logger.info(
            f"Stopping service: {service_key}",
            extra={
                'event': 'service_stop',
                'service': service_key,
                'graceful': graceful,
            }
        )

    def log_service_restart(self, service_key: str, reason: str):
        """Log service restart"""
        self.logger.warning(
            f"Restarting service: {service_key} - {reason}",
            extra={
                'event': 'service_restart',
                'service': service_key,
                'reason': reason,
            }
        )

    def log_health_check(self, service_key: str, healthy: bool, latency_ms: float,
                         check_type: str = 'tcp'):
        """Log health check result"""
        level = logging.INFO if healthy else logging.WARNING
        status = "healthy" if healthy else "unhealthy"

        self.logger.log(
            level,
            f"Health check {status}: {service_key} ({latency_ms:.0f}ms)",
            extra={
                'event': 'health_check',
                'service': service_key,
                'healthy': healthy,
                'latency_ms': round(latency_ms, 2),
                'check_type': check_type,
            }
        )

    def log_profile_start(self, profile_name: str, services: list):
        """Log profile startup"""
        self.logger.info(
            f"Starting profile: {profile_name}",
            extra={
                'event': 'profile_start',
                'profile': profile_name,
                'services': services,
                'service_count': len(services),
            }
        )

    def log_profile_complete(self, profile_name: str, duration_ms: float,
                             success_count: int, total_count: int):
        """Log profile startup completion"""
        self.logger.info(
            f"Profile ready: {profile_name} ({success_count}/{total_count} services, {duration_ms:.0f}ms)",
            extra={
                'event': 'profile_complete',
                'profile': profile_name,
                'duration_ms': round(duration_ms, 2),
                'success_count': success_count,
                'total_count': total_count,
                'success_rate': round(success_count / total_count * 100, 2) if total_count > 0 else 0,
            }
        )

    def log_dependency_order(self, profile_name: str, startup_tiers: list):
        """Log dependency-ordered startup plan"""
        self.logger.info(
            f"Startup order for {profile_name}: {len(startup_tiers)} tiers",
            extra={
                'event': 'dependency_order',
                'profile': profile_name,
                'tier_count': len(startup_tiers),
                'tiers': startup_tiers,
            }
        )

    def log_config_loaded(self, config_path: str, service_count: int, profile_count: int):
        """Log configuration file loaded"""
        self.logger.info(
            f"Configuration loaded: {service_count} services, {profile_count} profiles",
            extra={
                'event': 'config_loaded',
                'config_path': config_path,
                'service_count': service_count,
                'profile_count': profile_count,
            }
        )

    def log_error(self, message: str, error: Optional[Exception] = None, **kwargs):
        """Log general error"""
        extra = {'event': 'error', **kwargs}
        self.logger.error(message, extra=extra, exc_info=error is not None)

    def log_warning(self, message: str, **kwargs):
        """Log warning"""
        extra = {'event': 'warning', **kwargs}
        self.logger.warning(message, extra=extra)

    def log_info(self, message: str, **kwargs):
        """Log informational message"""
        extra = {'event': 'info', **kwargs}
        self.logger.info(message, extra=extra)

    def create_service_log_file(self, service_key: str) -> tuple[Path, Path]:
        """Create dedicated log files for service output capture"""
        service_log_dir = self.log_dir / service_key
        service_log_dir.mkdir(exist_ok=True, parents=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        stdout_file = service_log_dir / f"{timestamp}_stdout.log"
        stderr_file = service_log_dir / f"{timestamp}_stderr.log"

        # Create empty files
        stdout_file.touch()
        stderr_file.touch()

        self.logger.debug(
            f"Created log files for {service_key}",
            extra={
                'event': 'log_files_created',
                'service': service_key,
                'stdout': str(stdout_file),
                'stderr': str(stderr_file),
            }
        )

        return stdout_file, stderr_file

    def get_service_logs(self, service_key: str, lines: int = 50) -> Dict[str, list]:
        """Retrieve recent logs for a service"""
        service_log_dir = self.log_dir / service_key

        if not service_log_dir.exists():
            return {'stdout': [], 'stderr': []}

        # Find most recent log files
        stdout_files = sorted(service_log_dir.glob('*_stdout.log'), reverse=True)
        stderr_files = sorted(service_log_dir.glob('*_stderr.log'), reverse=True)

        stdout_lines = []
        stderr_lines = []

        if stdout_files:
            with open(stdout_files[0], 'r', encoding='utf-8', errors='ignore') as f:
                stdout_lines = f.readlines()[-lines:]

        if stderr_files:
            with open(stderr_files[0], 'r', encoding='utf-8', errors='ignore') as f:
                stderr_lines = f.readlines()[-lines:]

        return {
            'stdout': [line.rstrip('\n') for line in stdout_lines],
            'stderr': [line.rstrip('\n') for line in stderr_lines]
        }

    def cleanup_old_logs(self, days_to_keep: int = 7):
        """Clean up log files older than specified days"""
        import time

        cutoff_time = time.time() - (days_to_keep * 24 * 60 * 60)
        removed_count = 0

        for log_file in self.log_dir.rglob('*.log'):
            if log_file.stat().st_mtime < cutoff_time:
                try:
                    log_file.unlink()
                    removed_count += 1
                except Exception as e:
                    self.logger.warning(f"Failed to remove old log: {log_file} - {e}")

        if removed_count > 0:
            self.logger.info(
                f"Cleaned up {removed_count} old log files (>{days_to_keep} days)",
                extra={
                    'event': 'log_cleanup',
                    'removed_count': removed_count,
                    'days_to_keep': days_to_keep,
                }
            )


# Example usage and testing
if __name__ == '__main__':
    # Test the logger
    log_dir = Path(__file__).parent / 'logs'
    logger = WorkspaceLogger(log_dir)

    # Test service lifecycle logging
    logger.log_service_start('test-service', 'python test.py', '/home/user/project')
    logger.log_health_check('test-service', healthy=True, latency_ms=45.2, check_type='http')
    logger.log_service_success('test-service', duration_ms=1234.5, port=8000)

    # Test profile logging
    logger.log_profile_start('test-profile', ['service1', 'service2', 'service3'])
    logger.log_profile_complete('test-profile', duration_ms=5678.9, success_count=3, total_count=3)

    # Test error logging
    try:
        raise ValueError("Test error")
    except Exception as e:
        logger.log_service_failure('test-service', e, attempt=2)

    # Test service logs
    stdout_file, stderr_file = logger.create_service_log_file('test-service')
    print("\n✓ Logger initialized successfully")
    print(f"  Main log: {logger.main_log}")
    print(f"  Service logs: {stdout_file.parent}")
    print(f"\nCheck {logger.main_log} for JSON-structured logs")
