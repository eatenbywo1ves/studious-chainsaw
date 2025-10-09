#!/usr/bin/env python3
"""
Samsung Fold 7 SSH Connection Monitor and Auto-Reconnector
Monitors SSH connectivity to Samsung Fold 7 via Tailscale and automatically
reconnects when connection drops.
"""

import json
import logging
import subprocess
import time
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
import socket

# Import constants
try:
    from libs.constants import (
        SSH_DEFAULT_CONNECTION_TIMEOUT_SECONDS,
        SSH_DEFAULT_CHECK_INTERVAL_SECONDS,
        SSH_RESTART_WAIT_SECONDS,
        SSH_RESTART_TIMEOUT_SECONDS,
        SSH_DEFAULT_MAX_RETRY_ATTEMPTS,
        SSH_DEFAULT_BACKOFF_MULTIPLIER,
        SSH_MAX_BACKOFF_SECONDS,
        SSH_DEFAULT_PORT,
        SSH_TERMUX_DEFAULT_PORT,
    )
except ImportError:
    # Fallback values if constants module not available
    SSH_DEFAULT_CONNECTION_TIMEOUT_SECONDS = 10
    SSH_DEFAULT_CHECK_INTERVAL_SECONDS = 30
    SSH_RESTART_WAIT_SECONDS = 3
    SSH_RESTART_TIMEOUT_SECONDS = 10
    SSH_DEFAULT_MAX_RETRY_ATTEMPTS = 5
    SSH_DEFAULT_BACKOFF_MULTIPLIER = 2
    SSH_MAX_BACKOFF_SECONDS = 300
    SSH_DEFAULT_PORT = 22
    SSH_TERMUX_DEFAULT_PORT = 8022


class SSHMonitor:
    """Monitor and maintain SSH connection to remote device."""

    def __init__(self, config_path: str = "fold7_config.json"):
        """Initialize SSH monitor with configuration."""
        self.config = self._load_config(config_path)
        self._setup_logging()
        self.connection_failures = 0
        self.last_success = None
        self.total_reconnects = 0

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        config_file = Path(config_path)
        if not config_file.exists():
            self._create_default_config(config_file)
            logging.info(f"Created default config at {config_path}")
            print(f"Please edit {config_path} with your device details and restart.")
            sys.exit(0)

        with open(config_file, "r") as f:
            return json.load(f)

    def _create_default_config(self, config_path: Path) -> None:
        """Create default configuration file."""
        default_config = {
            "device": {
                "name": "Samsung Fold 7",
                "tailscale_hostname": "your-fold7-hostname",
                "ssh_port": SSH_TERMUX_DEFAULT_PORT,
                "ssh_user": "u0_a123",
            },
            "monitoring": {
                "check_interval_seconds": SSH_DEFAULT_CHECK_INTERVAL_SECONDS,
                "connection_timeout_seconds": SSH_DEFAULT_CONNECTION_TIMEOUT_SECONDS,
                "max_retry_attempts": SSH_DEFAULT_MAX_RETRY_ATTEMPTS,
                "exponential_backoff": True,
                "backoff_multiplier": SSH_DEFAULT_BACKOFF_MULTIPLIER,
                "max_backoff_seconds": SSH_MAX_BACKOFF_SECONDS,
            },
            "reconnection": {
                "enabled": True,
                "restart_sshd_command": "sshd",
                "restart_tailscale_command": None,
            },
            "notifications": {
                "log_to_file": True,
                "log_file": "fold7_ssh_monitor.log",
                "console_output": True,
                "notify_on_failure": True,
                "notify_on_recovery": True,
            },
        }

        with open(config_path, "w") as f:
            json.dump(default_config, f, indent=2)

    def _setup_logging(self) -> None:
        """Configure logging based on config settings."""
        log_config = self.config.get("notifications", {})
        log_level = logging.INFO

        handlers = []

        if log_config.get("console_output", True):
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            )
            handlers.append(console_handler)

        if log_config.get("log_to_file", True):
            log_file = log_config.get("log_file", "fold7_ssh_monitor.log")
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            )
            handlers.append(file_handler)

        logging.basicConfig(level=log_level, handlers=handlers)

    def check_tailscale_connectivity(self) -> bool:
        """Check if Tailscale can reach the device."""
        device = self.config["device"]
        hostname = device["tailscale_hostname"]
        timeout = self.config["monitoring"]["connection_timeout_seconds"]

        try:
            # Try to resolve the hostname
            socket.setdefaulttimeout(timeout)
            socket.gethostbyname(hostname)
            return True
        except (socket.gaierror, socket.timeout):
            return False

    def check_ssh_connection(self) -> bool:
        """Check if SSH connection to device is working."""
        device = self.config["device"]
        hostname = device["tailscale_hostname"]
        port = device["ssh_port"]
        user = device["ssh_user"]
        timeout = self.config["monitoring"]["connection_timeout_seconds"]

        # Use SSH to run a simple command
        ssh_command = [
            "ssh",
            "-o",
            "ConnectTimeout={}".format(timeout),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "BatchMode=yes",
            "-p",
            str(port),
            f"{user}@{hostname}",
            'echo "connected"',
        ]

        try:
            result = subprocess.run(
                ssh_command, capture_output=True, text=True, timeout=timeout + 5
            )
            return result.returncode == 0 and "connected" in result.stdout
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            logging.debug(f"SSH check failed: {e}")
            return False

    def restart_ssh_service(self) -> bool:
        """Attempt to restart SSH service on remote device."""
        if not self.config["reconnection"]["enabled"]:
            return False

        device = self.config["device"]
        hostname = device["tailscale_hostname"]
        port = device["ssh_port"]
        user = device["ssh_user"]
        restart_cmd = self.config["reconnection"]["restart_sshd_command"]

        if not restart_cmd:
            return False

        ssh_command = [
            "ssh",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=no",
            "-p",
            str(port),
            f"{user}@{hostname}",
            restart_cmd,
        ]

        try:
            subprocess.run(ssh_command, capture_output=True, timeout=SSH_RESTART_TIMEOUT_SECONDS)
            time.sleep(SSH_RESTART_WAIT_SECONDS)  # Give service time to start
            return True
        except Exception as e:
            logging.warning(f"Failed to restart SSH service: {e}")
            return False

    def calculate_backoff_delay(self, attempt: int) -> int:
        """Calculate exponential backoff delay."""
        monitoring = self.config["monitoring"]

        if not monitoring.get("exponential_backoff", True):
            return monitoring["check_interval_seconds"]

        base_delay = monitoring["check_interval_seconds"]
        multiplier = monitoring.get("backoff_multiplier", 2)
        max_delay = monitoring.get("max_backoff_seconds", 300)

        delay = base_delay * (multiplier ** (attempt - 1))
        return min(delay, max_delay)

    def handle_connection_failure(self) -> None:
        """Handle connection failure with retry logic."""
        self.connection_failures += 1
        max_retries = self.config["monitoring"]["max_retry_attempts"]

        logging.warning(f"SSH connection failed (attempt {self.connection_failures}/{max_retries})")

        if self.connection_failures >= max_retries:
            logging.error("Max retry attempts reached. Attempting service restart...")

            # Check if Tailscale is even reachable
            if not self.check_tailscale_connectivity():
                logging.error("Tailscale cannot reach device. Check phone connectivity.")
                self.connection_failures = 0  # Reset to keep trying
                return

            # Try to restart SSH service
            if self.restart_ssh_service():
                logging.info("SSH service restart attempted")
                self.total_reconnects += 1

            self.connection_failures = 0  # Reset counter after restart attempt

    def handle_connection_success(self) -> None:
        """Handle successful connection."""
        now = datetime.now()

        # Check if this is a recovery from failure
        if self.connection_failures > 0 and self.last_success:
            downtime = (now - self.last_success).total_seconds()
            logging.info(
                f"Connection RECOVERED after {downtime:.0f}s downtime "
                f"({self.connection_failures} failed attempts)"
            )

        self.connection_failures = 0
        self.last_success = now

    def monitor_loop(self) -> None:
        """Main monitoring loop."""
        device_name = self.config["device"]["name"]
        logging.info(f"Starting SSH monitor for {device_name}")
        logging.info(f"Target: {self.config['device']['tailscale_hostname']}")

        try:
            while True:
                if self.check_ssh_connection():
                    self.handle_connection_success()
                    delay = self.config["monitoring"]["check_interval_seconds"]
                else:
                    self.handle_connection_failure()
                    delay = self.calculate_backoff_delay(self.connection_failures)

                # Log periodic status
                if self.last_success:
                    uptime = (datetime.now() - self.last_success).total_seconds()
                    logging.info(
                        f"Status: Connected | Uptime: {uptime:.0f}s | "
                        f"Total reconnects: {self.total_reconnects}"
                    )

                time.sleep(delay)

        except KeyboardInterrupt:
            logging.info("Monitor stopped by user")
            logging.info(f"Session stats: {self.total_reconnects} reconnects")

    def run(self) -> None:
        """Run the monitor."""
        try:
            self.monitor_loop()
        except Exception as e:
            logging.error(f"Fatal error: {e}", exc_info=True)
            sys.exit(1)


def main():
    """Main entry point."""
    print("=" * 60)
    print("Samsung Fold 7 SSH Monitor - Auto-Reconnection Service")
    print("=" * 60)
    print()

    # Check if config file is provided as argument
    config_file = sys.argv[1] if len(sys.argv) > 1 else "fold7_config.json"

    monitor = SSHMonitor(config_file)
    monitor.run()


if __name__ == "__main__":
    main()
