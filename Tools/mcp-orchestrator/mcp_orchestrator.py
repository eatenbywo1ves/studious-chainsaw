#!/usr/bin/env python3
"""
MCP Server Orchestrator with Health Monitoring

Manages multiple MCP servers with health checks, auto-restart,
and centralized monitoring capabilities.
"""

import json
import subprocess
import threading
import time
import logging
import psutil
import socket
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import sys
import signal

# Add shared utilities to path
sys.path.insert(0, 'C:\\Users\\Corbin\\shared')


class ServerStatus(Enum):
    """MCP Server status states"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    UNHEALTHY = "unhealthy"
    CRASHED = "crashed"
    STOPPING = "stopping"


@dataclass
class MCPServer:
    """MCP Server configuration and state"""
    name: str
    command: str
    args: List[str]
    env: Dict[str, str]
    status: ServerStatus = ServerStatus.STOPPED
    process: Optional[subprocess.Popen] = None
    pid: Optional[int] = None
    port: Optional[int] = None
    start_time: Optional[datetime] = None
    restart_count: int = 0
    last_health_check: Optional[datetime] = None
    health_check_failures: int = 0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0


class MCPOrchestrator:
    """Orchestrates multiple MCP servers with monitoring"""

    def __init__(self, config_file: str = ".mcp.json"):
        self.config_file = Path(config_file)
        self.servers: Dict[str, MCPServer] = {}
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.logger = self._setup_logging()
        self._load_config()
        self._setup_signal_handlers()

    def _setup_logging(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger("MCPOrchestrator")
        logger.setLevel(logging.INFO)

        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

        # File handler
        fh = logging.FileHandler("Tools/mcp-orchestrator/orchestrator.log")
        fh.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        ch.setFormatter(formatter)
        fh.setFormatter(formatter)

        logger.addHandler(ch)
        logger.addHandler(fh)

        return logger

    def _setup_signal_handlers(self):
        """Setup graceful shutdown handlers"""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop_all()
        sys.exit(0)

    def _load_config(self):
        """Load MCP configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)

            for name, server_config in config.get('mcpServers', {}).items():
                self.servers[name] = MCPServer(
                    name=name,
                    command=server_config['command'],
                    args=server_config.get('args', []),
                    env=server_config.get('env', {})
                )
                # Assign ports for monitoring (simplified - would need actual port discovery)
                self.servers[name].port = 3000 + len(self.servers)

            self.logger.info(f"Loaded {len(self.servers)} MCP servers from config")

        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            raise

    def start_server(self, name: str) -> bool:
        """Start a specific MCP server"""
        if name not in self.servers:
            self.logger.error(f"Server {name} not found")
            return False

        server = self.servers[name]

        if server.status == ServerStatus.RUNNING:
            self.logger.info(f"Server {name} is already running")
            return True

        try:
            server.status = ServerStatus.STARTING
            self.logger.info(f"Starting server: {name}")

            # Prepare environment
            env = {**os.environ, **server.env}

            # Start the process
            server.process = subprocess.Popen(
                [server.command] + server.args,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == 'win32' else 0
            )

            server.pid = server.process.pid
            server.start_time = datetime.now()
            server.status = ServerStatus.RUNNING
            server.health_check_failures = 0

            self.logger.info(f"Server {name} started with PID {server.pid}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to start server {name}: {e}")
            server.status = ServerStatus.CRASHED
            return False

    def stop_server(self, name: str, timeout: int = 10) -> bool:
        """Stop a specific MCP server gracefully"""
        if name not in self.servers:
            self.logger.error(f"Server {name} not found")
            return False

        server = self.servers[name]

        if server.status == ServerStatus.STOPPED:
            self.logger.info(f"Server {name} is already stopped")
            return True

        try:
            server.status = ServerStatus.STOPPING
            self.logger.info(f"Stopping server: {name}")

            if server.process:
                server.process.terminate()
                try:
                    server.process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Server {name} didn't stop gracefully, forcing...")
                    server.process.kill()
                    server.process.wait()

            server.status = ServerStatus.STOPPED
            server.process = None
            server.pid = None
            self.logger.info(f"Server {name} stopped")
            return True

        except Exception as e:
            self.logger.error(f"Failed to stop server {name}: {e}")
            return False

    def restart_server(self, name: str) -> bool:
        """Restart a specific server"""
        self.logger.info(f"Restarting server: {name}")
        if self.stop_server(name):
            time.sleep(2)  # Brief pause before restart
            if self.start_server(name):
                self.servers[name].restart_count += 1
                return True
        return False

    def check_server_health(self, name: str) -> bool:
        """Check if a server is healthy"""
        server = self.servers.get(name)
        if not server:
            return False

        try:
            # Check if process is still running
            if server.process and server.process.poll() is not None:
                server.status = ServerStatus.CRASHED
                return False

            # Check process metrics if PID exists
            if server.pid:
                try:
                    proc = psutil.Process(server.pid)
                    server.cpu_usage = proc.cpu_percent(interval=0.1)
                    server.memory_usage = proc.memory_info().rss / (1024 * 1024)  # MB

                    # Basic health check - process exists and not using excessive resources
                    if server.cpu_usage > 90 or server.memory_usage > 1024:  # 1GB
                        self.logger.warning(f"Server {name} using high resources")
                        server.health_check_failures += 1
                        if server.health_check_failures > 3:
                            server.status = ServerStatus.UNHEALTHY
                            return False
                    else:
                        server.health_check_failures = 0

                except psutil.NoSuchProcess:
                    server.status = ServerStatus.CRASHED
                    return False

            server.last_health_check = datetime.now()
            return server.status == ServerStatus.RUNNING

        except Exception as e:
            self.logger.error(f"Health check failed for {name}: {e}")
            return False

    def monitor_servers(self):
        """Monitor all servers continuously"""
        self.logger.info("Starting server monitoring")

        while self.running:
            for name, server in self.servers.items():
                if server.status in [ServerStatus.RUNNING, ServerStatus.UNHEALTHY]:
                    if not self.check_server_health(name):
                        self.logger.warning(f"Server {name} is unhealthy, attempting restart...")
                        if server.restart_count < 3:  # Max 3 restarts
                            self.restart_server(name)
                        else:
                            self.logger.error(f"Server {name} exceeded restart limit")
                            server.status = ServerStatus.CRASHED

            time.sleep(10)  # Check every 10 seconds

    def start_all(self):
        """Start all configured servers"""
        self.logger.info("Starting all MCP servers")
        self.running = True

        for name in self.servers:
            self.start_server(name)
            time.sleep(1)  # Stagger starts

        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_servers, daemon=True)
        self.monitor_thread.start()

        self.logger.info("All servers started, monitoring active")

    def stop_all(self):
        """Stop all running servers"""
        self.logger.info("Stopping all MCP servers")
        self.running = False

        for name in self.servers:
            self.stop_server(name)

        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)

        self.logger.info("All servers stopped")

    def get_status(self) -> Dict:
        """Get status of all servers"""
        status = {}
        for name, server in self.servers.items():
            status[name] = {
                'status': server.status.value,
                'pid': server.pid,
                'uptime': str(datetime.now() - server.start_time) if server.start_time else None,
                'restart_count': server.restart_count,
                'cpu_usage': round(server.cpu_usage, 2),
                'memory_mb': round(server.memory_usage, 2),
                'last_health_check': server.last_health_check.isoformat() if server.last_health_check else None
            }
        return status

    def print_status(self):
        """Print formatted status to console"""
        print("\n" + "="*60)
        print("MCP SERVER STATUS".center(60))
        print("="*60)

        for name, server in self.servers.items():
            # Use ASCII characters for Windows compatibility
            status_symbol = {
                ServerStatus.RUNNING: "[OK]",
                ServerStatus.STOPPED: "[--]",
                ServerStatus.CRASHED: "[XX]",
                ServerStatus.UNHEALTHY: "[!!]",
                ServerStatus.STARTING: "[>>]",
                ServerStatus.STOPPING: "[<<]"
            }.get(server.status, "[??]")

            print(f"\n{status_symbol} {name}")
            print(f"   Status: {server.status.value}")
            if server.pid:
                print(f"   PID: {server.pid}")
            if server.start_time:
                uptime = datetime.now() - server.start_time
                print(f"   Uptime: {uptime}")
            if server.restart_count:
                print(f"   Restarts: {server.restart_count}")
            if server.cpu_usage or server.memory_usage:
                print(f"   Resources: CPU {server.cpu_usage:.1f}% | RAM {server.memory_usage:.1f}MB")

        print("="*60)


def main():
    """Main entry point for CLI usage"""
    import argparse

    parser = argparse.ArgumentParser(description='MCP Server Orchestrator')
    parser.add_argument('action', choices=['start', 'stop', 'restart', 'status', 'monitor'],
                        help='Action to perform')
    parser.add_argument('--server', help='Specific server name (for start/stop/restart)')
    parser.add_argument('--config', default='.mcp.json', help='Config file path')

    args = parser.parse_args()

    orchestrator = MCPOrchestrator(args.config)

    if args.action == 'start':
        if args.server:
            orchestrator.start_server(args.server)
        else:
            orchestrator.start_all()
            print("Press Ctrl+C to stop all servers")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                orchestrator.stop_all()

    elif args.action == 'stop':
        if args.server:
            orchestrator.stop_server(args.server)
        else:
            orchestrator.stop_all()

    elif args.action == 'restart':
        if args.server:
            orchestrator.restart_server(args.server)
        else:
            orchestrator.stop_all()
            time.sleep(2)
            orchestrator.start_all()

    elif args.action == 'status':
        orchestrator.print_status()

    elif args.action == 'monitor':
        orchestrator.start_all()
        print("Monitoring MCP servers... Press Ctrl+C to stop")
        try:
            while True:
                time.sleep(30)
                orchestrator.print_status()
        except KeyboardInterrupt:
            orchestrator.stop_all()


if __name__ == '__main__':
    import os
    os.chdir('C:\\Users\\Corbin')  # Ensure correct working directory
    main()