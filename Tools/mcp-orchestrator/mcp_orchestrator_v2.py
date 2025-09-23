#!/usr/bin/env python3
"""
MCP Server Orchestrator v2 with Improved Health Monitoring
Manages multiple MCP servers with proper health checks and restart management
"""

import json
import subprocess
import threading
import time
import logging
import psutil
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum
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
class ServerState:
    """Persistent server state"""
    restart_count: int = 0
    total_restarts: int = 0
    consecutive_failures: int = 0
    last_restart: Optional[str] = None


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
    start_time: Optional[datetime] = None
    last_health_check: Optional[datetime] = None
    health_check_failures: int = 0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    state: ServerState = field(default_factory=ServerState)
    startup_grace_period: int = 5  # seconds to wait before health checks


class MCPOrchestrator:
    """Orchestrates multiple MCP servers with monitoring"""

    def __init__(self, config_file: str = ".mcp.json"):
        self.config_file = Path(config_file)
        self.state_file = Path("Tools/mcp-orchestrator/orchestrator_state.json")
        self.servers: Dict[str, MCPServer] = {}
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.logger = self._setup_logging()
        self._load_state()
        self._load_config()
        self._setup_signal_handlers()

    def _setup_logging(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger("MCPOrchestrator")
        logger.setLevel(logging.INFO)

        # Clear existing handlers
        logger.handlers = []

        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

        # File handler
        os.makedirs("Tools/mcp-orchestrator", exist_ok=True)
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
        self._save_state()
        sys.exit(0)

    def _load_state(self):
        """Load persistent state from file"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    state_data = json.load(f)
                    return state_data
            except Exception as e:
                self.logger.warning(f"Could not load state: {e}")
        return {}

    def _save_state(self):
        """Save persistent state to file"""
        try:
            state_data = {}
            for name, server in self.servers.items():
                state_data[name] = {
                    'restart_count': server.state.restart_count,
                    'total_restarts': server.state.total_restarts,
                    'consecutive_failures': server.state.consecutive_failures,
                    'last_restart': server.state.last_restart
                }

            os.makedirs(self.state_file.parent, exist_ok=True)
            with open(self.state_file, 'w') as f:
                json.dump(state_data, f, indent=2)

        except Exception as e:
            self.logger.error(f"Failed to save state: {e}")

    def _load_config(self):
        """Load MCP configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)

            # Load saved state
            saved_state = self._load_state()

            for name, server_config in config.get('mcpServers', {}).items():
                # Create server with persistent state
                server = MCPServer(
                    name=name,
                    command=server_config['command'],
                    args=server_config.get('args', []),
                    env=server_config.get('env', {})
                )

                # Restore persistent state if available
                if name in saved_state:
                    state = saved_state[name]
                    server.state.restart_count = state.get('restart_count', 0)
                    server.state.total_restarts = state.get('total_restarts', 0)
                    server.state.consecutive_failures = state.get('consecutive_failures', 0)
                    server.state.last_restart = state.get('last_restart')

                self.servers[name] = server

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

            # Start the process with pipes for communication
            server.process = subprocess.Popen(
                [server.command] + server.args,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0,
                bufsize=1,  # Line buffered
                universal_newlines=False  # Use binary mode
            )

            server.pid = server.process.pid
            server.start_time = datetime.now()
            server.status = ServerStatus.RUNNING
            server.health_check_failures = 0

            self.logger.info(f"Server {name} started with PID {server.pid}")

            # Give the server time to initialize
            time.sleep(2)

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
                # Try graceful shutdown first
                try:
                    shutdown_request = json.dumps({
                        "jsonrpc": "2.0",
                        "method": "shutdown",
                        "params": {},
                        "id": "shutdown"
                    }).encode() + b"\\n"

                    server.process.stdin.write(shutdown_request)
                    server.process.stdin.flush()
                    server.process.wait(timeout=2)
                except:
                    pass

                # If still running, terminate
                if server.process.poll() is None:
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
        """Restart a specific server with backoff"""
        server = self.servers.get(name)
        if not server:
            return False

        # Check restart limits
        if server.state.restart_count >= 5:
            self.logger.error(f"Server {name} exceeded restart limit (5 restarts in current session)")
            return False

        # Exponential backoff
        backoff_time = min(2 ** server.state.restart_count, 30)
        self.logger.info(f"Restarting server {name} (attempt {server.state.restart_count + 1}, waiting {backoff_time}s)")

        if self.stop_server(name):
            time.sleep(backoff_time)
            if self.start_server(name):
                server.state.restart_count += 1
                server.state.total_restarts += 1
                server.state.last_restart = datetime.now().isoformat()
                self._save_state()
                return True
        return False

    def check_server_health(self, name: str) -> bool:
        """Check if a server is healthy using process existence only"""
        server = self.servers.get(name)
        if not server:
            return False

        try:
            # Skip health check during grace period
            if server.start_time:
                elapsed = (datetime.now() - server.start_time).total_seconds()
                if elapsed < server.startup_grace_period:
                    return True  # Assume healthy during startup

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

                    # Check resource usage
                    if server.cpu_usage > 95 or server.memory_usage > 2048:  # 2GB
                        self.logger.warning(f"Server {name} using high resources: CPU={server.cpu_usage}%, RAM={server.memory_usage}MB")

                    # Process exists, consider it healthy
                    server.health_check_failures = 0
                    server.state.consecutive_failures = 0

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
                        self.logger.warning(f"Server {name} is unhealthy")
                        server.state.consecutive_failures += 1

                        # Only restart if not exceeding limits
                        if server.state.restart_count < 5:
                            self.restart_server(name)
                        else:
                            self.logger.error(f"Server {name} exceeded restart limit")
                            server.status = ServerStatus.CRASHED

            # Save state periodically
            self._save_state()
            time.sleep(10)  # Check every 10 seconds

    def reset_server_limits(self, name: str):
        """Reset restart limits for a server"""
        if name in self.servers:
            self.servers[name].state.restart_count = 0
            self.servers[name].state.consecutive_failures = 0
            self._save_state()
            self.logger.info(f"Reset limits for server {name}")

    def start_all(self):
        """Start all configured servers"""
        self.logger.info("Starting all MCP servers")
        self.running = True

        # Reset session restart counts
        for server in self.servers.values():
            server.state.restart_count = 0

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

        self._save_state()
        self.logger.info("All servers stopped")

    def get_status(self) -> Dict:
        """Get status of all servers"""
        status = {}
        for name, server in self.servers.items():
            status[name] = {
                'status': server.status.value,
                'pid': server.pid,
                'uptime': str(datetime.now() - server.start_time) if server.start_time else None,
                'restarts_session': server.state.restart_count,
                'restarts_total': server.state.total_restarts,
                'cpu_usage': round(server.cpu_usage, 2),
                'memory_mb': round(server.memory_usage, 2),
                'last_health_check': server.last_health_check.isoformat() if server.last_health_check else None,
                'consecutive_failures': server.state.consecutive_failures
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
            if server.state.restart_count:
                print(f"   Restarts (session): {server.state.restart_count}/5")
            if server.state.total_restarts:
                print(f"   Restarts (total): {server.state.total_restarts}")
            if server.cpu_usage or server.memory_usage:
                print(f"   Resources: CPU {server.cpu_usage:.1f}% | RAM {server.memory_usage:.1f}MB")

        print("="*60)


def main():
    """Main entry point for CLI usage"""
    import argparse

    parser = argparse.ArgumentParser(description='MCP Server Orchestrator v2')
    parser.add_argument('action', choices=['start', 'stop', 'restart', 'status', 'monitor', 'reset'],
                        help='Action to perform')
    parser.add_argument('--server', help='Specific server name (for start/stop/restart/reset)')
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
                    time.sleep(30)
                    orchestrator.print_status()
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

    elif args.action == 'reset':
        if args.server:
            orchestrator.reset_server_limits(args.server)
        else:
            for name in orchestrator.servers:
                orchestrator.reset_server_limits(name)
            print("Reset all server limits")

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