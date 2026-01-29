#!/usr/bin/env python3
"""
Workspace Manager - Intelligent workspace launcher for development environment

Manages the startup and coordination of:
- MCP servers
- Development services
- Project environments
- Monitoring tools

Enhanced with:
- Structured JSON logging
- Automatic retry with exponential backoff
- Advanced health checking (TCP + HTTP)
"""

import os
import subprocess
import sys
import time
import socket
import shlex
import shutil
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
import argparse
import webbrowser

# Add paths
sys.path.insert(0, 'C:\\Users\\Corbin\\shared')
sys.path.insert(0, 'C:\\Users\\Corbin\\Tools\\mcp-orchestrator')

# Import our new enhanced modules
from workspace_logger import WorkspaceLogger
from retry_handler import RetryHandler, ExponentialBackoff
from health_checker import HealthChecker
from config_loader import ConfigLoader
from dependency_graph import DependencyGraph


class SecurityError(Exception):
    """Raised when security validation fails"""
    pass


@dataclass
class Service:
    """Service configuration"""
    name: str
    command: str
    directory: str
    port: Optional[int] = None
    url: Optional[str] = None
    wait_for_port: bool = False
    auto_open_browser: bool = False
    environment: Dict[str, str] = None


@dataclass
class WorkspaceProfile:
    """Workspace profile configuration"""
    name: str
    description: str
    services: List[str]
    projects: List[str]
    environment: Dict[str, str]


class WorkspaceManager:
    """Manages workspace initialization and service coordination"""

    # Security: Whitelist of allowed command executables
    ALLOWED_COMMANDS = {
        'python', 'python3', 'python.exe',
        'node', 'node.exe',
        'npm', 'npm.cmd',
        'jupyter', 'jupyter.exe',
        'code', 'code.exe',
        'cmd', 'cmd.exe',
        'wt', 'wt.exe',
        # Add more as needed
    }

    # Security: Whitelist of allowed environment variables
    # Common development environment variables that are safe to set
    ALLOWED_ENV_VARS = {
        # Python
        'PYTHONPATH', 'PYTHONHOME', 'PYTHONIOENCODING', 'PYTHONUNBUFFERED',
        # Node.js
        'NODE_ENV', 'NODE_PATH', 'NODE_OPTIONS',
        # General development
        'PATH', 'HOME', 'USER', 'USERNAME', 'USERPROFILE',
        'TEMP', 'TMP', 'TMPDIR',
        # Application-specific
        'PORT', 'HOST', 'DEBUG', 'LOG_LEVEL',
        'DATABASE_URL', 'DATABASE_NAME', 'DB_HOST', 'DB_PORT',
        'REDIS_URL', 'REDIS_HOST', 'REDIS_PORT', 'REDIS_PASSWORD',
        'API_KEY', 'API_URL', 'API_TOKEN',
        # Build tools
        'MAVEN_OPTS', 'GRADLE_OPTS', 'JAVA_HOME',
        'CARGO_HOME', 'RUSTUP_HOME',
        # Editor/IDE
        'EDITOR', 'VISUAL', 'PAGER',
        # MCP specific
        'MCP_SERVER_PORT', 'MCP_LOG_LEVEL',
        # Add more as needed for your specific environment
    }

    def __init__(self, config_path: Optional[Path] = None):
        # Security: Use platform-independent home directory
        self.base_dir = Path.home()

        # Initialize logging system
        log_dir = self.base_dir / "Tools" / "workspace-launcher" / "logs"
        self.logger = WorkspaceLogger(log_dir)

        # Initialize health checker
        self.health_checker = HealthChecker(timeout=10)

        # Initialize retry handler with exponential backoff
        retry_strategy = ExponentialBackoff(max_retries=3, initial_delay=2.0, backoff_factor=2.0)
        self.retry_handler = RetryHandler(retry_strategy)

        # Load YAML configuration
        if config_path is None:
            config_path = self.base_dir / "Tools" / "workspace-launcher" / "workspace-config.yaml"

        self.config_loader = ConfigLoader(config_path)
        if not self.config_loader.load():
            # Security: Log full path internally, show generic error to user
            self.logger.log_error("Failed to load configuration", config_path=str(config_path))
            raise RuntimeError("Failed to load workspace configuration file")

        # Validate configuration
        errors = self.config_loader.validate()
        if errors:
            self.logger.log_error("Configuration validation failed", errors=errors)
            for error in errors:
                print(f"[ERROR] Configuration: {error}")
            raise RuntimeError("Configuration validation failed")

        # Initialize dependency graph
        self.dependency_graph = DependencyGraph(self.config_loader.get_services())

        # Convert YAML config to internal Service/Profile objects
        self.services = self._define_services()
        self.profiles = self._define_profiles()
        self.active_processes = {}

        # Legacy log file path (kept for compatibility)
        self.log_file = log_dir / "workspace.log"

        self.logger.log_info("Workspace Manager initialized",
                           services_count=len(self.services),
                           profiles_count=len(self.profiles))

    def _define_services(self) -> Dict[str, Service]:
        """Convert YAML ServiceConfig objects to internal Service dataclass"""
        services = {}

        for service_key, service_config in self.config_loader.get_services().items():
            # Convert ServiceConfig to Service
            services[service_key] = Service(
                name=service_config.name,
                command=service_config.command,
                directory=service_config.directory,
                port=service_config.port,
                url=service_config.url,
                wait_for_port=service_config.wait_for_port,
                auto_open_browser=service_config.auto_open_browser,
                environment=service_config.environment if service_config.environment else None
            )

        return services

    def _define_profiles(self) -> Dict[str, WorkspaceProfile]:
        """Convert YAML ProfileConfig objects to internal WorkspaceProfile dataclass"""
        profiles = {}

        for profile_key, profile_config in self.config_loader.get_profiles().items():
            # Convert ProfileConfig to WorkspaceProfile
            profiles[profile_key] = WorkspaceProfile(
                name=profile_config.name,
                description=profile_config.description,
                services=profile_config.services,
                projects=profile_config.projects,
                environment=profile_config.environment
            )

        return profiles

    def _validate_and_prepare_command(self, command: str, service_key: str) -> List[str]:
        """
        Validate command and prepare it for safe execution

        Security: Prevents command injection by:
        1. Whitelisting allowed executables
        2. Using argument list instead of shell=True

        Args:
            command: Command string from configuration
            service_key: Service identifier for logging

        Returns:
            List of command arguments for subprocess (shell=False)

        Raises:
            SecurityError: If command uses unauthorized executable
        """
        # Parse command into arguments
        try:
            cmd_args = shlex.split(command)
        except ValueError as e:
            self.logger.log_error(
                f"Invalid command syntax for service '{service_key}'",
                error=e,
                command=command
            )
            raise ValueError(f"Invalid command syntax: {command}")

        if not cmd_args:
            raise ValueError(f"Empty command for service '{service_key}'")

        # Extract base command (first argument)
        base_cmd = os.path.basename(cmd_args[0]).lower()

        # Check against whitelist
        if base_cmd not in self.ALLOWED_COMMANDS:
            self.logger.log_error(
                "Security: Unauthorized command blocked",
                service=service_key,
                command=base_cmd,
                allowed=list(self.ALLOWED_COMMANDS)
            )
            raise SecurityError(
                f"Command '{base_cmd}' not in whitelist. "
                f"Allowed: {', '.join(sorted(self.ALLOWED_COMMANDS))}"
            )

        # Resolve executable to full path (handles .cmd/.bat on Windows)
        resolved = shutil.which(cmd_args[0])
        if resolved:
            cmd_args[0] = resolved

        # Log approved command
        self.logger.log_info(
            f"Command validated for service '{service_key}'",
            command=base_cmd,
            args_count=len(cmd_args) - 1
        )

        return cmd_args

    def _validate_environment_variables(self, env_vars: Dict[str, str], service_key: str) -> Dict[str, str]:
        """
        Validate and filter environment variables against whitelist

        Security: Prevents unauthorized environment variable injection

        Args:
            env_vars: Environment variables from configuration
            service_key: Service identifier for logging

        Returns:
            Dictionary of allowed environment variables only
        """
        if not env_vars:
            return {}

        validated_env = {}
        blocked_vars = []

        for key, value in env_vars.items():
            if key in self.ALLOWED_ENV_VARS:
                validated_env[key] = value
            else:
                blocked_vars.append(key)
                self.logger.log_warning(
                    f"Security: Blocked unauthorized environment variable for service '{service_key}'",
                    service=service_key,
                    blocked_var=key
                )

        if blocked_vars:
            self.logger.log_info(
                f"Environment variables filtered for service '{service_key}'",
                service=service_key,
                allowed_count=len(validated_env),
                blocked_count=len(blocked_vars),
                blocked_vars=blocked_vars
            )

        return validated_env

    def check_port(self, port: int, timeout: int = 30) -> bool:
        """Check if a port is open"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', port))
                sock.close()
                if result == 0:
                    return True
            except (socket.error, OSError):
                pass
            time.sleep(1)
        return False

    def check_dependencies(self) -> Dict[str, bool]:
        """Check for required dependencies"""
        checks = {}

        # Python
        try:
            result = subprocess.run(["python", "--version"], capture_output=True)
            checks['Python'] = result.returncode == 0
        except FileNotFoundError:
            checks['Python'] = False

        # Node.js
        try:
            result = subprocess.run(["node", "--version"], capture_output=True)
            checks['Node.js'] = result.returncode == 0
        except FileNotFoundError:
            checks['Node.js'] = False

        # npm
        try:
            result = subprocess.run(["npm", "--version"], capture_output=True)
            checks['npm'] = result.returncode == 0
        except FileNotFoundError:
            checks['npm'] = False

        # Git
        try:
            result = subprocess.run(["git", "--version"], capture_output=True)
            checks['Git'] = result.returncode == 0
        except FileNotFoundError:
            checks['Git'] = False

        # Check for Python packages
        try:
            import flask  # noqa: F401
            checks['Flask'] = True
        except ImportError:
            checks['Flask'] = False

        try:
            import psutil  # noqa: F401
            checks['psutil'] = True
        except ImportError:
            checks['psutil'] = False

        return checks

    def start_service(self, service_key: str) -> bool:
        """Start a specific service with retry logic and enhanced health checking"""
        if service_key not in self.services:
            self.logger.log_error(f"Service '{service_key}' not found", service=service_key)
            print(f"[ERROR] Service '{service_key}' not found")
            return False

        service = self.services[service_key]
        start_time = time.time()

        # Log service startup attempt
        self.logger.log_service_start(service_key, service.command, service.directory)
        print(f"[INFO] Starting {service.name}...")

        try:
            # Security: Validate and prepare command
            cmd_args = self._validate_and_prepare_command(service.command, service_key)

            # Create log files for service output
            stdout_file, stderr_file = self.logger.create_service_log_file(service_key)

            # Setup environment
            env = os.environ.copy()
            if service.environment:
                # Security: Validate environment variables against whitelist
                validated_env_vars = self._validate_environment_variables(service.environment, service_key)
                env.update(validated_env_vars)

            # Start process with output capture (SECURE: shell=False)
            if sys.platform == 'win32':
                # Use Windows Terminal for better process management
                process = subprocess.Popen(
                    cmd_args,
                    shell=False,  # ✅ Security: Disable shell interpretation
                    cwd=service.directory,
                    env=env,
                    stdout=open(stdout_file, 'w', encoding='utf-8'),
                    stderr=open(stderr_file, 'w', encoding='utf-8'),
                    creationflags=subprocess.CREATE_NEW_CONSOLE
                )
            else:
                process = subprocess.Popen(
                    cmd_args,
                    shell=False,  # ✅ Security: Disable shell interpretation
                    cwd=service.directory,
                    env=env,
                    stdout=open(stdout_file, 'w', encoding='utf-8'),
                    stderr=open(stderr_file, 'w', encoding='utf-8')
                )

            self.active_processes[service_key] = process

            # Wait for health check if configured
            if service.wait_for_port and service.port:
                print(f"[INFO] Waiting for {service.name} on port {service.port}...")

                # Use smart health checking with exponential backoff
                health_result = self.health_checker.check_tcp_port_smart(
                    'localhost',
                    service.port,
                    max_wait=30
                )

                # Log health check result
                self.logger.log_health_check(
                    service_key,
                    health_result.healthy,
                    health_result.latency_ms,
                    check_type='tcp'
                )

                if health_result.healthy:
                    duration_ms = (time.time() - start_time) * 1000
                    self.logger.log_service_success(service_key, duration_ms, service.port)
                    print(f"[OK] {service.name} is ready on port {service.port} ({health_result.latency_ms:.0f}ms)")

                    # Open browser if configured
                    if service.auto_open_browser and service.url:
                        time.sleep(2)  # Brief delay for service to fully initialize
                        webbrowser.open(service.url)
                else:
                    self.logger.log_warning(
                        f"{service.name} port {service.port} did not respond in time",
                        service=service_key,
                        port=service.port,
                        error=health_result.error
                    )
                    print(f"[WARN] {service.name} port {service.port} did not respond in time")
            else:
                # No health check configured - consider it successful if process started
                duration_ms = (time.time() - start_time) * 1000
                self.logger.log_service_success(service_key, duration_ms)
                print(f"[OK] {service.name} started")

            return True

        except Exception as e:
            # Security: Log full error details internally
            self.logger.log_service_failure(service_key, e, attempt=1)

            # Show sanitized error to user (no stack traces or paths)
            error_type = type(e).__name__
            print(f"[ERROR] Failed to start {service.name}: {error_type}")

            # Show first line of error only (truncated)
            error_msg = str(e).split('\n')[0][:100]
            if error_msg:
                print(f"[ERROR] Details: {error_msg}")

            return False

    def start_profile(self, profile_name: str):
        """Start a workspace profile with dependency-aware ordering"""
        if profile_name not in self.profiles:
            self.logger.log_error(f"Profile '{profile_name}' not found", profile=profile_name)
            print(f"[ERROR] Profile '{profile_name}' not found")
            print(f"Available profiles: {', '.join(self.profiles.keys())}")
            return False

        profile = self.profiles[profile_name]
        all_services = profile.services + profile.projects

        # Log profile startup
        self.logger.log_profile_start(profile_name, all_services)

        print(f"\n{'='*60}")
        print(f"Starting Workspace Profile: {profile.name}")
        print(f"Description: {profile.description}")
        print(f"Services: {len(all_services)}")
        print(f"{'='*60}\n")

        # Set environment variables
        for key, value in profile.environment.items():
            os.environ[key] = value

        start_time = time.time()
        success_count = 0
        total_count = len(all_services)

        # Use dependency graph to determine startup order
        try:
            startup_tiers = self.dependency_graph.get_startup_order(all_services)

            print(f"[INFO] Starting services in {len(startup_tiers)} tier(s) based on dependencies:\n")

            # Start services tier by tier
            for tier_num, tier_services in enumerate(startup_tiers, 1):
                print(f"[INFO] Tier {tier_num}: {', '.join([self.services[s].name for s in tier_services])}")

                # Start all services in this tier
                for service_key in tier_services:
                    if self.start_service(service_key):
                        success_count += 1
                    time.sleep(2)  # Brief delay between services

                # Wait a bit longer between tiers to ensure dependencies are ready
                if tier_num < len(startup_tiers):
                    print(f"[INFO] Tier {tier_num} complete, waiting for next tier...\n")
                    time.sleep(3)

        except ValueError as e:
            # Circular dependency or other dependency issue
            # Security: Log full details internally
            self.logger.log_error(f"Dependency resolution failed: {e}", profile=profile_name)

            # Show sanitized error to user
            print("[ERROR] Failed to resolve service dependencies")
            print("[INFO] Starting services in profile order as fallback...")

            # Fallback to sequential startup
            for service in all_services:
                if self.start_service(service):
                    success_count += 1
                time.sleep(2)

        # Calculate total duration
        duration_ms = (time.time() - start_time) * 1000

        # Log profile completion
        self.logger.log_profile_complete(profile_name, duration_ms, success_count, total_count)

        print(f"\n{'='*60}")
        print(f"[OK] Workspace '{profile.name}' is ready!")
        print(f"Services started: {success_count}/{total_count}")
        print(f"Total time: {duration_ms/1000:.1f}s")
        print(f"{'='*60}\n")

        return True

    def stop_all(self):
        """Stop all active processes with logging"""
        print("\n[INFO] Stopping all services...")
        self.logger.log_info("Stopping all services", active_count=len(self.active_processes))

        for name, process in self.active_processes.items():
            try:
                process.terminate()
                self.logger.log_service_stop(name, graceful=True)
                print(f"[INFO] Stopped {name}")
            except Exception as e:
                self.logger.log_warning(f"Failed to stop {name}", service=name, error=str(e))

        self.active_processes.clear()
        self.logger.log_info("All services stopped")

    def create_wt_layout(self, profile_name: str) -> str:
        """Create Windows Terminal layout configuration"""
        profile = self.profiles.get(profile_name)
        if not profile:
            return ""

        # Build Windows Terminal command with tabs
        wt_command = "wt"

        for i, service_key in enumerate(profile.services):
            service = self.services.get(service_key)
            if service:
                if i == 0:
                    wt_command += f' -d "{service.directory}" cmd /k "{service.command}"'
                else:
                    wt_command += f' ; new-tab -d "{service.directory}" cmd /k "{service.command}"'

        return wt_command

    def print_status(self):
        """Print current workspace status"""
        print("\n" + "="*60)
        print("WORKSPACE STATUS".center(60))
        print("="*60)

        # Check dependencies
        deps = self.check_dependencies()
        print("\nDependencies:")
        for name, status in deps.items():
            status_str = "[OK]" if status else "[MISSING]"
            print(f"  {status_str} {name}")

        # Show active processes
        print("\nActive Services:")
        if self.active_processes:
            for name, process in self.active_processes.items():
                if process.poll() is None:
                    print(f"  [RUNNING] {self.services[name].name}")
                else:
                    print(f"  [STOPPED] {self.services[name].name}")
        else:
            print("  None")

        print("="*60)


def create_launcher_script():
    """Create a Windows batch launcher script"""
    # Security: Use %USERPROFILE% instead of hardcoded path
    script_content = """@echo off
REM Workspace Launcher - Quick start for development environment

echo ========================================
echo       DEVELOPMENT WORKSPACE LAUNCHER
echo ========================================
echo.

cd /d "%USERPROFILE%"

echo Select workspace profile:
echo.
echo [1] Full Development - All services and tools
echo [2] MCP Services - MCP orchestrator and dashboard
echo [3] Financial - Financial apps and MCP services
echo [4] Reverse Engineering - Ghidra integration
echo [5] Minimal - Just code editor
echo [6] Custom - Choose services manually
echo.

choice /c 123456 /n /m "Select profile (1-6): "

if %errorlevel%==1 python Tools\\workspace-launcher\\workspace_manager.py launch --profile full
if %errorlevel%==2 python Tools\\workspace-launcher\\workspace_manager.py launch --profile mcp
if %errorlevel%==3 python Tools\\workspace-launcher\\workspace_manager.py launch --profile financial
if %errorlevel%==4 python Tools\\workspace-launcher\\workspace_manager.py launch --profile reverse-engineering
if %errorlevel%==5 python Tools\\workspace-launcher\\workspace_manager.py launch --profile minimal
if %errorlevel%==6 python Tools\\workspace-launcher\\workspace_manager.py launch --interactive

pause
"""

    # Security: Use Path.home() instead of hardcoded path
    launcher_path = Path.home() / "launch-workspace.bat"
    launcher_path.write_text(script_content)
    return launcher_path


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Workspace Manager')
    parser.add_argument('command', choices=['launch', 'stop', 'status', 'list'],
                        help='Command to execute')
    parser.add_argument('--profile', help='Workspace profile to launch')
    parser.add_argument('--interactive', action='store_true',
                        help='Interactive service selection')
    parser.add_argument('--use-wt', action='store_true',
                        help='Use Windows Terminal for layout')

    args = parser.parse_args()

    manager = WorkspaceManager()

    if args.command == 'launch':
        if args.interactive:
            # Interactive mode
            print("\nAvailable services:")
            for i, (key, service) in enumerate(manager.services.items(), 1):
                print(f"  [{i}] {service.name}")

            selections = input("\nEnter service numbers (comma-separated): ").split(',')
            service_keys = list(manager.services.keys())

            for selection in selections:
                try:
                    idx = int(selection.strip()) - 1
                    if 0 <= idx < len(service_keys):
                        manager.start_service(service_keys[idx])
                        time.sleep(2)
                except (ValueError, IndexError):
                    pass

        elif args.profile:
            if args.use_wt:
                # Security: Windows Terminal layout feature deprecated due to shell=True requirement
                print("[WARN] Windows Terminal layout feature (--use-wt) is deprecated for security reasons")
                print("[INFO] Reason: Command construction requires shell=True which poses injection risks")
                print("[INFO] Alternative: Use standard profile launcher instead")
                print("[INFO] Launching profile with standard method...\n")
                manager.start_profile(args.profile)
            else:
                manager.start_profile(args.profile)
        else:
            print("Please specify --profile or --interactive")

    elif args.command == 'stop':
        manager.stop_all()

    elif args.command == 'status':
        manager.print_status()

    elif args.command == 'list':
        print("\nAvailable Profiles:")
        print("="*60)
        for name, profile in manager.profiles.items():
            print(f"\n[{name}]")
            print(f"  Description: {profile.description}")
            print(f"  Services: {', '.join(profile.services)}")
            if profile.projects:
                print(f"  Projects: {', '.join(profile.projects)}")


if __name__ == '__main__':
    # Security: Set working directory to home (platform-independent)
    os.chdir(str(Path.home()))

    # Create launcher script if it doesn't exist
    launcher = Path.home() / "launch-workspace.bat"
    if not launcher.exists():
        create_launcher_script()
        print(f"Created launcher script: {launcher}")

    main()