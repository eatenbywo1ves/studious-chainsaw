#!/usr/bin/env python3
"""
Workspace Manager - Intelligent workspace launcher for development environment

Manages the startup and coordination of:
- MCP servers
- Development services
- Project environments
- Monitoring tools
"""

import json
import os
import subprocess
import sys
import time
import socket
import psutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import argparse
import webbrowser

# Add paths
sys.path.insert(0, 'C:\\Users\\Corbin\\shared')
sys.path.insert(0, 'C:\\Users\\Corbin\\Tools\\mcp-orchestrator')


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

    def __init__(self):
        self.base_dir = Path("C:\\Users\\Corbin")
        self.services = self._define_services()
        self.profiles = self._define_profiles()
        self.active_processes = {}
        self.log_file = self.base_dir / "Tools" / "workspace-launcher" / "workspace.log"

    def _define_services(self) -> Dict[str, Service]:
        """Define available services"""
        return {
            "mcp-orchestrator": Service(
                name="MCP Orchestrator",
                command="python Tools/mcp-orchestrator/mcp_orchestrator.py monitor",
                directory=str(self.base_dir)
            ),
            "mcp-dashboard": Service(
                name="MCP Dashboard",
                command="python Tools/mcp-orchestrator/dashboard.py",
                directory=str(self.base_dir),
                port=5000,
                url="http://localhost:5000",
                wait_for_port=True,
                auto_open_browser=True
            ),
            "ghidra-bridge": Service(
                name="Ghidra-Claude Bridge",
                command="python ghidra-claude/ghidra_claude_bridge.py",
                directory=str(self.base_dir)
            ),
            "financial-simulator": Service(
                name="Financial Simulator",
                command="npm run dev",
                directory=str(self.base_dir / "projects" / "financial-apps" / "financial-simulator"),
                port=5173,
                url="http://localhost:5173",
                wait_for_port=True
            ),
            "api-gateway": Service(
                name="API Gateway",
                command='python api_gateway.py',
                directory=str(self.base_dir),
                environment={"PYTHONPATH": "C:\\Users\\Corbin\\development\\shared"}
            ),
            "jupyter": Service(
                name="Jupyter Lab",
                command="jupyter lab --no-browser",
                directory=str(self.base_dir / "projects"),
                port=8888,
                url="http://localhost:8888",
                wait_for_port=True
            ),
            "code-server": Service(
                name="VS Code Server",
                command="code . --new-window",
                directory=str(self.base_dir / "projects" / "active")
            )
        }

    def _define_profiles(self) -> Dict[str, WorkspaceProfile]:
        """Define workspace profiles"""
        return {
            "full": WorkspaceProfile(
                name="Full Development",
                description="All services and tools",
                services=["mcp-orchestrator", "mcp-dashboard", "ghidra-bridge", "api-gateway"],
                projects=["financial-simulator"],
                environment={"NODE_ENV": "development", "PYTHONPATH": "C:\\Users\\Corbin\\shared"}
            ),
            "mcp": WorkspaceProfile(
                name="MCP Services Only",
                description="MCP orchestrator and dashboard",
                services=["mcp-orchestrator", "mcp-dashboard"],
                projects=[],
                environment={}
            ),
            "financial": WorkspaceProfile(
                name="Financial Development",
                description="Financial apps and MCP services",
                services=["mcp-orchestrator", "mcp-dashboard"],
                projects=["financial-simulator"],
                environment={"NODE_ENV": "development"}
            ),
            "reverse-engineering": WorkspaceProfile(
                name="Reverse Engineering",
                description="Ghidra integration tools",
                services=["ghidra-bridge"],
                projects=[],
                environment={"GHIDRA_HOME": "C:\\Users\\Corbin\\Downloads\\ghidra-master\\build\\ghidra_12.0_DEV"}
            ),
            "minimal": WorkspaceProfile(
                name="Minimal",
                description="Basic workspace with code editor",
                services=["code-server"],
                projects=[],
                environment={}
            )
        }

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
            except:
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
            import flask
            checks['Flask'] = True
        except:
            checks['Flask'] = False

        try:
            import psutil
            checks['psutil'] = True
        except:
            checks['psutil'] = False

        return checks

    def start_service(self, service_key: str) -> bool:
        """Start a specific service"""
        if service_key not in self.services:
            print(f"[ERROR] Service '{service_key}' not found")
            return False

        service = self.services[service_key]
        print(f"[INFO] Starting {service.name}...")

        try:
            # Setup environment
            env = os.environ.copy()
            if service.environment:
                env.update(service.environment)

            # Start process
            if sys.platform == 'win32':
                # Use Windows Terminal for better process management
                process = subprocess.Popen(
                    service.command,
                    shell=True,
                    cwd=service.directory,
                    env=env,
                    creationflags=subprocess.CREATE_NEW_CONSOLE
                )
            else:
                process = subprocess.Popen(
                    service.command,
                    shell=True,
                    cwd=service.directory,
                    env=env
                )

            self.active_processes[service_key] = process

            # Wait for port if needed
            if service.wait_for_port and service.port:
                print(f"[INFO] Waiting for {service.name} on port {service.port}...")
                if self.check_port(service.port):
                    print(f"[OK] {service.name} is ready on port {service.port}")

                    # Open browser if configured
                    if service.auto_open_browser and service.url:
                        time.sleep(2)  # Brief delay for service to fully initialize
                        webbrowser.open(service.url)
                else:
                    print(f"[WARN] {service.name} port {service.port} did not respond in time")

            return True

        except Exception as e:
            print(f"[ERROR] Failed to start {service.name}: {e}")
            return False

    def start_profile(self, profile_name: str):
        """Start a workspace profile"""
        if profile_name not in self.profiles:
            print(f"[ERROR] Profile '{profile_name}' not found")
            print(f"Available profiles: {', '.join(self.profiles.keys())}")
            return False

        profile = self.profiles[profile_name]
        print(f"\n{'='*60}")
        print(f"Starting Workspace Profile: {profile.name}")
        print(f"Description: {profile.description}")
        print(f"{'='*60}\n")

        # Set environment variables
        for key, value in profile.environment.items():
            os.environ[key] = value

        # Start services
        for service in profile.services:
            self.start_service(service)
            time.sleep(2)  # Stagger service starts

        # Start projects
        for project in profile.projects:
            if project in self.services:
                self.start_service(project)
                time.sleep(2)

        print(f"\n[OK] Workspace '{profile.name}' is ready!")
        return True

    def stop_all(self):
        """Stop all active processes"""
        print("\n[INFO] Stopping all services...")
        for name, process in self.active_processes.items():
            try:
                process.terminate()
                print(f"[INFO] Stopped {name}")
            except:
                pass
        self.active_processes.clear()

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
    script_content = """@echo off
REM Workspace Launcher - Quick start for development environment

echo ========================================
echo       DEVELOPMENT WORKSPACE LAUNCHER
echo ========================================
echo.

cd /d C:\\Users\\Corbin

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

    launcher_path = Path("C:\\Users\\Corbin\\launch-workspace.bat")
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
                except:
                    pass

        elif args.profile:
            if args.use_wt:
                # Use Windows Terminal
                wt_command = manager.create_wt_layout(args.profile)
                if wt_command:
                    subprocess.run(wt_command, shell=True)
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
    # Set working directory
    os.chdir('C:\\Users\\Corbin')

    # Create launcher script if it doesn't exist
    launcher = Path("C:\\Users\\Corbin\\launch-workspace.bat")
    if not launcher.exists():
        create_launcher_script()
        print(f"Created launcher script: {launcher}")

    main()