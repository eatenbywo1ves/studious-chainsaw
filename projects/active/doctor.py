#!/usr/bin/env python3
"""
System Health Diagnostic Tool (Doctor)
Comprehensive health check for the development environment
"""

import os
import sys
import json
import subprocess
import psutil
from pathlib import Path
from datetime import datetime

# Add shared libraries to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir / "shared" / "libraries"))
sys.path.insert(0, str(current_dir / "shared" / "utilities"))


class SystemDoctor:
    def __init__(self):
        self.base_path = Path(__file__).parent
        self.health_status = {
            "timestamp": datetime.now().isoformat(),
            "overall": "HEALTHY",
            "checks": {},
            "issues": [],
            "recommendations": [],
        }

    def run_diagnostics(self):
        """Run all diagnostic checks"""
        print("\n" + "=" * 60)
        print("SYSTEM HEALTH DIAGNOSTIC (DOCTOR)")
        print("=" * 60)

        # System checks
        self.check_python_environment()
        self.check_node_environment()
        self.check_directory_structure()
        self.check_configurations()
        self.check_agents()
        self.check_mcp_servers()
        self.check_logs()
        self.check_memory_usage()
        self.check_disk_space()
        self.check_network()

        # Generate report
        self.generate_report()

    def check_python_environment(self):
        """Check Python environment health"""
        print("\n[CHECK] Checking Python Environment...")
        check_name = "python_environment"

        try:
            python_version = sys.version.split()[0]
            pip_version = subprocess.check_output(
                ["pip", "--version"], text=True
            ).split()[1]

            # Check if shared libraries are accessible
            shared_libs_ok = all(
                [
                    (self.base_path / "shared" / "libraries").exists(),
                    (self.base_path / "shared" / "utilities").exists(),
                ]
            )

            # Check for required packages
            required_packages = ["psutil", "redis", "asyncio", "aiohttp"]
            missing_packages = []

            for package in required_packages:
                try:
                    __import__(package)
                except ImportError:
                    missing_packages.append(package)

            status = "HEALTHY" if not missing_packages and shared_libs_ok else "WARNING"

            self.health_status["checks"][check_name] = {
                "status": status,
                "python_version": python_version,
                "pip_version": pip_version,
                "shared_libs": "OK" if shared_libs_ok else "MISSING",
                "missing_packages": missing_packages,
            }

            if missing_packages:
                self.health_status["issues"].append(
                    f"Missing Python packages: {', '.join(missing_packages)}"
                )
                self.health_status["recommendations"].append(
                    f"Run: pip install {' '.join(missing_packages)}"
                )

            print(f"  [OK] Python {python_version}")
            print(f"  [OK] Pip {pip_version}")
            print(f"  {'[OK]' if shared_libs_ok else '[FAIL]'} Shared libraries")

        except Exception as e:
            self.health_status["checks"][check_name] = {
                "status": "ERROR",
                "error": str(e),
            }
            self.health_status["issues"].append(f"Python environment check failed: {e}")
            print(f"  [FAIL] Error: {e}")

    def check_node_environment(self):
        """Check Node.js environment health"""
        print("\n[CHECK] Checking Node.js Environment...")
        check_name = "node_environment"

        try:
            # Use shell=True on Windows for proper PATH resolution
            node_version = subprocess.check_output(
                "node --version", shell=True, text=True
            ).strip()
            npm_version = subprocess.check_output(
                "npm --version", shell=True, text=True
            ).strip()

            # Check NODE_OPTIONS
            node_options = os.environ.get("NODE_OPTIONS", "")
            heap_size_ok = "--max-old-space-size" in node_options

            # Check for node_modules
            node_modules_exists = (self.base_path.parent / "node_modules").exists()

            # Check for running Node processes
            node_processes = []
            for proc in psutil.process_iter(["pid", "name", "memory_info"]):
                if "node" in proc.info["name"].lower():
                    node_processes.append(
                        {
                            "pid": proc.info["pid"],
                            "memory_mb": proc.info["memory_info"].rss / 1024 / 1024,
                        }
                    )

            status = "HEALTHY" if heap_size_ok else "WARNING"

            self.health_status["checks"][check_name] = {
                "status": status,
                "node_version": node_version,
                "npm_version": npm_version,
                "node_options": node_options or "NOT SET",
                "heap_configured": heap_size_ok,
                "node_modules": "EXISTS" if node_modules_exists else "MISSING",
                "running_processes": len(node_processes),
            }

            if not heap_size_ok:
                self.health_status["recommendations"].append(
                    'Run: export NODE_OPTIONS="--max-old-space-size=4096"'
                )

            print(f"  [OK] Node.js {node_version}")
            print(f"  [OK] NPM {npm_version}")
            print(f"  {'[OK]' if heap_size_ok else '[WARN]'} Heap size configuration")
            print(f"  [INFO] {len(node_processes)} Node processes running")

        except Exception as e:
            self.health_status["checks"][check_name] = {
                "status": "ERROR",
                "error": str(e),
            }
            self.health_status["issues"].append(
                f"Node.js environment check failed: {e}"
            )
            print(f"  [FAIL] Error: {e}")

    def check_directory_structure(self):
        """Check directory structure integrity"""
        print("\n[CHECK] Checking Directory Structure...")
        check_name = "directory_structure"

        required_dirs = [
            "agents/production",
            "agents/experimental",
            "mcp-servers/financial",
            "mcp-servers/utilities",
            "configs/mcp",
            "configs/agents",
            "shared/libraries",
            "shared/utilities",
            "logs/system",
            "logs/services",
        ]

        missing_dirs = []
        for dir_path in required_dirs:
            full_path = self.base_path / dir_path
            if not full_path.exists():
                missing_dirs.append(dir_path)

        status = "HEALTHY" if not missing_dirs else "WARNING"

        self.health_status["checks"][check_name] = {
            "status": status,
            "required_dirs": len(required_dirs),
            "missing_dirs": missing_dirs,
        }

        if missing_dirs:
            self.health_status["issues"].append(
                f"Missing directories: {', '.join(missing_dirs)}"
            )
            self.health_status["recommendations"].append("Run: python initialize.py")

        status_text = '[OK]' if not missing_dirs else '[WARN]'
        dirs_present = len(required_dirs) - len(missing_dirs)
        total_dirs = len(required_dirs)
        print(f"  {status_text} {dirs_present}/{total_dirs} directories present")

    def check_configurations(self):
        """Check configuration files"""
        print("\n[CHECK] Checking Configurations...")
        check_name = "configurations"

        try:
            from config_manager import ConfigManager

            config_manager = ConfigManager()

            mcp_configs = config_manager.list_configs("mcp")
            agent_configs = config_manager.list_configs("agents")

            # Check Claude configurations
            claude_configs = []
            for config in mcp_configs:
                if "claude" in config.lower():
                    claude_configs.append(config)

            status = "HEALTHY" if mcp_configs else "WARNING"

            self.health_status["checks"][check_name] = {
                "status": status,
                "mcp_configs": len(mcp_configs),
                "agent_configs": len(agent_configs),
                "claude_configs": len(claude_configs),
            }

            print(f"  [OK] {len(mcp_configs)} MCP configurations")
            print(f"  [OK] {len(agent_configs)} Agent configurations")
            print(f"  [OK] {len(claude_configs)} Claude configurations")

        except Exception as e:
            self.health_status["checks"][check_name] = {
                "status": "ERROR",
                "error": str(e),
            }
            self.health_status["issues"].append(f"Configuration check failed: {e}")
            print(f"  ❌ Error: {e}")

    def check_agents(self):
        """Check agent registry"""
        print("\n[CHECK] Checking Agents...")
        check_name = "agents"

        try:
            from agent_registry import AgentRegistry

            registry = AgentRegistry()
            agents = registry.list_agents()

            active_agents = [
                a
                for a in agents
                if hasattr(a, "status")
                and str(getattr(a, "status", "")).lower() in ["active", "experimental"]
            ]

            self.health_status["checks"][check_name] = {
                "status": "HEALTHY" if agents else "WARNING",
                "total_agents": len(agents),
                "active_agents": len(active_agents),
                "agent_names": [a.name for a in agents],
            }

            print(f"  [OK] {len(agents)} agents registered")
            print(f"  [OK] {len(active_agents)} active/experimental")

        except Exception as e:
            self.health_status["checks"][check_name] = {
                "status": "ERROR",
                "error": str(e),
            }
            self.health_status["issues"].append(f"Agent check failed: {e}")
            print(f"  ❌ Error: {e}")

    def check_mcp_servers(self):
        """Check MCP server registry"""
        print("\n[CHECK] Checking MCP Servers...")
        check_name = "mcp_servers"

        try:
            from mcp_registry import MCPRegistry

            registry = MCPRegistry()
            servers = registry.list_servers()

            self.health_status["checks"][check_name] = {
                "status": "HEALTHY" if servers else "WARNING",
                "total_servers": len(servers),
                "server_names": [s.name for s in servers],
            }

            print(f"  [OK] {len(servers)} MCP servers registered")

        except Exception as e:
            self.health_status["checks"][check_name] = {
                "status": "ERROR",
                "error": str(e),
            }
            self.health_status["issues"].append(f"MCP server check failed: {e}")
            print(f"  ❌ Error: {e}")

    def check_logs(self):
        """Check logging system"""
        print("\n[CHECK] Checking Logs...")
        check_name = "logging"

        log_dirs = ["logs/system", "logs/services", "logs/agents", "logs/mcp"]
        log_files = []

        for log_dir in log_dirs:
            log_path = self.base_path / log_dir
            if log_path.exists():
                log_files.extend(list(log_path.glob("*.log")))

        # Check for recent errors in logs
        recent_errors = 0
        if log_files:
            latest_log = max(
                log_files, key=lambda f: f.stat().st_mtime if f.exists() else 0
            )
            if latest_log.exists():
                with open(latest_log, "r") as f:
                    for line in f.readlines()[-100:]:  # Check last 100 lines
                        if '"level": "ERROR"' in line:
                            recent_errors += 1

        status = "HEALTHY" if recent_errors == 0 else "WARNING"

        self.health_status["checks"][check_name] = {
            "status": status,
            "log_files": len(log_files),
            "recent_errors": recent_errors,
        }

        print(f"  [OK] {len(log_files)} log files")
        print(
            f"  {'[OK]' if recent_errors == 0 else '[WARN]'} {recent_errors} recent errors"
        )

    def check_memory_usage(self):
        """Check system memory usage"""
        print("\n[CHECK] Checking Memory Usage...")
        check_name = "memory"

        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()

        memory_percent = memory.percent
        status = (
            "HEALTHY"
            if memory_percent < 80
            else "WARNING" if memory_percent < 90 else "CRITICAL"
        )

        self.health_status["checks"][check_name] = {
            "status": status,
            "ram_percent": memory_percent,
            "ram_available_gb": round(memory.available / (1024**3), 2),
            "ram_total_gb": round(memory.total / (1024**3), 2),
            "swap_percent": swap.percent,
        }

        if memory_percent > 80:
            self.health_status["issues"].append(f"High memory usage: {memory_percent}%")
            self.health_status["recommendations"].append(
                "Consider closing unnecessary applications"
            )

        print(
            f"  {'[OK]' if memory_percent < 80 else '[WARN]'} RAM: {memory_percent:.1f}% used"
        )
        print(
            f"  [INFO] Available: {memory.available / (1024**3):.1f}GB / {memory.total / (1024**3):.1f}GB"
        )

    def check_disk_space(self):
        """Check disk space"""
        print("\n[CHECK] Checking Disk Space...")
        check_name = "disk_space"

        disk = psutil.disk_usage(str(self.base_path))
        disk_percent = disk.percent

        status = (
            "HEALTHY"
            if disk_percent < 80
            else "WARNING" if disk_percent < 90 else "CRITICAL"
        )

        self.health_status["checks"][check_name] = {
            "status": status,
            "percent_used": disk_percent,
            "free_gb": round(disk.free / (1024**3), 2),
            "total_gb": round(disk.total / (1024**3), 2),
        }

        if disk_percent > 80:
            self.health_status["issues"].append(f"Low disk space: {disk_percent}% used")
            self.health_status["recommendations"].append("Free up disk space")

        print(
            f"  {'[OK]' if disk_percent < 80 else '[WARN]'} Disk: {disk_percent:.1f}% used"
        )
        print(
            f"  [INFO] Free: {disk.free / (1024**3):.1f}GB / {disk.total / (1024**3):.1f}GB"
        )

    def check_network(self):
        """Check network connectivity"""
        print("\n[CHECK] Checking Network...")
        check_name = "network"

        try:
            import socket

            # Try to resolve a common hostname
            socket.gethostbyname("google.com")
            network_ok = True
        except Exception:
            network_ok = False

        self.health_status["checks"][check_name] = {
            "status": "HEALTHY" if network_ok else "WARNING",
            "connectivity": "OK" if network_ok else "OFFLINE",
        }

        print(f"  {'[OK]' if network_ok else '[WARN]'} Network connectivity")

    def generate_report(self):
        """Generate final health report"""

        # Determine overall health
        critical_count = sum(
            1
            for check in self.health_status["checks"].values()
            if check.get("status") == "CRITICAL"
        )
        error_count = sum(
            1
            for check in self.health_status["checks"].values()
            if check.get("status") == "ERROR"
        )
        warning_count = sum(
            1
            for check in self.health_status["checks"].values()
            if check.get("status") == "WARNING"
        )

        if critical_count > 0 or error_count > 0:
            self.health_status["overall"] = "CRITICAL"
            emoji = "[CRITICAL]"
        elif warning_count > 0:
            self.health_status["overall"] = "WARNING"
            emoji = "[WARNING]"
        else:
            self.health_status["overall"] = "HEALTHY"
            emoji = "[HEALTHY]"

        # Print summary
        print("\n" + "=" * 60)
        print(f"{emoji} OVERALL HEALTH: {self.health_status['overall']}")
        print("=" * 60)

        if self.health_status["issues"]:
            print("\n[!] ISSUES FOUND:")
            for issue in self.health_status["issues"]:
                print(f"  • {issue}")

        if self.health_status["recommendations"]:
            print("\n[i] RECOMMENDATIONS:")
            for rec in self.health_status["recommendations"]:
                print(f"  • {rec}")

        # Save report to file
        report_file = self.base_path / "logs" / "system" / "health_report.json"
        report_file.parent.mkdir(parents=True, exist_ok=True)

        with open(report_file, "w") as f:
            json.dump(self.health_status, f, indent=2, default=str)

        print(f"\n[REPORT] Full report saved to: {report_file}")

        # Return status code
        if self.health_status["overall"] == "CRITICAL":
            return 2
        elif self.health_status["overall"] == "WARNING":
            return 1
        else:
            return 0


if __name__ == "__main__":
    doctor = SystemDoctor()
    exit_code = doctor.run_diagnostics()
    sys.exit(exit_code)
