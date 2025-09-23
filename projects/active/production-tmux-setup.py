#!/usr/bin/env python3
"""
Production TMUX Setup for Workflow Architecture
Creates production-ready tmux sessions for monitoring and operations
"""

from libraries.validation_errors import ValidationErrorHandler
from libraries.input_validation import StringValidator, validate_input
import subprocess
import sys
import logging
from pathlib import Path
from typing import Dict, List, Optional
import argparse

# Add shared directory for validation
sys.path.insert(0, str(Path(__file__).parent / "shared"))


class ProductionTMUXSetup:
    """Setup and manage production tmux sessions"""

    def __init__(self, tmux_cmd: str = "tmux", config_path: Optional[str] = None):
        # Validate tmux command
        cmd_result = validate_input(
            StringValidator.validate_command_string, tmux_cmd, raise_on_error=False
        )
        if not cmd_result.is_valid:
            raise ValueError(f"Invalid tmux command: {cmd_result.error_message}")

        self.tmux_cmd = cmd_result.sanitized_value

        # Validate config path if provided
        if config_path:
            path_result = validate_input(
                lambda p: StringValidator.validate_file_path(p, must_exist=True),
                config_path,
                raise_on_error=False,
            )
            if not path_result.is_valid:
                logging.warning(f"Invalid config path: {path_result.error_message}")
                config_path = str(Path.home() / "development" / ".tmux.conf")

        self.config_path = config_path or str(
            Path.home() / "development" / ".tmux.conf"
        )
        self.base_session = "production-monitor"
        self.logger = logging.getLogger(__name__)
        self.validator = ValidationErrorHandler(self.logger)

    def run_tmux_command(self, args: List[str]) -> subprocess.CompletedProcess:
        """Run tmux command with error handling"""
        cmd = [self.tmux_cmd]
        if self.config_path:
            cmd.extend(["-f", self.config_path])
        cmd.extend(args)

        try:
            return subprocess.run(cmd, capture_output=True, text=True, check=False)
        except Exception as e:
            print(f"Error running tmux command: {e}")
            return subprocess.CompletedProcess(cmd, 1, "", str(e))

    def check_tmux_available(self) -> bool:
        """Check if tmux is available"""
        result = self.run_tmux_command(["-V"])
        return result.returncode == 0

    def session_exists(self, session_name: str) -> bool:
        """Check if tmux session exists"""
        # Validate session name before checking
        session_result = validate_input(
            StringValidator.validate_session_name, session_name, raise_on_error=False
        )

        if not session_result.is_valid:
            self.logger.warning(f"Invalid session name format: {session_name}")
            return False

        result = self.run_tmux_command(
            ["has-session", "-t", session_result.sanitized_value]
        )
        return result.returncode == 0

    def create_production_monitoring_session(self):
        """Create comprehensive production monitoring session"""
        session = "prod-monitor"

        print(f"Creating production monitoring session: {session}")

        # Kill existing session if it exists
        if self.session_exists(session):
            print(f"Killing existing session: {session}")
            self.run_tmux_command(["kill-session", "-t", session])

        # Create main session
        self.run_tmux_command(
            [
                "new-session",
                "-d",
                "-s",
                session,
                "-n",
                "overview",
                "-x",
                "120",
                "-y",
                "40",
                "echo 'Production Workflow Architecture Monitor'",
            ]
        )

        # Window 1: System Overview
        self.run_tmux_command(["new-window", "-t", f"{session}:1", "-n", "system"])

        # Split into 4 panes for system monitoring
        self.run_tmux_command(["split-window", "-h", "-t", f"{session}:system"])
        self.run_tmux_command(["split-window", "-v", "-t", f"{session}:system.0"])
        self.run_tmux_command(["split-window", "-v", "-t", f"{session}:system.1"])

        # System monitoring commands
        system_commands = ["htop -u root", "iostat -x 5", "free -h -s 5", "df -h"]

        for i, cmd in enumerate(system_commands):
            self.run_tmux_command(
                ["send-keys", "-t", f"{session}:system.{i}", cmd, "Enter"]
            )

        # Window 2: Workflow Engine Monitoring
        self.run_tmux_command(["new-window", "-t", f"{session}:2", "-n", "workflows"])

        self.run_tmux_command(["split-window", "-h", "-t", f"{session}:workflows"])
        self.run_tmux_command(["split-window", "-v", "-t", f"{session}:workflows.1"])

        workflow_commands = [
            "watch -n 5 'curl -s http://localhost:8080/metrics | grep workflow'",
            "watch -n 3 'python -c \"from shared.libraries.workflow_engine import get_workflow_engine; import json; print(json.dumps(get_workflow_engine().get_statistics(), indent=2))\"'",
            "tail -f /var/log/workflow-engine/production.log",
        ]

        for i, cmd in enumerate(workflow_commands):
            self.run_tmux_command(
                ["send-keys", "-t", f"{session}:workflows.{i}", cmd, "Enter"]
            )

        # Window 3: Agent Orchestrator
        self.run_tmux_command(["new-window", "-t", f"{session}:3", "-n", "agents"])

        self.run_tmux_command(["split-window", "-h", "-t", f"{session}:agents"])
        self.run_tmux_command(["split-window", "-v", "-t", f"{session}:agents.0"])
        self.run_tmux_command(["split-window", "-v", "-t", f"{session}:agents.1"])

        agent_commands = [
            "watch -n 3 'kubectl get pods -l app=agent -o wide'",
            "watch -n 5 'kubectl top pods -l app=agent'",
            "kubectl logs -l app=agent --tail=50 -f",
            "watch -n 10 'kubectl get hpa -o wide'",
        ]

        for i, cmd in enumerate(agent_commands):
            self.run_tmux_command(
                ["send-keys", "-t", f"{session}:agents.{i}", cmd, "Enter"]
            )

        # Window 4: Message Queue & Redis
        self.run_tmux_command(["new-window", "-t", f"{session}:4", "-n", "messaging"])

        self.run_tmux_command(["split-window", "-h", "-t", f"{session}:messaging"])
        self.run_tmux_command(["split-window", "-v", "-t", f"{session}:messaging.1"])

        messaging_commands = [
            "redis-cli --latency-history -i 5",
            "watch -n 3 'redis-cli info | grep -E \"used_memory_human|connected_clients|total_commands_processed\"'",
            "watch -n 5 'python -c \"from shared.libraries.message_queue import get_message_broker; import json; print(json.dumps(get_message_broker().get_statistics(), indent=2))\"'",
        ]

        for i, cmd in enumerate(messaging_commands):
            self.run_tmux_command(
                ["send-keys", "-t", f"{session}:messaging.{i}", cmd, "Enter"]
            )

        # Window 5: Database Monitoring
        self.run_tmux_command(["new-window", "-t", f"{session}:5", "-n", "database"])

        self.run_tmux_command(["split-window", "-h", "-t", f"{session}:database"])
        self.run_tmux_command(["split-window", "-v", "-t", f"{session}:database.1"])

        db_commands = [
            'watch -n 10 \'psql -h localhost -U postgres -c "SELECT datname,numbackends,xact_commit,xact_rollback,blks_read,blks_hit FROM pg_stat_database WHERE datname NOT IN (\\"template0\\",\\"template1\\");"\'',
            "watch -n 5 'psql -h localhost -U postgres -c \"SELECT schemaname,tablename,n_tup_ins,n_tup_upd,n_tup_del FROM pg_stat_user_tables ORDER BY n_tup_ins DESC LIMIT 10;\"'",
            "tail -f /var/log/postgresql/postgresql-*.log",
        ]

        for i, cmd in enumerate(db_commands):
            self.run_tmux_command(
                ["send-keys", "-t", f"{session}:database.{i}", cmd, "Enter"]
            )

        # Window 6: Network & Security
        self.run_tmux_command(["new-window", "-t", f"{session}:6", "-n", "network"])

        self.run_tmux_command(["split-window", "-h", "-t", f"{session}:network"])
        self.run_tmux_command(["split-window", "-v", "-t", f"{session}:network.0"])
        self.run_tmux_command(["split-window", "-v", "-t", f"{session}:network.1"])

        network_commands = [
            "watch -n 5 'ss -tuln | grep :808'",
            "watch -n 10 'netstat -i'",
            "watch -n 30 'fail2ban-client status'",
            "journalctl -u nginx -f",
        ]

        for i, cmd in enumerate(network_commands):
            self.run_tmux_command(
                ["send-keys", "-t", f"{session}:network.{i}", cmd, "Enter"]
            )

        # Window 7: Alerts & Logs
        self.run_tmux_command(["new-window", "-t", f"{session}:7", "-n", "alerts"])

        self.run_tmux_command(["split-window", "-h", "-t", f"{session}:alerts"])
        self.run_tmux_command(["split-window", "-v", "-t", f"{session}:alerts.1"])

        alert_commands = [
            "tail -f /var/log/syslog | grep -i error",
            'journalctl --since="1 minute ago" -f | grep -E "ERROR|CRITICAL|FATAL"',
            "watch -n 60 'find /var/log -name \"*.log\" -mmin -1 -exec grep -l ERROR {} \\;'",
        ]

        for i, cmd in enumerate(alert_commands):
            self.run_tmux_command(
                ["send-keys", "-t", f"{session}:alerts.{i}", cmd, "Enter"]
            )

        print(f"Production monitoring session '{session}' created successfully!")
        return session

    def create_incident_response_session(self):
        """Create incident response session for troubleshooting"""
        session = "incident-response"

        print(f"Creating incident response session: {session}")

        if self.session_exists(session):
            print(f"Killing existing session: {session}")
            self.run_tmux_command(["kill-session", "-t", session])

        # Create session
        self.run_tmux_command(
            [
                "new-session",
                "-d",
                "-s",
                session,
                "-n",
                "triage",
                "echo 'Incident Response Console - Ready for troubleshooting'",
            ]
        )

        # Window 1: System Diagnostics
        self.run_tmux_command(["new-window", "-t", f"{session}:1", "-n", "diagnostics"])

        self.run_tmux_command(["split-window", "-h", "-t", f"{session}:diagnostics"])

        diagnostic_commands = [
            "echo 'System Diagnostics Ready - use commands like: dmesg, journalctl, ps aux'",
            "echo 'Network Diagnostics Ready - use commands like: netstat, ss, tcpdump'",
        ]

        for i, cmd in enumerate(diagnostic_commands):
            self.run_tmux_command(
                ["send-keys", "-t", f"{session}:diagnostics.{i}", cmd, "Enter"]
            )

        # Window 2: Database Investigation
        self.run_tmux_command(
            [
                "new-window",
                "-t",
                f"{session}:2",
                "-n",
                "database-debug",
                "psql -h localhost -U postgres",
            ]
        )

        # Window 3: Log Investigation
        self.run_tmux_command(
            [
                "new-window",
                "-t",
                f"{session}:3",
                "-n",
                "logs",
                "echo 'Log Investigation - cd /var/log && tail -f specific.log'",
            ]
        )

        # Window 4: Agent Debugging
        self.run_tmux_command(
            [
                "new-window",
                "-t",
                f"{session}:4",
                "-n",
                "agent-debug",
                "kubectl get pods -A",
            ]
        )

        print(f"Incident response session '{session}' created successfully!")
        return session

    def create_deployment_session(self):
        """Create deployment monitoring session"""
        session = "deployment"

        print(f"Creating deployment session: {session}")

        if self.session_exists(session):
            self.run_tmux_command(["kill-session", "-t", session])

        self.run_tmux_command(
            [
                "new-session",
                "-d",
                "-s",
                session,
                "-n",
                "deploy-status",
                "echo 'Deployment Session Ready'",
            ]
        )

        # Window 1: Git & CI/CD
        self.run_tmux_command(["new-window", "-t", f"{session}:1", "-n", "git"])

        self.run_tmux_command(["split-window", "-h", "-t", f"{session}:git"])

        git_commands = [
            "git status",
            "echo 'CI/CD Pipeline Monitor - check Jenkins/GitHub Actions here'",
        ]

        for i, cmd in enumerate(git_commands):
            self.run_tmux_command(
                ["send-keys", "-t", f"{session}:git.{i}", cmd, "Enter"]
            )

        # Window 2: Kubernetes Deployment
        self.run_tmux_command(["new-window", "-t", f"{session}:2", "-n", "k8s-deploy"])

        self.run_tmux_command(["split-window", "-h", "-t", f"{session}:k8s-deploy"])
        self.run_tmux_command(["split-window", "-v", "-t", f"{session}:k8s-deploy.1"])

        k8s_commands = [
            "kubectl get deployments -A -w",
            "kubectl get events --sort-by=.metadata.creationTimestamp -w",
            "kubectl get pods -A -w",
        ]

        for i, cmd in enumerate(k8s_commands):
            self.run_tmux_command(
                ["send-keys", "-t", f"{session}:k8s-deploy.{i}", cmd, "Enter"]
            )

        # Window 3: Health Checks
        self.run_tmux_command(
            [
                "new-window",
                "-t",
                f"{session}:3",
                "-n",
                "health",
                "watch -n 5 'curl -s http://localhost:8080/health && curl -s http://localhost:8081/health'",
            ]
        )

        print(f"Deployment session '{session}' created successfully!")
        return session

    def list_sessions(self) -> List[Dict]:
        """List all tmux sessions"""
        result = self.run_tmux_command(
            [
                "list-sessions",
                "-F",
                "#{session_name}:#{session_windows}:#{?session_attached,attached,detached}",
            ]
        )

        sessions = []
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().split("\n"):
                if line:
                    parts = line.split(":")
                    if len(parts) >= 3:
                        sessions.append(
                            {
                                "name": parts[0],
                                "windows": int(parts[1]),
                                "status": parts[2],
                            }
                        )

        return sessions

    def attach_session(self, session_name: str):
        """Attach to a tmux session"""
        if not self.session_exists(session_name):
            print(f"Session '{session_name}' does not exist")
            return False

        # Use subprocess.call to keep the session interactive
        import subprocess

        cmd = [self.tmux_cmd]
        if self.config_path:
            cmd.extend(["-f", self.config_path])
        cmd.extend(["attach-session", "-t", session_name])

        return subprocess.call(cmd) == 0


def main():
    """Main function with command line interface"""
    parser = argparse.ArgumentParser(
        description="Production TMUX Setup for Workflow Architecture"
    )

    parser.add_argument(
        "command",
        choices=["monitor", "incident", "deploy", "list", "attach"],
        help="Command to execute",
    )

    parser.add_argument("--session", help="Session name (for attach command)")

    parser.add_argument(
        "--tmux-cmd", default="tmux", help="TMUX command to use (default: tmux)"
    )

    parser.add_argument("--config", help="TMUX configuration file path")

    args = parser.parse_args()

    # Setup the production tmux manager
    setup = ProductionTMUXSetup(tmux_cmd=args.tmux_cmd, config_path=args.config)

    # Check if tmux is available
    if not setup.check_tmux_available():
        print("Error: TMUX is not available")
        print("Install tmux or build tmux-clone first")
        return 1

    if args.command == "monitor":
        session = setup.create_production_monitoring_session()
        print(f"\nTo attach: {args.tmux_cmd} attach-session -t {session}")

    elif args.command == "incident":
        session = setup.create_incident_response_session()
        print(f"\nTo attach: {args.tmux_cmd} attach-session -t {session}")

    elif args.command == "deploy":
        session = setup.create_deployment_session()
        print(f"\nTo attach: {args.tmux_cmd} attach-session -t {session}")

    elif args.command == "list":
        sessions = setup.list_sessions()
        if sessions:
            print("Active TMUX sessions:")
            for session in sessions:
                print(
                    f"  {session['name']}: {session['windows']} windows ({session['status']})"
                )
        else:
            print("No active TMUX sessions")

    elif args.command == "attach":
        if not args.session:
            sessions = setup.list_sessions()
            if sessions:
                print("Available sessions:")
                for session in sessions:
                    print(f"  {session['name']}")
                print("\nUse --session <name> to attach")
            else:
                print("No sessions available")
            return 1

        success = setup.attach_session(args.session)
        if not success:
            return 1

    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
