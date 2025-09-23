"""
TMUX Integration for Agent Orchestration
Extends the agent orchestrator with tmux session management for development
"""

import asyncio
import subprocess
import logging
from typing import Dict, List
from dataclasses import dataclass
from .agent_orchestrator import AgentOrchestrator
from ..libraries.input_validation import (
    StringValidator,
    TMUXConfigValidator,
    ValidationError,
    validate_input,
)
from ..libraries.validation_errors import ValidationErrorHandler


@dataclass
class TMUXSession:
    """Represents a tmux session for an agent"""

    session_name: str
    agent_id: str
    window_id: str
    pane_ids: List[str]
    status: str = "running"


class TMUXAgentManager:
    """Manages agents using tmux sessions for development environments"""

    def __init__(self, orchestrator: AgentOrchestrator):
        self.orchestrator = orchestrator
        self.tmux_sessions: Dict[str, TMUXSession] = {}
        self.base_session = "agent-orchestrator"
        self.logger = logging.getLogger(__name__)
        self.validator = ValidationErrorHandler(self.logger)

    async def initialize(self, window_width: float = 120, window_height: float = 40):
        """Initialize tmux environment for agent management"""
        # Validate window dimensions
        size_result = TMUXConfigValidator.validate_window_size(
            window_width, window_height
        )
        if not size_result.is_valid:
            ___error_response = self.validator.handle_validation_error(
                size_result, "window_dimensions", "TMUX initialization"
            )
            raise ValidationError(size_result)

        width, height = size_result.sanitized_value

        # Validate base session name
        ___session_result = validate_input(
            StringValidator.validate_session_name,
            self.base_session,
            raise_on_error=True,
        )

        # Create base session for orchestrator
        await self._run_tmux_command(
            [
                "new-session",
                "-d",
                "-s",
                self.base_session,
                "-x",
                str(width),
                "-y",
                str(height),
                "echo 'Agent Orchestrator Console'",
            ]
        )

        # Create monitoring window
        await self._run_tmux_command(
            ["new-window", "-t", f"{self.base_session}:1", "-n", "monitoring", "htop"]
        )

        # Create logs window
        await self._run_tmux_command(
            [
                "new-window",
                "-t",
                f"{self.base_session}:2",
                "-n",
                "logs",
                "tail -f /var/log/agent-orchestrator.log",
            ]
        )

    async def spawn_agent_with_tmux(
        self, spec_id: str, tenant_id: str = ""
    ) -> TMUXSession:
        """Spawn agent with dedicated tmux session"""

        # Create agent through orchestrator
        agent_instance = await self.orchestrator.spawn_agent(spec_id, tenant_id)

        # Create tmux session for this agent
        session_name = f"agent-{agent_instance.id[:8]}"

        # Create new session for the agent
        await self._run_tmux_command(
            [
                "new-session",
                "-d",
                "-s",
                session_name,
                "-n",
                "main",
                f"echo 'Agent {agent_instance.id} - Status: {agent_instance.status.value}'",
            ]
        )

        # Split into multiple panes for different views
        pane_ids = []

        # Pane 1: Agent output
        await self._run_tmux_command(
            ["split-window", "-h", "-t", f"{session_name}:main"]
        )
        pane_ids.append(f"{session_name}:main.0")
        pane_ids.append(f"{session_name}:main.1")

        # Pane 2: Agent logs
        await self._run_tmux_command(
            ["split-window", "-v", "-t", f"{session_name}:main.1"]
        )
        pane_ids.append(f"{session_name}:main.2")

        # Send commands to different panes
        await self._run_tmux_command(
            [
                "send-keys",
                "-t",
                pane_ids[0],
                f"curl -s {agent_instance.endpoint_url}/health | jq .",
                "Enter",
            ]
        )

        await self._run_tmux_command(
            [
                "send-keys",
                "-t",
                pane_ids[1],
                f"watch -n 2 'kubectl describe pod {agent_instance.pod_name}'",
                "Enter",
            ]
        )

        await self._run_tmux_command(
            [
                "send-keys",
                "-t",
                pane_ids[2],
                f"kubectl logs -f {agent_instance.pod_name}",
                "Enter",
            ]
        )

        # Create tmux session object
        tmux_session = TMUXSession(
            session_name=session_name,
            agent_id=agent_instance.id,
            window_id=f"{session_name}:main",
            pane_ids=pane_ids,
        )

        self.tmux_sessions[agent_instance.id] = tmux_session
        return tmux_session

    async def create_workflow_session(self, workflow_id: str) -> str:
        """Create tmux session for workflow monitoring"""
        # Validate workflow ID
        workflow_result = validate_input(
            StringValidator.validate_session_name, workflow_id, raise_on_error=False
        )

        if not workflow_result.is_valid:
            self.logger.warning(f"Invalid workflow ID format: {workflow_id}")
            # Use sanitized version or create safe alternative
            safe_workflow_id = f"workflow-{abs(hash(workflow_id)) % 10000}"
        else:
            safe_workflow_id = workflow_result.sanitized_value

        session_name = f"workflow-{safe_workflow_id[:8]}"

        # Validate the generated session name
        ___session_result = validate_input(
            StringValidator.validate_session_name, session_name, raise_on_error=True
        )

        # Create session with workflow overview
        await self._run_tmux_command(
            [
                "new-session",
                "-d",
                "-s",
                session_name,
                "-n",
                "overview",
                f"echo 'Workflow {workflow_id} Overview'",
            ]
        )

        # Create window for each workflow step
        workflow = self.orchestrator.workflows.get(workflow_id)
        if workflow:
            for i, step in enumerate(workflow.steps):
                window_name = f"step-{i + 1}"
                await self._run_tmux_command(
                    [
                        "new-window",
                        "-t",
                        f"{session_name}:{i + 1}",
                        "-n",
                        window_name,
                        f"echo 'Step: {step.name} - Agent Type: {step.agent_type}'",
                    ]
                )

        return session_name

    async def create_development_environment(self):
        """Create complete development environment in tmux"""
        dev_session = "dev-environment"

        # Main development session
        await self._run_tmux_command(
            [
                "new-session",
                "-d",
                "-s",
                dev_session,
                "-n",
                "editor",
                "cd /Users/Corbin/development && code .",
            ]
        )

        # Service monitoring window
        await self._run_tmux_command(
            ["new-window", "-t", f"{dev_session}:1", "-n", "services"]
        )

        # Split into service monitoring panes
        service_commands = [
            "docker ps -a",
            "kubectl get pods -A",
            "redis-cli ping",
            "pg_isready -h localhost",
        ]

        for i, cmd in enumerate(service_commands):
            if i > 0:
                await self._run_tmux_command(
                    [
                        "split-window",
                        "-v" if i % 2 else "-h",
                        "-t",
                        f"{dev_session}:services",
                    ]
                )

            await self._run_tmux_command(
                [
                    "send-keys",
                    "-t",
                    f"{dev_session}:services.{i}",
                    f"watch -n 2 '{cmd}'",
                    "Enter",
                ]
            )

        # Logs window
        await self._run_tmux_command(
            [
                "new-window",
                "-t",
                f"{dev_session}:2",
                "-n",
                "logs",
                "multitail -i /logs/workflow-engine.log -i /logs/agent-orchestrator.log",
            ]
        )

        # Testing window
        await self._run_tmux_command(
            [
                "new-window",
                "-t",
                f"{dev_session}:3",
                "-n",
                "testing",
                "cd /Users/Corbin/development/shared && python -m pytest -v",
            ]
        )

        return dev_session

    async def attach_to_agent(self, agent_id: str):
        """Attach to specific agent's tmux session"""
        if agent_id in self.tmux_sessions:
            session = self.tmux_sessions[agent_id]
            await self._run_tmux_command(["attach-session", "-t", session.session_name])
        else:
            print(f"No tmux session found for agent {agent_id}")

    async def list_sessions(self) -> List[Dict]:
        """List all tmux sessions"""
        result = await self._run_tmux_command(
            [
                "list-sessions",
                "-F",
                "#{session_name}:#{session_windows}:#{?session_attached,attached,not attached}",
            ]
        )

        sessions = []
        if result and result.stdout:
            for line in result.stdout.strip().split("\n"):
                parts = line.split(":")
                if len(parts) >= 3:
                    sessions.append(
                        {
                            "name": parts[0],
                            "windows": int(parts[1]),
                            "attached": parts[2] == "attached",
                        }
                    )

        return sessions

    async def cleanup_agent_session(self, agent_id: str):
        """Clean up tmux session when agent is terminated"""
        if agent_id in self.tmux_sessions:
            session = self.tmux_sessions[agent_id]

            # Kill the session
            await self._run_tmux_command(["kill-session", "-t", session.session_name])

            # Remove from tracking
            del self.tmux_sessions[agent_id]

    async def create_debug_session(self, agent_id: str) -> str:
        """Create debugging session for specific agent"""
        if agent_id not in self.tmux_sessions:
            return None

        debug_session = f"debug-{agent_id[:8]}"
        agent = self.orchestrator.agent_instances.get(agent_id)

        if not agent:
            return None

        # Create debug session
        await self._run_tmux_command(
            [
                "new-session",
                "-d",
                "-s",
                debug_session,
                "-n",
                "debugger",
                f"echo 'Debugging Agent {agent_id}'",
            ]
        )

        # Add debugging tools
        debug_commands = [
            f"kubectl exec -it {agent.pod_name} -- /bin/bash",
            f"kubectl describe pod {agent.pod_name}",
            f"kubectl logs -f {agent.pod_name} --previous",
            f"curl -v {agent.endpoint_url}/debug",
        ]

        for i, cmd in enumerate(debug_commands):
            if i > 0:
                await self._run_tmux_command(
                    [
                        "split-window",
                        "-v" if i % 2 else "-h",
                        "-t",
                        f"{debug_session}:debugger",
                    ]
                )

            await self._run_tmux_command(
                ["send-keys", "-t", f"{debug_session}:debugger.{i}", cmd, "Enter"]
            )

        return debug_session

    async def _run_tmux_command(self, args: List[str]) -> subprocess.CompletedProcess:
        """Run tmux command asynchronously"""
        try:
            # Use your custom tmux if available, otherwise system tmux
            tmux_path = "/Users/Corbin/development/tmux-clone/bin/tmux-clone"
            if (
                not subprocess.run(["which", tmux_path], capture_output=True).returncode
                == 0
            ):
                tmux_path = "tmux"  # Fall back to system tmux

            cmd = [tmux_path] + args

            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            return subprocess.CompletedProcess(
                cmd, process.returncode, stdout.decode(), stderr.decode()
            )

        except Exception as e:
            print(f"Error running tmux command {args}: {e}")
            return subprocess.CompletedProcess(args, 1, "", str(e))

    def get_session_info(self) -> Dict:
        """Get information about all managed sessions"""
        return {
            "total_sessions": len(self.tmux_sessions),
            "sessions": [
                {
                    "agent_id": agent_id,
                    "session_name": session.session_name,
                    "status": session.status,
                    "panes": len(session.pane_ids),
                }
                for agent_id, session in self.tmux_sessions.items()
            ],
        }


# Integration example
async def main():
    """Example usage of TMUXAgentManager"""

    # Initialize orchestrator
    orchestrator = AgentOrchestrator(
        {"kubernetes_enabled": True, "redis_enabled": True}
    )
    await orchestrator.initialize()

    # Initialize tmux manager
    tmux_manager = TMUXAgentManager(orchestrator)
    await tmux_manager.initialize()

    # Create development environment
    dev_session = await tmux_manager.create_development_environment()
    print(f"Development environment created: {dev_session}")

    # Spawn agent with tmux session
    # (Assuming you have agent specs registered)
    # agent_session = await tmux_manager.spawn_agent_with_tmux("some-spec-id")
    # print(f"Agent session created: {agent_session.session_name}")

    # List all sessions
    sessions = await tmux_manager.list_sessions()
    print(f"Active sessions: {sessions}")


if __name__ == "__main__":
    asyncio.run(main())
