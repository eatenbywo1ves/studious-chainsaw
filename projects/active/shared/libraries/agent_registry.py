"""
Agent Registry and Discovery System
Centralized system for managing and discovering agents in the development environment.
"""

import json
import os
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum


class AgentStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"


class AgentType(Enum):
    COORDINATION = "coordination"
    MONITORING = "monitoring"
    AUTONOMOUS = "autonomous"
    UTILITY = "utility"
    PROCESSING = "processing"


@dataclass
class AgentInfo:
    name: str
    description: str
    path: str
    main: str
    type: AgentType
    status: AgentStatus
    dependencies: List[str]
    capabilities: List[str]
    version: Optional[str] = None
    author: Optional[str] = None
    last_modified: Optional[str] = None


class AgentRegistry:
    def __init__(self, config_path: str = None):
        """Initialize the agent registry."""
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(__file__),
                "..",
                "..",
                "configs",
                "agents",
                "agent-registry.json",
            )
        self.config_path = config_path
        self.agents = {}
        self.load_registry()

    def load_registry(self):
        """Load agent registry from configuration file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, "r") as f:
                    config = json.load(f)

                for category in ["production", "experimental"]:
                    if category in config.get("agentRegistry", {}):
                        for agent_id, agent_data in config["agentRegistry"][
                            category
                        ].items():
                            self.agents[agent_id] = AgentInfo(
                                name=agent_data["name"],
                                description=agent_data["description"],
                                path=agent_data["path"],
                                main=agent_data["main"],
                                type=AgentType(agent_data["type"]),
                                status=AgentStatus(agent_data["status"]),
                                dependencies=agent_data.get("dependencies", []),
                                capabilities=agent_data.get("capabilities", []),
                                version=agent_data.get("version"),
                                author=agent_data.get("author"),
                                last_modified=agent_data.get("last_modified"),
                            )
            else:
                logging.warning(f"Registry config file not found: {self.config_path}")

        except Exception as e:
            logging.error(f"Error loading agent registry: {e}")

    def get_agent(self, agent_id: str) -> Optional[AgentInfo]:
        """Get agent information by ID."""
        return self.agents.get(agent_id)

    def list_agents(
        self,
        status: Optional[AgentStatus] = None,
        agent_type: Optional[AgentType] = None,
    ) -> List[AgentInfo]:
        """List agents with optional filtering."""
        agents = list(self.agents.values())

        if status:
            agents = [a for a in agents if a.status == status]

        if agent_type:
            agents = [a for a in agents if a.type == agent_type]

        return agents

    def register_agent(self, agent_id: str, agent_info: AgentInfo):
        """Register a new agent."""
        self.agents[agent_id] = agent_info
        self.save_registry()

    def unregister_agent(self, agent_id: str):
        """Unregister an agent."""
        if agent_id in self.agents:
            del self.agents[agent_id]
            self.save_registry()

    def update_agent_status(self, agent_id: str, status: AgentStatus):
        """Update agent status."""
        if agent_id in self.agents:
            self.agents[agent_id].status = status
            self.save_registry()

    def save_registry(self):
        """Save agent registry to configuration file."""
        try:
            config = {
                "agentRegistry": {
                    "production": {},
                    "experimental": {},
                    "templates": {},
                },
                "metadata": {"version": "1.0.0", "updated": "2025-08-27T21:19:00Z"},
            }

            for agent_id, agent_info in self.agents.items():
                category = (
                    "production"
                    if agent_info.status == AgentStatus.ACTIVE
                    else "experimental"
                )
                config["agentRegistry"][category][agent_id] = {
                    "name": agent_info.name,
                    "description": agent_info.description,
                    "path": agent_info.path,
                    "main": agent_info.main,
                    "type": agent_info.type.value,
                    "status": agent_info.status.value,
                    "dependencies": agent_info.dependencies,
                    "capabilities": agent_info.capabilities,
                    "version": agent_info.version,
                    "author": agent_info.author,
                    "last_modified": agent_info.last_modified,
                }

            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, "w") as f:
                json.dump(config, f, indent=2)

        except Exception as e:
            logging.error(f"Error saving agent registry: {e}")

    def discover_agents(self, search_path: str) -> List[Dict[str, Any]]:
        """Discover agents in the filesystem."""
        discovered = []

        for root, dirs, files in os.walk(search_path):
            # Look for Python files that might be agents
            python_files = [f for f in files if f.endswith(".py")]

            # Look for package.json files for Node.js agents
            if "package.json" in files:
                try:
                    with open(os.path.join(root, "package.json"), "r") as f:
                        package_info = json.load(f)
                        discovered.append(
                            {
                                "path": root,
                                "type": "nodejs",
                                "main": package_info.get("main", "index.js"),
                                "name": package_info.get(
                                    "name", os.path.basename(root)
                                ),
                                "description": package_info.get("description", ""),
                                "dependencies": list(
                                    package_info.get("dependencies", {}).keys()
                                ),
                            }
                        )
                except Exception:
                    pass

            # Look for main Python agent files
            for py_file in python_files:
                if "agent" in py_file.lower() or py_file in ["main.py", "app.py"]:
                    discovered.append(
                        {
                            "path": root,
                            "type": "python",
                            "main": py_file,
                            "name": os.path.basename(root),
                            "description": f"Python agent: {py_file}",
                        }
                    )

        return discovered

    def health_check(self, agent_id: str) -> Dict[str, Any]:
        """Perform health check on an agent."""
        agent = self.get_agent(agent_id)
        if not agent:
            return {"status": "error", "message": "Agent not found"}

        # Check if agent files exist
        if not os.path.exists(agent.path):
            return {"status": "error", "message": "Agent path not found"}

        main_file = os.path.join(agent.path, agent.main)
        if not os.path.exists(main_file):
            return {"status": "error", "message": "Main file not found"}

        return {
            "status": "healthy",
            "path_exists": True,
            "main_file_exists": True,
            "last_checked": "2025-08-27T21:19:00Z",
        }


# Convenience functions
def get_registry() -> AgentRegistry:
    """Get the global agent registry instance."""
    return AgentRegistry()


def list_active_agents() -> List[AgentInfo]:
    """List all active agents."""
    registry = get_registry()
    return registry.list_agents(status=AgentStatus.ACTIVE)


def find_agent_by_capability(capability: str) -> List[AgentInfo]:
    """Find agents by capability."""
    registry = get_registry()
    return [
        agent for agent in registry.agents.values() if capability in agent.capabilities
    ]
