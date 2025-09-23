"""
MCP Server Registry and Management System
Centralized system for managing MCP servers and their configurations.
"""

import json
import os
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum


class MCPServerStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"


class MCPServerCategory(Enum):
    FINANCIAL = "financial"
    UTILITIES = "utilities"
    DEVELOPMENT = "development"
    AUTOMATION = "automation"


@dataclass
class MCPServerInfo:
    name: str
    description: str
    path: str
    main: str
    category: MCPServerCategory
    status: MCPServerStatus
    command: str
    args: List[str]
    env: Dict[str, str]
    capabilities: List[str]
    version: Optional[str] = None
    author: Optional[str] = None
    port: Optional[int] = None
    dependencies: Optional[List[str]] = None


class MCPRegistry:
    def __init__(self, config_path: str = None):
        """Initialize the MCP registry."""
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(__file__),
                "..",
                "..",
                "configs",
                "mcp",
                "mcp-registry.json",
            )
        self.config_path = config_path
        self.servers = {}
        self.load_registry()

    def load_registry(self):
        """Load MCP registry from configuration file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, "r") as f:
                    config = json.load(f)

                for server_id, server_data in config.get("mcpServers", {}).items():
                    self.servers[server_id] = MCPServerInfo(
                        name=server_data["name"],
                        description=server_data["description"],
                        path=server_data["path"],
                        main=server_data["main"],
                        category=MCPServerCategory(server_data["category"]),
                        status=MCPServerStatus(server_data["status"]),
                        command=server_data["command"],
                        args=server_data.get("args", []),
                        env=server_data.get("env", {}),
                        capabilities=server_data.get("capabilities", []),
                        version=server_data.get("version"),
                        author=server_data.get("author"),
                        port=server_data.get("port"),
                        dependencies=server_data.get("dependencies", []),
                    )
            else:
                # Create default registry
                self.create_default_registry()

        except Exception as e:
            logging.error(f"Error loading MCP registry: {e}")
            self.create_default_registry()

    def create_default_registry(self):
        """Create default MCP registry based on known servers."""
        default_servers = {
            "filesystem": {
                "name": "Filesystem Server",
                "description": "File system operations MCP server",
                "path": "C:\\Users\\Corbin\\development\\mcp-servers\\utilities\\filesystem",
                "main": "index.js",
                "category": "utilities",
                "status": "active",
                "command": "npx",
                "args": [
                    "-y",
                    "@modelcontextprotocol/server-filesystem",
                    "C:\\Users\\Corbin\\development",
                ],
                "env": {},
                "capabilities": ["file_operations", "directory_listing", "file_search"],
            },
            "financial-localization": {
                "name": "Financial Localization Server",
                "description": "Financial terminology translation and localization",
                "path": "C:\\Users\\Corbin\\development\\mcp-servers\\financial\\localization",
                "main": "src\\index.js",
                "category": "financial",
                "status": "active",
                "command": "node",
                "args": ["src\\index.js"],
                "env": {"NODE_ENV": "production"},
                "capabilities": [
                    "translation",
                    "currency_formatting",
                    "locale_support",
                ],
            },
            "financial-stochastic": {
                "name": "Financial Stochastic Server",
                "description": "Stochastic financial modeling and simulation",
                "path": "C:\\Users\\Corbin\\development\\mcp-servers\\financial\\stochastic",
                "main": "src\\index.js",
                "category": "financial",
                "status": "active",
                "command": "node",
                "args": ["src\\index.js"],
                "env": {"NODE_ENV": "production"},
                "capabilities": [
                    "gbm",
                    "ou_process",
                    "heston_model",
                    "merton_jump",
                    "cir_process",
                    "risk_metrics",
                ],
            },
            "multidimensional-stochastic": {
                "name": "Multidimensional Stochastic Server",
                "description": "Multi-asset stochastic process modeling",
                "path": "C:\\Users\\Corbin\\development\\mcp-servers\\financial\\multidimensional",
                "main": "src\\index.js",
                "category": "financial",
                "status": "active",
                "command": "node",
                "args": ["src\\index.js"],
                "env": {"NODE_ENV": "production"},
                "capabilities": [
                    "multi_gbm",
                    "multi_ou",
                    "multi_heston",
                    "portfolio_metrics",
                    "correlation_analysis",
                ],
            },
            "random-walk": {
                "name": "Random Walk Server",
                "description": "Random walk and stochastic process generation",
                "path": "C:\\Users\\Corbin\\development\\mcp-servers\\utilities\\random-walk",
                "main": "src\\index.js",
                "category": "utilities",
                "status": "active",
                "command": "node",
                "args": ["src\\index.js"],
                "env": {"NODE_ENV": "production"},
                "capabilities": [
                    "simple_walk",
                    "biased_walk",
                    "levy_walk",
                    "correlated_walk",
                    "walk_analysis",
                ],
            },
        }

        for server_id, server_data in default_servers.items():
            # Convert string values to enums
            server_data_with_enums = server_data.copy()
            server_data_with_enums["category"] = MCPServerCategory(
                server_data["category"]
            )
            server_data_with_enums["status"] = MCPServerStatus(server_data["status"])
            self.servers[server_id] = MCPServerInfo(**server_data_with_enums)

        self.save_registry()

    def get_server(self, server_id: str) -> Optional[MCPServerInfo]:
        """Get MCP server information by ID."""
        return self.servers.get(server_id)

    def list_servers(
        self,
        category: Optional[MCPServerCategory] = None,
        status: Optional[MCPServerStatus] = None,
    ) -> List[MCPServerInfo]:
        """List MCP servers with optional filtering."""
        servers = list(self.servers.values())

        if category:
            servers = [s for s in servers if s.category == category]

        if status:
            servers = [s for s in servers if s.status == status]

        return servers

    def register_server(self, server_id: str, server_info: MCPServerInfo):
        """Register a new MCP server."""
        self.servers[server_id] = server_info
        self.save_registry()

    def unregister_server(self, server_id: str):
        """Unregister an MCP server."""
        if server_id in self.servers:
            del self.servers[server_id]
            self.save_registry()

    def update_server_status(self, server_id: str, status: MCPServerStatus):
        """Update MCP server status."""
        if server_id in self.servers:
            self.servers[server_id].status = status
            self.save_registry()

    def generate_claude_config(self, platform: str = "code") -> Dict[str, Any]:
        """Generate Claude configuration for active MCP servers."""
        config = {"mcpServers": {}}

        for server_id, server_info in self.servers.items():
            if server_info.status == MCPServerStatus.ACTIVE:
                server_config = {
                    "command": server_info.command,
                    "args": server_info.args,
                    "env": server_info.env,
                }

                # Add working directory if specified
                if hasattr(server_info, "cwd") and server_info.cwd:
                    server_config["cwd"] = server_info.cwd

                config["mcpServers"][server_id] = server_config

        return config

    def save_registry(self):
        """Save MCP registry to configuration file."""
        try:
            config = {
                "mcpServers": {},
                "metadata": {"version": "1.0.0", "updated": "2025-08-27T21:19:00Z"},
            }

            for server_id, server_info in self.servers.items():
                config["mcpServers"][server_id] = {
                    "name": server_info.name,
                    "description": server_info.description,
                    "path": server_info.path,
                    "main": server_info.main,
                    "category": server_info.category.value,
                    "status": server_info.status.value,
                    "command": server_info.command,
                    "args": server_info.args,
                    "env": server_info.env,
                    "capabilities": server_info.capabilities,
                    "version": server_info.version,
                    "author": server_info.author,
                    "port": server_info.port,
                    "dependencies": server_info.dependencies,
                }

            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, "w") as f:
                json.dump(config, f, indent=2)

        except Exception as e:
            logging.error(f"Error saving MCP registry: {e}")

    def health_check(self, server_id: str) -> Dict[str, Any]:
        """Perform health check on an MCP server."""
        server = self.get_server(server_id)
        if not server:
            return {"status": "error", "message": "Server not found"}

        # Check if server files exist
        if not os.path.exists(server.path):
            return {"status": "error", "message": "Server path not found"}

        main_file = os.path.join(server.path, server.main)
        if not os.path.exists(main_file):
            return {"status": "error", "message": "Main file not found"}

        return {
            "status": "healthy",
            "path_exists": True,
            "main_file_exists": True,
            "last_checked": "2025-08-27T21:19:00Z",
        }


# Convenience functions
def get_mcp_registry() -> MCPRegistry:
    """Get the global MCP registry instance."""
    return MCPRegistry()


def list_active_servers() -> List[MCPServerInfo]:
    """List all active MCP servers."""
    registry = get_mcp_registry()
    return registry.list_servers(status=MCPServerStatus.ACTIVE)


def find_servers_by_capability(capability: str) -> List[MCPServerInfo]:
    """Find MCP servers by capability."""
    registry = get_mcp_registry()
    return [
        server
        for server in registry.servers.values()
        if capability in server.capabilities
    ]
