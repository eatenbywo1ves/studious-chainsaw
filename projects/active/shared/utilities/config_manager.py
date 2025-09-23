"""
Configuration Management Utility
Centralized configuration management for agents and MCP servers.
"""

import json
import os
import logging
from typing import Dict, List, Any
from pathlib import Path
import shutil


class ConfigManager:
    def __init__(self, base_path: str = None):
        """Initialize configuration manager."""
        if base_path is None:
            base_path = os.path.join(os.path.dirname(__file__), "..", "..", "configs")

        self.base_path = Path(base_path)
        self.logger = logging.getLogger(__name__)

        # Ensure configs directory exists
        self.base_path.mkdir(parents=True, exist_ok=True)

    def load_config(self, config_type: str, config_name: str) -> Dict[str, Any]:
        """Load a configuration file."""
        config_path = self.base_path / config_type / f"{config_name}.json"

        try:
            if config_path.exists():
                with open(config_path, "r") as f:
                    return json.load(f)
            else:
                self.logger.warning(f"Config file not found: {config_path}")
                return {}
        except Exception as e:
            self.logger.error(f"Error loading config {config_path}: {e}")
            return {}

    def save_config(
        self, config_type: str, config_name: str, config_data: Dict[str, Any]
    ):
        """Save a configuration file."""
        config_dir = self.base_path / config_type
        config_dir.mkdir(parents=True, exist_ok=True)

        config_path = config_dir / f"{config_name}.json"

        try:
            with open(config_path, "w") as f:
                json.dump(config_data, f, indent=2)
            self.logger.info(f"Saved config to {config_path}")
        except Exception as e:
            self.logger.error(f"Error saving config to {config_path}: {e}")

    def backup_config(self, config_type: str, config_name: str) -> bool:
        """Create a backup of a configuration file."""
        config_path = self.base_path / config_type / f"{config_name}.json"
        backup_path = self.base_path / config_type / f"{config_name}.backup.json"

        try:
            if config_path.exists():
                shutil.copy2(config_path, backup_path)
                self.logger.info(f"Backed up config to {backup_path}")
                return True
            else:
                self.logger.warning(f"Config file not found for backup: {config_path}")
                return False
        except Exception as e:
            self.logger.error(f"Error backing up config: {e}")
            return False

    def restore_config(self, config_type: str, config_name: str) -> bool:
        """Restore a configuration file from backup."""
        config_path = self.base_path / config_type / f"{config_name}.json"
        backup_path = self.base_path / config_type / f"{config_name}.backup.json"

        try:
            if backup_path.exists():
                shutil.copy2(backup_path, config_path)
                self.logger.info(f"Restored config from {backup_path}")
                return True
            else:
                self.logger.warning(f"Backup file not found: {backup_path}")
                return False
        except Exception as e:
            self.logger.error(f"Error restoring config: {e}")
            return False

    def list_configs(self, config_type: str) -> List[str]:
        """List available configuration files of a specific type."""
        config_dir = self.base_path / config_type

        if not config_dir.exists():
            return []

        configs = []
        for file_path in config_dir.glob("*.json"):
            if not file_path.name.endswith(".backup.json"):
                configs.append(file_path.stem)

        return sorted(configs)

    def merge_configs(
        self, config_type: str, base_config: str, overlay_config: str
    ) -> Dict[str, Any]:
        """Merge two configuration files."""
        base_data = self.load_config(config_type, base_config)
        overlay_data = self.load_config(config_type, overlay_config)

        def deep_merge(base: Dict, overlay: Dict) -> Dict:
            """Deep merge two dictionaries."""
            merged = base.copy()

            for key, value in overlay.items():
                if (
                    key in merged
                    and isinstance(merged[key], dict)
                    and isinstance(value, dict)
                ):
                    merged[key] = deep_merge(merged[key], value)
                else:
                    merged[key] = value

            return merged

        return deep_merge(base_data, overlay_data)

    def validate_mcp_config(self, config_data: Dict[str, Any]) -> List[str]:
        """Validate MCP configuration structure."""
        errors = []

        if "mcpServers" not in config_data:
            errors.append("Missing 'mcpServers' key")
            return errors

        for server_name, server_config in config_data["mcpServers"].items():
            if not isinstance(server_config, dict):
                errors.append(f"Server '{server_name}' config must be an object")
                continue

            if "command" not in server_config:
                errors.append(f"Server '{server_name}' missing 'command'")

            if "args" in server_config and not isinstance(server_config["args"], list):
                errors.append(f"Server '{server_name}' 'args' must be an array")

            if "env" in server_config and not isinstance(server_config["env"], dict):
                errors.append(f"Server '{server_name}' 'env' must be an object")

        return errors

    def generate_mcp_config_for_claude_code(
        self, server_configs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate Claude Code MCP configuration."""
        config = {"mcpServers": {}}

        for server_name, server_info in server_configs.items():
            config["mcpServers"][server_name] = {
                "command": server_info.get("command", "node"),
                "args": server_info.get("args", []),
                "env": server_info.get("env", {}),
            }

            if "cwd" in server_info:
                # Claude Code uses absolute paths in args instead of cwd
                if server_info["command"] == "node" and server_info["args"]:
                    # Convert relative path to absolute
                    main_file = server_info["args"][0]
                    if not os.path.isabs(main_file):
                        abs_path = os.path.join(server_info["cwd"], main_file)
                        config["mcpServers"][server_name]["args"] = [
                            abs_path
                        ] + server_info["args"][1:]

        return config

    def generate_mcp_config_for_claude_desktop(
        self, server_configs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate Claude Desktop MCP configuration."""
        config = {"mcpServers": {}}

        for server_name, server_info in server_configs.items():
            server_config = {
                "command": server_info.get("command", "node"),
                "args": server_info.get("args", []),
            }

            if "env" in server_info and server_info["env"]:
                server_config["env"] = server_info["env"]

            if "cwd" in server_info:
                server_config["cwd"] = server_info["cwd"].replace("\\", "/")

            config["mcpServers"][server_name] = server_config

        return config

    def sync_mcp_configs(self, master_config: str = "mcp-registry") -> bool:
        """Sync MCP configurations to Claude Code and Desktop formats."""
        try:
            # Load master config
            master_data = self.load_config("mcp", master_config)

            if not master_data or "mcpServers" not in master_data:
                self.logger.error("Invalid master MCP config")
                return False

            # Generate Claude Code config
            claude_code_config = self.generate_mcp_config_for_claude_code(
                master_data["mcpServers"]
            )
            self.save_config("mcp", "claude-code-synced", claude_code_config)

            # Generate Claude Desktop config
            claude_desktop_config = self.generate_mcp_config_for_claude_desktop(
                master_data["mcpServers"]
            )
            self.save_config("mcp", "claude-desktop-synced", claude_desktop_config)

            self.logger.info("Successfully synced MCP configurations")
            return True

        except Exception as e:
            self.logger.error(f"Error syncing MCP configs: {e}")
            return False


# Convenience functions
_config_manager = None


def get_config_manager() -> ConfigManager:
    """Get global config manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def load_agent_config(agent_name: str) -> Dict[str, Any]:
    """Load agent configuration."""
    return get_config_manager().load_config("agents", agent_name)


def save_agent_config(agent_name: str, config: Dict[str, Any]):
    """Save agent configuration."""
    get_config_manager().save_config("agents", agent_name, config)


def load_mcp_config(config_name: str = "claude-code") -> Dict[str, Any]:
    """Load MCP configuration."""
    return get_config_manager().load_config("mcp", config_name)


def save_mcp_config(config_name: str, config: Dict[str, Any]):
    """Save MCP configuration."""
    get_config_manager().save_config("mcp", config_name, config)
