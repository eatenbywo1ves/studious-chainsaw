#!/usr/bin/env python3
"""
Development Environment Initialization Script

This script initializes the development environment, sets up configurations,
and validates the structure.
"""

import sys
import json
from pathlib import Path

# Add shared libraries to path
current_dir = Path(__file__).parent
shared_lib_path = current_dir / "shared" / "libraries"
shared_util_path = current_dir / "shared" / "utilities"
sys.path.insert(0, str(shared_lib_path))
sys.path.insert(0, str(shared_util_path))

try:
    from agent_registry import AgentRegistry
    from mcp_registry import MCPRegistry
    from config_manager import ConfigManager
    from logging_utils import setup_system_logging
except ImportError as e:
    print(f"Error importing shared libraries: {e}")
    print("Please ensure shared libraries are properly installed.")
    sys.exit(1)


class DevelopmentEnvironmentInitializer:
    def __init__(self):
        self.base_path = Path(__file__).parent
        self.logger = setup_system_logging("initializer", "INFO")

    def initialize(self):
        """Initialize the complete development environment."""
        self.logger.info("Starting development environment initialization...")

        try:
            # Validate directory structure
            self.validate_directory_structure()

            # Initialize registries
            self.initialize_agent_registry()
            self.initialize_mcp_registry()

            # Setup configurations
            self.setup_configurations()

            # Validate configurations
            self.validate_configurations()

            # Create symlinks for easy access
            self.create_convenience_links()

            self.logger.info(
                "Development environment initialization completed successfully!"
            )
            self.print_summary()

        except Exception as e:
            self.logger.error(f"Initialization failed: {e}")
            return False

        return True

    def validate_directory_structure(self):
        """Validate that all required directories exist."""
        self.logger.info("Validating directory structure...")

        required_dirs = [
            "agents/production",
            "agents/experimental",
            "agents/templates",
            "mcp-servers/financial",
            "mcp-servers/utilities",
            "mcp-servers/templates",
            "configs/mcp",
            "configs/agents",
            "shared/libraries",
            "shared/schemas",
            "shared/utilities",
        ]

        missing_dirs = []
        for dir_path in required_dirs:
            full_path = self.base_path / dir_path
            if not full_path.exists():
                missing_dirs.append(dir_path)
                self.logger.warning(f"Missing directory: {dir_path}")

        if missing_dirs:
            self.logger.info("Creating missing directories...")
            for dir_path in missing_dirs:
                full_path = self.base_path / dir_path
                full_path.mkdir(parents=True, exist_ok=True)
                self.logger.info(f"Created directory: {dir_path}")

    def initialize_agent_registry(self):
        """Initialize the agent registry with discovered agents."""
        self.logger.info("Initializing agent registry...")

        registry = AgentRegistry()

        # Discover agents in production directory
        production_path = self.base_path / "agents" / "production"
        if production_path.exists():
            for agent_dir in production_path.iterdir():
                if agent_dir.is_dir():
                    self.logger.info(f"Discovered agent: {agent_dir.name}")

        # Save registry
        registry.save_registry()
        self.logger.info("Agent registry initialized")

    def initialize_mcp_registry(self):
        """Initialize the MCP registry with discovered servers."""
        self.logger.info("Initializing MCP registry...")

        registry = MCPRegistry()

        # The registry will create default entries for known servers
        servers = registry.list_servers()
        self.logger.info(f"Initialized {len(servers)} MCP servers")

        for server in servers:
            self.logger.info(
                f"  - {server.name} ({server.category.value if hasattr(server.category, 'value') else server.category})"
            )

    def setup_configurations(self):
        """Setup and synchronize configurations."""
        self.logger.info("Setting up configurations...")

        config_manager = ConfigManager()

        # Create environment configuration if it doesn't exist
        env_config_path = self.base_path / "configs" / "environment.json"
        if not env_config_path.exists():
            env_config = {
                "environment": {
                    "development": {
                        "base_path": str(self.base_path),
                        "agents_path": str(self.base_path / "agents"),
                        "mcp_servers_path": str(self.base_path / "mcp-servers"),
                        "shared_path": str(self.base_path / "shared"),
                        "configs_path": str(self.base_path / "configs"),
                    }
                },
                "runtime": {
                    "python": {"version": "3.11+", "virtual_env": True},
                    "node": {"version": "18+", "package_manager": "npm"},
                },
                "logging": {
                    "level": "INFO",
                    "file_logging": True,
                    "console_logging": True,
                },
            }

            with open(env_config_path, "w") as f:
                json.dump(env_config, f, indent=2)

            self.logger.info("Created environment configuration")

        # Synchronize MCP configurations
        if config_manager.sync_mcp_configs():
            self.logger.info("MCP configurations synchronized")
        else:
            self.logger.warning("Failed to synchronize MCP configurations")

    def validate_configurations(self):
        """Validate all configuration files."""
        self.logger.info("Validating configurations...")

        config_manager = ConfigManager()

        # Validate MCP configurations
        mcp_configs = config_manager.list_configs("mcp")
        for config_name in mcp_configs:
            config_data = config_manager.load_config("mcp", config_name)
            errors = config_manager.validate_mcp_config(config_data)

            if errors:
                self.logger.warning(f"Validation errors in {config_name}: {errors}")
            else:
                self.logger.info(f"Configuration {config_name} is valid")

    def create_convenience_links(self):
        """Create convenience scripts and shortcuts."""
        self.logger.info("Creating convenience links...")

        # Create activation script
        activate_script = self.base_path / "activate.py"
        if not activate_script.exists():
            script_content = '''#!/usr/bin/env python3
"""
Development Environment Activation Script
Run this to activate the development environment.
"""

import os
import sys
from pathlib import Path

# Add shared libraries to path
base_path = Path(__file__).parent
shared_lib_path = base_path / "shared" / "libraries"
sys.path.insert(0, str(shared_lib_path))

print("Development Environment Activated!")
print(f"Base path: {base_path}")
print("Available commands:")
print("  python -c 'from agent_registry import get_registry; print(get_registry().list_agents())'")
print("  python -c 'from mcp_registry import get_mcp_registry; print(get_mcp_registry().list_servers())'")
'''

            with open(activate_script, "w") as f:
                f.write(script_content)

            self.logger.info("Created activation script")

    def print_summary(self):
        """Print initialization summary."""
        print("\n" + "=" * 60)
        print("DEVELOPMENT ENVIRONMENT INITIALIZATION COMPLETE")
        print("=" * 60)

        # Agent summary
        registry = AgentRegistry()
        agents = registry.list_agents()
        print(f"\n[AGENTS] Found {len(agents)} agents:")
        for agent in agents:
            print(
                f"   - {agent.name} ({agent.status.value if hasattr(agent.status, 'value') else agent.status})"
            )

        # MCP server summary
        mcp_registry = MCPRegistry()
        servers = mcp_registry.list_servers()
        print(f"\n[MCP] Found {len(servers)} servers:")
        for server in servers:
            print(
                f"   - {server.name} ({server.category.value if hasattr(server.category, 'value') else server.category})"
            )

        # Configuration summary
        config_manager = ConfigManager()
        mcp_configs = config_manager.list_configs("mcp")
        agent_configs = config_manager.list_configs("agents")
        print("\n[CONFIG] Configurations:")
        print(f"   - MCP configs: {len(mcp_configs)}")
        print(f"   - Agent configs: {len(agent_configs)}")

        print(f"\n[PATH] Base Path: {self.base_path}")
        print("\n[NEXT] Next Steps:")
        print("   1. Review the README.md file for detailed usage instructions")
        print("   2. Update MCP configurations in Claude Code/Desktop if needed")
        print("   3. Start developing agents or MCP servers using the templates")
        print("   4. Use the observatory agent for monitoring")

        print("\n[COMMANDS] Quick Commands:")
        print("   python activate.py  # Activate environment")
        print("   python initialize.py  # Re-initialize environment")

        print("\n" + "=" * 60 + "\n")


def main():
    """Main initialization function."""
    print("Development Environment Initializer")
    print("===================================")

    initializer = DevelopmentEnvironmentInitializer()
    success = initializer.initialize()

    if success:
        print("\n[SUCCESS] Initialization completed successfully!")
        return 0
    else:
        print("\n[ERROR] Initialization failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
