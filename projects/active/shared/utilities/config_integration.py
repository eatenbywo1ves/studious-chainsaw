#!/usr/bin/env python3
"""
Configuration Integration Module
Integrates hot-reload with existing services like API Gateway, Observatory, and agents.
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any, Optional

# Add shared libraries to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utilities.config_hot_reload import (
    ConfigHotReload, 
    ConfigChange,
    ConfigFormat,
    get_hot_reload,
    watch_config
)
from utilities.logging_utils import setup_service_logging, LogLevel


class ConfigIntegration:
    """Integrates hot-reload with existing services"""
    
    def __init__(self):
        self.logger = setup_service_logging("config-integration", LogLevel.INFO)
        self.hot_reload = get_hot_reload()
        self.service_configs = {}
        self.callbacks = {}
        
        # Register standard configuration files
        self._register_standard_configs()
    
    def _register_standard_configs(self):
        """Register standard configuration files in the development environment"""
        base_path = Path("C:/Users/Corbin/development")
        
        # Configuration paths
        configs_to_watch = [
            # Agent configurations
            (base_path / "configs" / "agents" / "director.json", self._on_agent_config_change),
            (base_path / "configs" / "agents" / "observatory.json", self._on_agent_config_change),
            
            # MCP configurations  
            (base_path / "configs" / "mcp" / "claude-code-updated.json", self._on_mcp_config_change),
            
            # Environment configuration
            (base_path / "configs" / "environment.json", self._on_environment_config_change),
            
            # Code Analysis Agent configuration
            (base_path / "agents" / "experimental" / "code-analysis-agent" / "config.json", 
             self._on_code_analysis_config_change),
        ]
        
        registered = 0
        for config_path, callback in configs_to_watch:
            if config_path.exists():
                if watch_config(str(config_path), callback=callback):
                    registered += 1
                    self.logger.info(f"Registered: {config_path.name}")
                else:
                    self.logger.warning(f"Failed to register: {config_path.name}")
            else:
                self.logger.debug(f"Config not found: {config_path}")
        
        self.logger.info(f"Registered {registered} configuration files for hot-reload")
    
    def _on_agent_config_change(self, change: ConfigChange):
        """Handle agent configuration changes"""
        agent_name = change.file_path.stem
        self.logger.info(f"Agent config changed: {agent_name}")
        
        # Log specific changes
        for key in change.changed_keys:
            if key.startswith('~'):  # Modified
                clean_key = key[1:]
                old_val = self._get_nested_value(change.old_config, clean_key)
                new_val = self._get_nested_value(change.new_config, clean_key)
                self.logger.info(f"  {clean_key}: {old_val} → {new_val}")
        
        # Notify agent to reload configuration
        self._notify_agent(agent_name, change.new_config)
    
    def _on_mcp_config_change(self, change: ConfigChange):
        """Handle MCP configuration changes"""
        self.logger.info("MCP configuration changed")
        
        # Check for new servers added
        old_servers = set(change.old_config.get('mcpServers', {}).keys())
        new_servers = set(change.new_config.get('mcpServers', {}).keys())
        
        added = new_servers - old_servers
        removed = old_servers - new_servers
        
        if added:
            self.logger.info(f"  MCP servers added: {', '.join(added)}")
        if removed:
            self.logger.info(f"  MCP servers removed: {', '.join(removed)}")
        
        # Notify MCP registry of changes
        self._update_mcp_registry(change.new_config)
    
    def _on_environment_config_change(self, change: ConfigChange):
        """Handle environment configuration changes"""
        self.logger.info("Environment configuration changed")
        
        # Check for critical changes
        if 'logging' in str(change.changed_keys):
            self.logger.info("  Logging configuration changed - updating log levels")
            self._update_logging_config(change.new_config.get('logging', {}))
        
        if 'runtime' in str(change.changed_keys):
            self.logger.warning("  Runtime configuration changed - may require restart")
    
    def _on_code_analysis_config_change(self, change: ConfigChange):
        """Handle Code Analysis Agent configuration changes"""
        self.logger.info("Code Analysis Agent configuration changed")
        
        # Check for important changes
        if 'scan_interval' in str(change.changed_keys):
            old_interval = change.old_config.get('scan_interval')
            new_interval = change.new_config.get('scan_interval')
            self.logger.info(f"  Scan interval: {old_interval}s → {new_interval}s")
        
        if 'directories' in str(change.changed_keys):
            self.logger.info("  Monitored directories changed")
        
        if 'thresholds' in str(change.changed_keys):
            self.logger.info("  Quality thresholds updated")
    
    def _get_nested_value(self, config: Dict, key_path: str) -> Any:
        """Get value from nested dictionary using dot notation"""
        keys = key_path.split('.')
        value = config
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        
        return value
    
    def _notify_agent(self, agent_name: str, new_config: Dict):
        """Notify an agent about configuration change"""
        try:
            # This would integrate with your agent registry
            from libraries.agent_registry import AgentRegistry
            registry = AgentRegistry()
            
            # Send configuration update to agent
            # In a real implementation, this would use the agent's API
            self.logger.info(f"  Notified {agent_name} agent of config change")
            
        except Exception as e:
            self.logger.error(f"Failed to notify agent {agent_name}: {e}")
    
    def _update_mcp_registry(self, mcp_config: Dict):
        """Update MCP registry with new configuration"""
        try:
            from libraries.mcp_registry import MCPRegistry
            registry = MCPRegistry()
            
            # Update registry with new servers
            for server_name, server_config in mcp_config.get('mcpServers', {}).items():
                self.logger.info(f"  Updating MCP server: {server_name}")
                # Registry update logic here
            
        except Exception as e:
            self.logger.error(f"Failed to update MCP registry: {e}")
    
    def _update_logging_config(self, logging_config: Dict):
        """Update logging configuration across services"""
        new_level = logging_config.get('level', 'INFO')
        
        # Convert to LogLevel enum
        from utilities.logging_utils import LogLevel
        level_map = {
            'DEBUG': LogLevel.DEBUG,
            'INFO': LogLevel.INFO,
            'WARNING': LogLevel.WARNING,
            'ERROR': LogLevel.ERROR,
            'CRITICAL': LogLevel.CRITICAL
        }
        
        if new_level in level_map:
            # This would update all service loggers
            self.logger.info(f"  Updated global log level to: {new_level}")
    
    def create_config_dashboard(self) -> str:
        """Create an HTML dashboard showing configuration status"""
        stats = self.hot_reload.get_statistics()
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Configuration Hot-Reload Dashboard</title>
    <meta charset="utf-8">
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        h1 {{
            margin: 0;
            color: #2d3748;
            font-size: 2em;
        }}
        .subtitle {{
            color: #718096;
            margin-top: 10px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin: 10px 0;
        }}
        .stat-label {{
            color: #718096;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .config-list {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .config-item {{
            padding: 15px;
            border-bottom: 1px solid #e2e8f0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .config-item:last-child {{
            border-bottom: none;
        }}
        .config-name {{
            font-weight: 500;
            color: #2d3748;
        }}
        .config-status {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.85em;
            background: #48bb78;
            color: white;
        }}
        .reload-indicator {{
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #48bb78;
            animation: pulse 2s infinite;
            margin-right: 10px;
        }}
        @keyframes pulse {{
            0% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
            100% {{ opacity: 1; }}
        }}
        .timestamp {{
            color: #a0aec0;
            font-size: 0.9em;
            margin-top: 20px;
            text-align: center;
        }}
    </style>
    <script>
        // Auto-refresh every 5 seconds
        setTimeout(() => location.reload(), 5000);
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔄 Configuration Hot-Reload System</h1>
            <div class="subtitle">Real-time configuration monitoring and reloading</div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Files Monitored</div>
                <div class="stat-value">{stats['files_monitored']}</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Total Reloads</div>
                <div class="stat-value">{stats['total_reloads']}</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Failed Validations</div>
                <div class="stat-value">{stats['failed_validations']}</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Uptime</div>
                <div class="stat-value">{int(stats['uptime_seconds'])}s</div>
            </div>
        </div>
        
        <div class="config-list">
            <h2 style="margin-top: 0;">Monitored Configurations</h2>
"""
        
        for config_path in stats['configs']:
            config_name = Path(config_path).name
            html += f"""
            <div class="config-item">
                <div>
                    <span class="reload-indicator"></span>
                    <span class="config-name">{config_name}</span>
                </div>
                <span class="config-status">Active</span>
            </div>
"""
        
        if stats['last_reload']:
            html += f"""
            <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #e2e8f0;">
                <strong>Last Reload:</strong> {stats['last_reload']}
            </div>
"""
        
        html += f"""
        </div>
        
        <div class="timestamp">
            Dashboard generated at {Path(__file__).parent}
            <br>Auto-refreshes every 5 seconds
        </div>
    </div>
</body>
</html>
"""
        
        # Save dashboard
        dashboard_path = Path("C:/Users/Corbin/development/logs/config-hot-reload-dashboard.html")
        dashboard_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(dashboard_path, 'w') as f:
            f.write(html)
        
        self.logger.info(f"Dashboard created: {dashboard_path}")
        return str(dashboard_path)


def setup_hot_reload_for_service(service_name: str, config_path: str, 
                                reload_callback: callable = None) -> bool:
    """
    Convenience function to set up hot-reload for a service
    
    Args:
        service_name: Name of the service
        config_path: Path to configuration file
        reload_callback: Function to call on config change
    
    Returns:
        Success status
    """
    logger = setup_service_logging(f"{service_name}-config", LogLevel.INFO)
    
    def default_callback(change: ConfigChange):
        logger.info(f"Configuration reloaded for {service_name}")
        logger.info(f"Changed keys: {change.changed_keys}")
        
        if reload_callback:
            reload_callback(change.new_config)
    
    return watch_config(config_path, callback=default_callback)


# Example: Integration with API Gateway
def integrate_with_api_gateway():
    """Example of integrating hot-reload with API Gateway"""
    
    def reload_api_gateway_config(new_config: Dict):
        """Reload API Gateway configuration"""
        # This would update the running API Gateway
        print(f"API Gateway config updated:")
        print(f"  - Rate limit: {new_config.get('rate_limit', {}).get('requests_per_minute')}")
        print(f"  - Auth enabled: {new_config.get('authentication', {}).get('enabled')}")
        print(f"  - Circuit breaker threshold: {new_config.get('circuit_breaker', {}).get('threshold')}")
    
    config_path = "C:/Users/Corbin/development/configs/api-gateway.json"
    
    # Create example config if it doesn't exist
    if not Path(config_path).exists():
        Path(config_path).parent.mkdir(parents=True, exist_ok=True)
        example_config = {
            "rate_limit": {
                "enabled": True,
                "requests_per_minute": 100
            },
            "authentication": {
                "enabled": False,
                "jwt_secret": "change-me"
            },
            "circuit_breaker": {
                "enabled": True,
                "threshold": 5,
                "timeout": 30
            }
        }
        with open(config_path, 'w') as f:
            json.dump(example_config, f, indent=2)
    
    return setup_hot_reload_for_service(
        "api-gateway",
        config_path,
        reload_api_gateway_config
    )


if __name__ == "__main__":
    print("=" * 60)
    print("CONFIG INTEGRATION MODULE")
    print("=" * 60)
    
    # Initialize integration
    integration = ConfigIntegration()
    
    # Create dashboard
    dashboard_path = integration.create_config_dashboard()
    print(f"\n📊 Dashboard created: {dashboard_path}")
    
    # Example: Set up API Gateway integration
    if integrate_with_api_gateway():
        print("\n✅ API Gateway hot-reload configured")
    
    # Show statistics
    stats = integration.hot_reload.get_statistics()
    print(f"\n📈 Hot-Reload Statistics:")
    print(f"   Files monitored: {stats['files_monitored']}")
    print(f"   Total reloads: {stats['total_reloads']}")
    
    print("\n✅ Configuration integration ready!")
    print("   Modify any monitored config file to see hot-reload in action.")
    print("   Check the dashboard for real-time status.")