"""
Centralized Configuration Management System
Provides environment-specific configs, validation, and hot-reload capabilities
"""

import json
import os
import logging
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from enum import Enum
import yaml
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import jsonschema
from copy import deepcopy


class Environment(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TEST = "test"


class ConfigFormat(Enum):
    JSON = "json"
    YAML = "yaml"


@dataclass
class ConfigSchema:
    """Configuration schema for validation"""

    name: str
    version: str = "1.0.0"
    schema: Dict[str, Any] = field(default_factory=dict)
    required_fields: List[str] = field(default_factory=list)

    def validate(self, config: Dict[str, Any]) -> bool:
        """Validate configuration against schema"""
        try:
            jsonschema.validate(config, self.schema)
            return True
        except jsonschema.ValidationError:
            return False


class ConfigurationManager:
    """Centralized configuration management"""

    def __init__(
        self, base_path: Optional[str] = None, environment: Optional[Environment] = None
    ):
        """Initialize configuration manager"""
        self.base_path = base_path or self._get_default_base_path()
        self.environment = environment or self._detect_environment()
        self.configs: Dict[str, Dict[str, Any]] = {}
        self.schemas: Dict[str, ConfigSchema] = {}
        self.logger = self._setup_logging()
        self.callbacks: Dict[str, List[Callable]] = {}
        self.observer: Optional[Observer] = None
        self.file_handler: Optional[ConfigFileHandler] = None
        self._config_cache: Dict[str, Any] = {}
        self._load_initial_configs()

    def _setup_logging(self) -> logging.Logger:
        """Setup structured logging"""
        logger = logging.getLogger("ConfigManager")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "component": "ConfigManager", '
                '"level": "%(levelname)s", "message": "%(message)s"}'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _get_default_base_path(self) -> str:
        """Get default configuration base path"""
        return os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "configs"
        )

    def _detect_environment(self) -> Environment:
        """Detect current environment"""
        env = os.environ.get("ENVIRONMENT", "development").lower()
        try:
            return Environment(env)
        except ValueError:
            self.logger.warning(
                f"Unknown environment '{env}', defaulting to development"
            )
            return Environment.DEVELOPMENT

    def _load_initial_configs(self):
        """Load initial configuration files"""
        self.logger.info(
            f"Loading configs from {self.base_path} for {self.environment.value}"
        )

        # Load base configuration
        self._load_config_file("base.json", "base")

        # Load environment-specific configuration
        env_file = f"{self.environment.value}.json"
        if os.path.exists(os.path.join(self.base_path, env_file)):
            self._load_config_file(env_file, "environment")

        # Load unified configuration
        if os.path.exists(os.path.join(self.base_path, "unified_config.json")):
            self._load_config_file("unified_config.json", "unified")

        # Merge configurations
        self._merge_configs()

    def _load_config_file(self, filename: str, namespace: str):
        """Load a configuration file"""
        filepath = os.path.join(self.base_path, filename)

        if not os.path.exists(filepath):
            self.logger.warning(f"Config file not found: {filepath}")
            return

        try:
            with open(filepath, "r") as f:
                if filename.endswith(".json"):
                    config = json.load(f)
                elif filename.endswith(".yaml") or filename.endswith(".yml"):
                    config = yaml.safe_load(f)
                else:
                    self.logger.error(f"Unsupported file format: {filename}")
                    return

                self.configs[namespace] = config
                self.logger.info(f"Loaded config: {namespace} from {filename}")

        except Exception as e:
            self.logger.error(f"Failed to load config {filename}: {e}")

    def _merge_configs(self):
        """Merge configurations with environment overrides"""
        merged = {}

        # Start with base config
        if "base" in self.configs:
            merged = deepcopy(self.configs["base"])

        # Override with environment-specific config
        if "environment" in self.configs:
            merged = self._deep_merge(merged, self.configs["environment"])

        # Apply unified config if available
        if "unified" in self.configs:
            merged = self._deep_merge(merged, self.configs["unified"])

        self._config_cache = merged

    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """Deep merge two dictionaries"""
        result = deepcopy(base)

        for key, value in override.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = deepcopy(value)

        return result

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)"""
        keys = key.split(".")
        value = self._config_cache

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any, persist: bool = False):
        """Set configuration value"""
        keys = key.split(".")
        config = self._config_cache

        # Navigate to the parent
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        # Set the value
        old_value = config.get(keys[-1])
        config[keys[-1]] = value

        # Trigger callbacks
        self._trigger_callbacks(key, old_value, value)

        # Persist if requested
        if persist:
            self._save_config()

    def _save_config(self):
        """Save current configuration to file"""
        try:
            output_file = os.path.join(
                self.base_path, f"{self.environment.value}_runtime.json"
            )

            with open(output_file, "w") as f:
                json.dump(self._config_cache, f, indent=2)

            self.logger.info(f"Saved configuration to {output_file}")

        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")

    def reload(self):
        """Reload configuration from files"""
        self.logger.info("Reloading configuration")
        self.configs.clear()
        self._config_cache.clear()
        self._load_initial_configs()
        self._trigger_callbacks("__reload__", None, None)

    def validate(self, schema_name: str, config: Optional[Dict] = None) -> bool:
        """Validate configuration against schema"""
        if schema_name not in self.schemas:
            self.logger.warning(f"Schema '{schema_name}' not found")
            return True

        config_to_validate = config or self._config_cache
        schema = self.schemas[schema_name]

        try:
            return schema.validate(config_to_validate)
        except Exception as e:
            self.logger.error(f"Validation failed: {e}")
            return False

    def register_schema(self, schema: ConfigSchema):
        """Register a configuration schema"""
        self.schemas[schema.name] = schema
        self.logger.info(f"Registered schema: {schema.name}")

    def watch(self, callback: Callable[[str, Any, Any], None]):
        """Watch for configuration changes"""
        if not self.observer:
            self.file_handler = ConfigFileHandler(self)
            self.observer = Observer()
            self.observer.schedule(self.file_handler, self.base_path, recursive=False)
            self.observer.start()
            self.logger.info("Started configuration file watcher")

        # Generate unique callback ID
        callback_id = f"callback_{len(self.callbacks)}"
        self.callbacks[callback_id] = callback

        return callback_id

    def unwatch(self, callback_id: str):
        """Remove a configuration change callback"""
        if callback_id in self.callbacks:
            del self.callbacks[callback_id]

    def _trigger_callbacks(self, key: str, old_value: Any, new_value: Any):
        """Trigger configuration change callbacks"""
        for callback_id, callback in self.callbacks.items():
            try:
                callback(key, old_value, new_value)
            except Exception as e:
                self.logger.error(f"Callback {callback_id} error: {e}")

    def stop_watching(self):
        """Stop watching for configuration changes"""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            self.logger.info("Stopped configuration file watcher")

    def get_all(self) -> Dict[str, Any]:
        """Get all configuration"""
        return deepcopy(self._config_cache)

    def get_service_config(self, service_name: str) -> Dict[str, Any]:
        """Get configuration for a specific service"""
        # Check in services section
        service_config = self.get(f"services.{service_name}", {})

        # Check in agents section
        if not service_config:
            service_config = self.get(f"services.agents.{service_name}", {})

        # Check in MCP servers section
        if not service_config:
            service_config = self.get(f"services.mcp_servers.{service_name}", {})

        return service_config

    def get_infrastructure_config(self) -> Dict[str, Any]:
        """Get infrastructure configuration"""
        return self.get("infrastructure", {})

    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration"""
        return self.get(
            "infrastructure.logging",
            {"level": "INFO", "format": "json", "destinations": ["console"]},
        )

    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring configuration"""
        return self.get(
            "infrastructure.monitoring",
            {"metrics_enabled": True, "tracing_enabled": False, "sample_rate": 0.1},
        )

    def export(self, format: ConfigFormat = ConfigFormat.JSON) -> str:
        """Export configuration as string"""
        if format == ConfigFormat.JSON:
            return json.dumps(self._config_cache, indent=2)
        elif format == ConfigFormat.YAML:
            return yaml.dump(self._config_cache, default_flow_style=False)
        else:
            raise ValueError(f"Unsupported format: {format}")


class ConfigFileHandler(FileSystemEventHandler):
    """Handler for configuration file changes"""

    def __init__(self, config_manager: ConfigurationManager):
        self.config_manager = config_manager
        self.last_reload = 0
        self.reload_cooldown = 1  # seconds

    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return

        # Check if it's a config file
        if event.src_path.endswith(".json") or event.src_path.endswith(".yaml"):
            current_time = time.time()

            # Prevent rapid reloads
            if current_time - self.last_reload > self.reload_cooldown:
                self.last_reload = current_time
                self.config_manager.logger.info(
                    f"Config file changed: {event.src_path}"
                )
                self.config_manager.reload()


# Singleton instance
_config_instance: Optional[ConfigurationManager] = None


def get_config_manager() -> ConfigurationManager:
    """Get singleton configuration manager instance"""
    global _config_instance
    if _config_instance is None:
        _config_instance = ConfigurationManager()
    return _config_instance


# Convenience functions
def get_config(key: str, default: Any = None) -> Any:
    """Get configuration value"""
    return get_config_manager().get(key, default)


def set_config(key: str, value: Any, persist: bool = False):
    """Set configuration value"""
    get_config_manager().set(key, value, persist)


def reload_config():
    """Reload configuration"""
    get_config_manager().reload()
