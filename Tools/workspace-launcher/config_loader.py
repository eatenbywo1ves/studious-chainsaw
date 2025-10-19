#!/usr/bin/env python3
"""
Configuration Loader - YAML-based configuration management for workspace launcher

Provides configuration loading, validation, and template variable expansion.
"""

import yaml
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


logger = logging.getLogger('workspace_manager.config')


@dataclass
class ServiceConfig:
    """Service configuration from YAML"""
    name: str
    command: str
    directory: str
    depends_on: List[str] = field(default_factory=list)
    port: Optional[int] = None
    url: Optional[str] = None
    environment: Dict[str, str] = field(default_factory=dict)
    health_check: Dict[str, Any] = field(default_factory=dict)
    startup_timeout: int = 60
    auto_restart: bool = False
    auto_open_browser: bool = False
    wait_for_port: bool = False

    def __post_init__(self):
        """Post-initialization processing"""
        # Set wait_for_port based on health_check if not explicitly set
        if self.port and not self.wait_for_port:
            health_type = self.health_check.get('type', 'none')
            self.wait_for_port = health_type in ('tcp', 'http')


@dataclass
class ProfileConfig:
    """Profile configuration from YAML"""
    name: str
    description: str
    services: List[str]
    projects: List[str] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)


class ConfigLoader:
    """Load and validate workspace configuration from YAML"""

    def __init__(self, config_path: Path):
        """
        Initialize configuration loader

        Args:
            config_path: Path to YAML configuration file
        """
        self.config_path = Path(config_path)
        self.raw_config = None
        self.base_paths = {}
        self.services = {}
        self.profiles = {}

    def load(self) -> bool:
        """
        Load configuration from YAML file

        Returns:
            True if configuration loaded successfully, False otherwise
        """
        try:
            if not self.config_path.exists():
                logger.error(f"Configuration file not found: {self.config_path}")
                return False

            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.raw_config = yaml.safe_load(f)

            if not self.raw_config:
                logger.error("Configuration file is empty")
                return False

            # Process configuration
            self._resolve_base_paths()
            self._expand_templates()
            self._parse_services()
            self._parse_profiles()

            logger.info(
                f"Configuration loaded: {len(self.services)} services, {len(self.profiles)} profiles",
                extra={
                    'config_path': str(self.config_path),
                    'services_count': len(self.services),
                    'profiles_count': len(self.profiles)
                }
            )

            return True

        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error: {e}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}", exc_info=True)
            return False

    def _resolve_base_paths(self):
        """Resolve base path templates"""
        base_paths = self.raw_config.get('base_paths', {})

        # Get home directory
        home = Path.home()

        # Replace {HOME} and store resolved paths
        for key, value in base_paths.items():
            if isinstance(value, str):
                # Replace {HOME} with actual home directory
                value = value.replace('{HOME}', str(home))
                value = value.replace('{home}', str(home))  # Case-insensitive

                # Store resolved path
                base_paths[key] = value
                self.base_paths[key] = value

        # Add default paths if not specified
        if 'home' not in self.base_paths:
            self.base_paths['home'] = str(home)

        logger.debug(f"Resolved base paths: {self.base_paths}")

    def _expand_templates(self):
        """Expand template variables in configuration"""
        def expand(value):
            """Recursively expand template variables"""
            if isinstance(value, str):
                # Replace all template variables
                for key, path in self.base_paths.items():
                    value = value.replace(f'{{{key}}}', path)
                return value
            elif isinstance(value, dict):
                return {k: expand(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [expand(item) for item in value]
            else:
                return value

        # Expand templates in entire configuration
        self.raw_config = expand(self.raw_config)

    def _parse_services(self):
        """Parse service configurations"""
        services_config = self.raw_config.get('services', {})

        for key, config in services_config.items():
            try:
                # Extract health check configuration
                health_check = config.get('health_check', {})

                # Create ServiceConfig
                service = ServiceConfig(
                    name=config['name'],
                    command=config['command'],
                    directory=config['directory'],
                    depends_on=config.get('depends_on', []),
                    port=config.get('port'),
                    url=config.get('url'),
                    environment=config.get('environment', {}),
                    health_check=health_check,
                    startup_timeout=config.get('startup_timeout', 60),
                    auto_restart=config.get('auto_restart', False),
                    auto_open_browser=config.get('auto_open_browser', False),
                    wait_for_port=config.get('wait_for_port', False)
                )

                self.services[key] = service

            except KeyError as e:
                logger.warning(f"Service '{key}' missing required field: {e}")
            except Exception as e:
                logger.warning(f"Failed to parse service '{key}': {e}")

    def _parse_profiles(self):
        """Parse profile configurations"""
        profiles_config = self.raw_config.get('profiles', {})

        for key, config in profiles_config.items():
            try:
                profile = ProfileConfig(
                    name=config['name'],
                    description=config['description'],
                    services=config.get('services', []),
                    projects=config.get('projects', []),
                    environment=config.get('environment', {})
                )

                self.profiles[key] = profile

            except KeyError as e:
                logger.warning(f"Profile '{key}' missing required field: {e}")
            except Exception as e:
                logger.warning(f"Failed to parse profile '{key}': {e}")

    def get_services(self) -> Dict[str, ServiceConfig]:
        """Get all service configurations"""
        return self.services

    def get_profiles(self) -> Dict[str, ProfileConfig]:
        """Get all profile configurations"""
        return self.profiles

    def get_service(self, service_key: str) -> Optional[ServiceConfig]:
        """Get specific service configuration"""
        return self.services.get(service_key)

    def get_profile(self, profile_key: str) -> Optional[ProfileConfig]:
        """Get specific profile configuration"""
        return self.profiles.get(profile_key)

    def validate(self) -> List[str]:
        """
        Validate configuration

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Check services exist
        if not self.services:
            errors.append("No services defined in configuration")

        # Check profiles exist
        if not self.profiles:
            errors.append("No profiles defined in configuration")

        # Validate service dependencies
        for service_key, service in self.services.items():
            for dep in service.depends_on:
                if dep not in self.services:
                    errors.append(f"Service '{service_key}' depends on undefined service '{dep}'")

        # Validate profile service references
        for profile_key, profile in self.profiles.items():
            for service in profile.services:
                if service not in self.services:
                    errors.append(f"Profile '{profile_key}' references undefined service '{service}'")

            for project in profile.projects:
                if project not in self.services:
                    errors.append(f"Profile '{profile_key}' references undefined project '{project}'")

        # Check for circular dependencies
        circular = self._check_circular_dependencies()
        if circular:
            errors.append(f"Circular dependency detected: {' -> '.join(circular)}")

        return errors

    def _check_circular_dependencies(self) -> List[str]:
        """
        Check for circular dependencies in service graph

        Returns:
            List of services in circular dependency chain (empty if none)
        """
        def has_cycle(service_key: str, visited: set, rec_stack: list) -> List[str]:
            """DFS to detect cycles"""
            visited.add(service_key)
            rec_stack.append(service_key)

            # Check all dependencies
            service = self.services.get(service_key)
            if service:
                for dep in service.depends_on:
                    if dep not in visited:
                        cycle = has_cycle(dep, visited, rec_stack)
                        if cycle:
                            return cycle
                    elif dep in rec_stack:
                        # Found cycle
                        cycle_start = rec_stack.index(dep)
                        return rec_stack[cycle_start:] + [dep]

            rec_stack.remove(service_key)
            return []

        visited = set()
        for service_key in self.services:
            if service_key not in visited:
                cycle = has_cycle(service_key, visited, [])
                if cycle:
                    return cycle

        return []

    def export_to_yaml(self, output_path: Path):
        """
        Export current configuration to YAML file

        Args:
            output_path: Path where to save configuration
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.raw_config, f, default_flow_style=False, sort_keys=False)

            logger.info(f"Configuration exported to {output_path}")

        except Exception as e:
            logger.error(f"Failed to export configuration: {e}")
            raise


# Example usage and testing
if __name__ == '__main__':
    import sys

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Test configuration loading
    config_file = Path(__file__).parent / 'workspace-config.yaml'

    if not config_file.exists():
        print(f"Configuration file not found: {config_file}")
        print("Create workspace-config.yaml first")
        sys.exit(1)

    print(f"Loading configuration from: {config_file}")
    print("-" * 60)

    loader = ConfigLoader(config_file)

    if loader.load():
        print("\n[OK] Configuration loaded successfully!")

        # Validate
        errors = loader.validate()
        if errors:
            print("\n[WARN] Validation errors:")
            for error in errors:
                print(f"  - {error}")
        else:
            print("\n[OK] Configuration is valid")

        # Show summary
        print(f"\nServices ({len(loader.services)}):")
        for key, service in loader.services.items():
            deps = f" (depends on: {', '.join(service.depends_on)})" if service.depends_on else ""
            print(f"  - {key}: {service.name}{deps}")

        print(f"\nProfiles ({len(loader.profiles)}):")
        for key, profile in loader.profiles.items():
            print(f"  - {key}: {profile.name}")
            print(f"    Services: {', '.join(profile.services)}")

    else:
        print("[ERROR] Failed to load configuration")
        sys.exit(1)
