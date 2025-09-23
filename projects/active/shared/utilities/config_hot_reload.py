#!/usr/bin/env python3
"""
Configuration Hot-Reload System
Automatically detects and applies configuration changes without service restart.
100% offline - uses only local file system monitoring.
"""

import os
import sys
import json
import yaml
import threading
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, field
from collections import defaultdict
import time
import copy
from enum import Enum

# Add logging
sys.path.insert(0, str(Path(__file__).parent.parent))
from utilities.logging_utils import setup_service_logging, LogLevel


class ConfigFormat(Enum):
    """Supported configuration file formats"""
    JSON = "json"
    YAML = "yaml"
    ENV = "env"
    INI = "ini"


@dataclass
class ConfigFile:
    """Represents a configuration file being monitored"""
    path: Path
    format: ConfigFormat
    last_modified: float
    last_hash: str
    current_config: Dict[str, Any]
    previous_configs: List[Dict[str, Any]] = field(default_factory=list)
    validation_schema: Optional[Dict] = None
    
    def get_hash(self, content: str) -> str:
        """Calculate hash of file content"""
        return hashlib.sha256(content.encode()).hexdigest()


@dataclass
class ConfigChange:
    """Represents a configuration change event"""
    file_path: Path
    timestamp: datetime
    old_config: Dict[str, Any]
    new_config: Dict[str, Any]
    changed_keys: Set[str]
    change_type: str  # 'added', 'modified', 'deleted'


class ConfigValidator:
    """Validates configuration against schemas"""
    
    def __init__(self):
        self.logger = setup_service_logging("config-validator", LogLevel.INFO)
        self.schemas = {}
    
    def register_schema(self, config_name: str, schema: Dict):
        """Register a validation schema for a configuration"""
        self.schemas[config_name] = schema
        self.logger.info(f"Registered schema for {config_name}")
    
    def validate(self, config_name: str, config: Dict) -> tuple[bool, List[str]]:
        """Validate configuration against its schema"""
        errors = []
        
        if config_name not in self.schemas:
            return True, []  # No schema, assume valid
        
        schema = self.schemas[config_name]
        
        # Check required fields
        if 'required' in schema:
            for field in schema['required']:
                if field not in config:
                    errors.append(f"Missing required field: {field}")
        
        # Check field types
        if 'properties' in schema:
            for field, rules in schema['properties'].items():
                if field in config:
                    value = config[field]
                    
                    # Type checking
                    if 'type' in rules:
                        expected_type = rules['type']
                        if not self._check_type(value, expected_type):
                            errors.append(f"Field '{field}' has wrong type. Expected {expected_type}")
                    
                    # Range checking for numbers
                    if 'minimum' in rules and isinstance(value, (int, float)):
                        if value < rules['minimum']:
                            errors.append(f"Field '{field}' below minimum: {rules['minimum']}")
                    
                    if 'maximum' in rules and isinstance(value, (int, float)):
                        if value > rules['maximum']:
                            errors.append(f"Field '{field}' above maximum: {rules['maximum']}")
                    
                    # Pattern matching for strings
                    if 'pattern' in rules and isinstance(value, str):
                        import re
                        if not re.match(rules['pattern'], value):
                            errors.append(f"Field '{field}' doesn't match pattern: {rules['pattern']}")
        
        return len(errors) == 0, errors
    
    def _check_type(self, value: Any, expected_type: str) -> bool:
        """Check if value matches expected type"""
        type_map = {
            'string': str,
            'integer': int,
            'number': (int, float),
            'boolean': bool,
            'array': list,
            'object': dict
        }
        
        if expected_type in type_map:
            return isinstance(value, type_map[expected_type])
        
        return True


class ConfigHotReload:
    """Main configuration hot-reload system"""
    
    def __init__(self, check_interval: float = 1.0):
        """
        Initialize hot-reload system
        
        Args:
            check_interval: How often to check for changes (seconds)
        """
        self.logger = setup_service_logging("config-hot-reload", LogLevel.INFO)
        self.check_interval = check_interval
        self.configs: Dict[str, ConfigFile] = {}
        self.callbacks: Dict[str, List[Callable]] = defaultdict(list)
        self.validator = ConfigValidator()
        self.running = False
        self.monitor_thread = None
        self.lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'files_monitored': 0,
            'total_reloads': 0,
            'failed_validations': 0,
            'last_reload': None,
            'uptime': datetime.now()
        }
        
        self.logger.info(f"Config hot-reload system initialized (interval: {check_interval}s)")
    
    def register_config(self, 
                       config_path: str,
                       format: ConfigFormat = None,
                       callback: Callable = None,
                       validation_schema: Dict = None) -> bool:
        """
        Register a configuration file for monitoring
        
        Args:
            config_path: Path to configuration file
            format: File format (auto-detected if None)
            callback: Function to call on config change
            validation_schema: Schema for validation
        
        Returns:
            Success status
        """
        path = Path(config_path)
        
        if not path.exists():
            self.logger.error(f"Config file not found: {config_path}")
            return False
        
        # Auto-detect format
        if format is None:
            ext = path.suffix.lower()
            format_map = {
                '.json': ConfigFormat.JSON,
                '.yaml': ConfigFormat.YAML,
                '.yml': ConfigFormat.YAML,
                '.env': ConfigFormat.ENV,
                '.ini': ConfigFormat.INI
            }
            format = format_map.get(ext, ConfigFormat.JSON)
        
        # Load initial configuration
        config = self._load_config(path, format)
        if config is None:
            return False
        
        # Validate if schema provided
        if validation_schema:
            self.validator.register_schema(str(path), validation_schema)
            valid, errors = self.validator.validate(str(path), config)
            if not valid:
                self.logger.error(f"Initial config validation failed: {errors}")
                return False
        
        # Create config file object
        with self.lock:
            config_file = ConfigFile(
                path=path,
                format=format,
                last_modified=path.stat().st_mtime,
                last_hash=self._calculate_hash(path),
                current_config=config,
                validation_schema=validation_schema
            )
            
            self.configs[str(path)] = config_file
            
            if callback:
                self.callbacks[str(path)].append(callback)
            
            self.stats['files_monitored'] += 1
        
        self.logger.info(f"Registered config: {path.name} (format: {format.value})")
        return True
    
    def _load_config(self, path: Path, format: ConfigFormat) -> Optional[Dict]:
        """Load configuration from file"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if format == ConfigFormat.JSON:
                return json.loads(content)
            elif format == ConfigFormat.YAML:
                # Simple YAML parsing without external dependency
                # For production, you'd use PyYAML
                return self._parse_simple_yaml(content)
            elif format == ConfigFormat.ENV:
                return self._parse_env(content)
            elif format == ConfigFormat.INI:
                return self._parse_ini(content)
            
        except Exception as e:
            self.logger.error(f"Failed to load config {path}: {e}")
            return None
    
    def _parse_simple_yaml(self, content: str) -> Dict:
        """Simple YAML parser for basic configs"""
        result = {}
        current_section = None
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Section header
            if not line.startswith(' ') and line.endswith(':'):
                current_section = line[:-1]
                result[current_section] = {}
            # Key-value pair
            elif ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                # Type conversion
                if value.lower() in ('true', 'false'):
                    value = value.lower() == 'true'
                elif value.isdigit():
                    value = int(value)
                elif '.' in value and value.replace('.', '').isdigit():
                    value = float(value)
                
                if current_section:
                    result[current_section][key] = value
                else:
                    result[key] = value
        
        return result
    
    def _parse_env(self, content: str) -> Dict:
        """Parse .env file format"""
        result = {}
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                result[key] = value
        
        return result
    
    def _parse_ini(self, content: str) -> Dict:
        """Parse INI file format"""
        result = {}
        current_section = 'DEFAULT'
        result[current_section] = {}
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(';') or line.startswith('#'):
                continue
            
            # Section header
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1]
                result[current_section] = {}
            # Key-value pair
            elif '=' in line:
                key, value = line.split('=', 1)
                result[current_section][key.strip()] = value.strip()
        
        return result
    
    def _calculate_hash(self, path: Path) -> str:
        """Calculate file hash"""
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    
    def start(self):
        """Start monitoring configuration files"""
        if self.running:
            self.logger.warning("Hot-reload already running")
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        self.logger.info(f"Started monitoring {len(self.configs)} configuration files")
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        self.logger.info("Stopped configuration monitoring")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                with self.lock:
                    for config_path, config_file in self.configs.items():
                        self._check_config_changes(config_file)
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"Monitor loop error: {e}", exc_info=True)
                time.sleep(self.check_interval)
    
    def _check_config_changes(self, config_file: ConfigFile):
        """Check if a configuration file has changed"""
        try:
            path = config_file.path
            
            if not path.exists():
                self.logger.warning(f"Config file disappeared: {path}")
                return
            
            # Check modification time
            current_mtime = path.stat().st_mtime
            if current_mtime <= config_file.last_modified:
                return
            
            # Check hash to confirm change
            current_hash = self._calculate_hash(path)
            if current_hash == config_file.last_hash:
                config_file.last_modified = current_mtime
                return
            
            # Load new configuration
            new_config = self._load_config(path, config_file.format)
            if new_config is None:
                self.logger.error(f"Failed to reload config: {path}")
                return
            
            # Validate new configuration
            if str(path) in self.validator.schemas:
                valid, errors = self.validator.validate(str(path), new_config)
                if not valid:
                    self.logger.error(f"Validation failed for {path.name}: {errors}")
                    self.stats['failed_validations'] += 1
                    return
            
            # Detect changes
            old_config = config_file.current_config
            changed_keys = self._detect_changes(old_config, new_config)
            
            if not changed_keys:
                self.logger.debug(f"No actual changes in {path.name}")
                config_file.last_modified = current_mtime
                config_file.last_hash = current_hash
                return
            
            # Create change event
            change = ConfigChange(
                file_path=path,
                timestamp=datetime.now(),
                old_config=copy.deepcopy(old_config),
                new_config=copy.deepcopy(new_config),
                changed_keys=changed_keys,
                change_type='modified'
            )
            
            # Store previous config for rollback
            config_file.previous_configs.append(copy.deepcopy(old_config))
            if len(config_file.previous_configs) > 10:  # Keep last 10 versions
                config_file.previous_configs.pop(0)
            
            # Update current config
            config_file.current_config = new_config
            config_file.last_modified = current_mtime
            config_file.last_hash = current_hash
            
            # Log changes
            self.logger.info(f"Config reloaded: {path.name}")
            self.logger.info(f"  Changed keys: {', '.join(changed_keys)}")
            
            # Update statistics
            self.stats['total_reloads'] += 1
            self.stats['last_reload'] = datetime.now()
            
            # Notify callbacks
            self._notify_callbacks(str(path), change)
            
        except Exception as e:
            self.logger.error(f"Error checking config {config_file.path}: {e}", exc_info=True)
    
    def _detect_changes(self, old_config: Dict, new_config: Dict) -> Set[str]:
        """Detect which keys have changed"""
        changed = set()
        
        # Check for modified and deleted keys
        for key in old_config:
            if key not in new_config:
                changed.add(f"-{key}")  # Deleted
            elif old_config[key] != new_config.get(key):
                changed.add(f"~{key}")  # Modified
        
        # Check for added keys
        for key in new_config:
            if key not in old_config:
                changed.add(f"+{key}")  # Added
        
        return changed
    
    def _notify_callbacks(self, config_path: str, change: ConfigChange):
        """Notify registered callbacks of configuration change"""
        callbacks = self.callbacks.get(config_path, [])
        
        for callback in callbacks:
            try:
                callback(change)
            except Exception as e:
                self.logger.error(f"Callback error for {config_path}: {e}", exc_info=True)
    
    def get_config(self, config_path: str) -> Optional[Dict]:
        """Get current configuration"""
        with self.lock:
            config_file = self.configs.get(config_path)
            if config_file:
                return copy.deepcopy(config_file.current_config)
        return None
    
    def reload_config(self, config_path: str) -> bool:
        """Manually trigger configuration reload"""
        with self.lock:
            config_file = self.configs.get(config_path)
            if config_file:
                self._check_config_changes(config_file)
                return True
        return False
    
    def rollback_config(self, config_path: str, versions_back: int = 1) -> bool:
        """Rollback configuration to previous version"""
        with self.lock:
            config_file = self.configs.get(config_path)
            if not config_file:
                return False
            
            if len(config_file.previous_configs) < versions_back:
                self.logger.error(f"Not enough history to rollback {versions_back} versions")
                return False
            
            # Get previous config
            previous_config = config_file.previous_configs[-versions_back]
            
            # Save current as previous
            config_file.previous_configs.append(copy.deepcopy(config_file.current_config))
            
            # Restore previous
            config_file.current_config = copy.deepcopy(previous_config)
            
            # Write to file
            try:
                self._write_config(config_file.path, config_file.format, previous_config)
                
                # Update file tracking
                config_file.last_modified = config_file.path.stat().st_mtime
                config_file.last_hash = self._calculate_hash(config_file.path)
                
                self.logger.info(f"Rolled back config: {config_file.path.name}")
                return True
                
            except Exception as e:
                self.logger.error(f"Failed to rollback config: {e}")
                return False
    
    def _write_config(self, path: Path, format: ConfigFormat, config: Dict):
        """Write configuration back to file"""
        if format == ConfigFormat.JSON:
            content = json.dumps(config, indent=2)
        elif format == ConfigFormat.YAML:
            content = self._generate_yaml(config)
        elif format == ConfigFormat.ENV:
            content = self._generate_env(config)
        elif format == ConfigFormat.INI:
            content = self._generate_ini(config)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def _generate_yaml(self, config: Dict) -> str:
        """Generate YAML content"""
        lines = []
        for key, value in config.items():
            if isinstance(value, dict):
                lines.append(f"{key}:")
                for sub_key, sub_value in value.items():
                    lines.append(f"  {sub_key}: {sub_value}")
            else:
                lines.append(f"{key}: {value}")
        return '\n'.join(lines)
    
    def _generate_env(self, config: Dict) -> str:
        """Generate .env content"""
        lines = []
        for key, value in config.items():
            if isinstance(value, str) and ' ' in value:
                value = f'"{value}"'
            lines.append(f"{key}={value}")
        return '\n'.join(lines)
    
    def _generate_ini(self, config: Dict) -> str:
        """Generate INI content"""
        lines = []
        for section, values in config.items():
            lines.append(f"[{section}]")
            if isinstance(values, dict):
                for key, value in values.items():
                    lines.append(f"{key} = {value}")
            lines.append("")
        return '\n'.join(lines)
    
    def get_statistics(self) -> Dict:
        """Get hot-reload statistics"""
        uptime = (datetime.now() - self.stats['uptime']).total_seconds()
        
        return {
            'files_monitored': self.stats['files_monitored'],
            'total_reloads': self.stats['total_reloads'],
            'failed_validations': self.stats['failed_validations'],
            'last_reload': self.stats['last_reload'].isoformat() if self.stats['last_reload'] else None,
            'uptime_seconds': uptime,
            'configs': list(self.configs.keys())
        }


# Convenience functions for easy integration
_global_hot_reload = None

def get_hot_reload() -> ConfigHotReload:
    """Get or create global hot-reload instance"""
    global _global_hot_reload
    if _global_hot_reload is None:
        _global_hot_reload = ConfigHotReload()
        _global_hot_reload.start()
    return _global_hot_reload


def watch_config(config_path: str, 
                callback: Callable = None,
                validation_schema: Dict = None) -> bool:
    """Convenience function to watch a configuration file"""
    hot_reload = get_hot_reload()
    return hot_reload.register_config(config_path, callback=callback, validation_schema=validation_schema)


def get_config(config_path: str) -> Optional[Dict]:
    """Get current configuration value"""
    hot_reload = get_hot_reload()
    return hot_reload.get_config(config_path)


def reload_config(config_path: str) -> bool:
    """Manually reload a configuration"""
    hot_reload = get_hot_reload()
    return hot_reload.reload_config(config_path)


# Example usage and testing
if __name__ == "__main__":
    import tempfile
    
    print("=" * 60)
    print("CONFIG HOT-RELOAD SYSTEM TEST")
    print("=" * 60)
    
    # Create test config file
    test_dir = Path(tempfile.gettempdir()) / "config_hot_reload_test"
    test_dir.mkdir(exist_ok=True)
    
    test_config_path = test_dir / "test_config.json"
    test_config = {
        "service": {
            "name": "test-service",
            "port": 8080,
            "debug": False
        },
        "database": {
            "host": "localhost",
            "port": 5432
        }
    }
    
    with open(test_config_path, 'w') as f:
        json.dump(test_config, f, indent=2)
    
    print(f"Created test config: {test_config_path}")
    
    # Define callback
    def on_config_change(change: ConfigChange):
        print(f"\n🔄 Configuration changed at {change.timestamp}")
        print(f"   File: {change.file_path.name}")
        print(f"   Changed keys: {change.changed_keys}")
        for key in change.changed_keys:
            if key.startswith('~'):  # Modified
                clean_key = key[1:]
                print(f"   {clean_key}: {change.old_config.get(clean_key)} → {change.new_config.get(clean_key)}")
    
    # Define validation schema
    schema = {
        "required": ["service", "database"],
        "properties": {
            "service": {
                "type": "object",
                "properties": {
                    "port": {
                        "type": "integer",
                        "minimum": 1024,
                        "maximum": 65535
                    }
                }
            }
        }
    }
    
    # Start hot-reload
    hot_reload = ConfigHotReload(check_interval=0.5)
    hot_reload.register_config(
        str(test_config_path),
        callback=on_config_change,
        validation_schema=schema
    )
    hot_reload.start()
    
    print("\n✅ Hot-reload system started!")
    print("   Monitoring:", test_config_path.name)
    print("\nTry modifying the test config file to see hot-reload in action.")
    print("The system will detect changes within 0.5 seconds.")
    
    # Simulate config change after 2 seconds
    def simulate_change():
        time.sleep(2)
        print("\n📝 Simulating configuration change...")
        test_config["service"]["port"] = 9090
        test_config["service"]["debug"] = True
        with open(test_config_path, 'w') as f:
            json.dump(test_config, f, indent=2)
    
    change_thread = threading.Thread(target=simulate_change)
    change_thread.start()
    
    # Run for 5 seconds
    try:
        time.sleep(5)
    except KeyboardInterrupt:
        pass
    
    # Show statistics
    stats = hot_reload.get_statistics()
    print("\n📊 Statistics:")
    print(f"   Files monitored: {stats['files_monitored']}")
    print(f"   Total reloads: {stats['total_reloads']}")
    print(f"   Failed validations: {stats['failed_validations']}")
    
    # Cleanup
    hot_reload.stop()
    test_config_path.unlink()
    test_dir.rmdir()
    
    print("\n✅ Test completed successfully!")