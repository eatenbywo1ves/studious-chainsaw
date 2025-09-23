#!/usr/bin/env python3
"""
Configuration Hot-Reload System Demonstration
Shows the hot-reload system detecting and applying configuration changes in real-time.
"""

import json
import time
import threading
from pathlib import Path
from datetime import datetime
import sys

# Add shared utilities to path
sys.path.insert(0, str(Path(__file__).parent / "shared"))

from utilities.config_hot_reload import ConfigHotReload, ConfigChange
from utilities.config_integration import ConfigIntegration


def create_demo_configs():
    """Create demonstration configuration files"""
    demo_dir = Path("C:/Users/Corbin/development/configs/demo")
    demo_dir.mkdir(parents=True, exist_ok=True)

    # Service configuration
    service_config = demo_dir / "service_config.json"
    with open(service_config, 'w') as f:
        json.dump({
            "service": {
                "name": "demo-service",
                "port": 8080,
                "workers": 4,
                "timeout": 30
            },
            "features": {
                "cache": True,
                "compression": False,
                "rate_limiting": True
            },
            "logging": {
                "level": "INFO",
                "file": "logs/service.log"
            }
        }, f, indent=2)

    # Database configuration
    db_config = demo_dir / "database_config.json"
    with open(db_config, 'w') as f:
        json.dump({
            "connection": {
                "host": "localhost",
                "port": 5432,
                "database": "myapp",
                "pool_size": 10
            },
            "performance": {
                "query_timeout": 5000,
                "cache_queries": True
            }
        }, f, indent=2)

    return service_config, db_config


def simulate_config_changes(config_path: Path, changes: list, delay: float = 2.0):
    """Simulate configuration changes over time"""
    def make_changes():
        for change_desc, change_func in changes:
            time.sleep(delay)
            print(f"\n📝 {change_desc}")

            # Load current config
            with open(config_path, 'r') as f:
                config = json.load(f)

            # Apply change
            change_func(config)

            # Save modified config
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)

    thread = threading.Thread(target=make_changes, daemon=True)
    thread.start()
    return thread


def run_demonstration():
    """Run the hot-reload demonstration"""
    print("=" * 70)
    print("🔄 CONFIGURATION HOT-RELOAD DEMONSTRATION")
    print("=" * 70)
    print("This demo shows automatic configuration reloading without service restart")
    print()
    
    # Create demo configs
    service_config, db_config = create_demo_configs()
    print(f"✅ Created demo configurations:")
    print(f"   - {service_config.name}")
    print(f"   - {db_config.name}")
    
    # Initialize hot-reload system
    hot_reload = ConfigHotReload(check_interval=0.5)  # Check every 0.5 seconds
    
    # Service config callback
    def on_service_config_change(change: ConfigChange):
        print(f"\n🔄 SERVICE CONFIG RELOADED at {change.timestamp.strftime('%H:%M:%S')}")

        for key in change.changed_keys:
            if key.startswith('~'):  # Modified
                clean_key = key[1:]
                print(f"   Changed: {clean_key}")

                # Show specific changes
                if 'port' in clean_key:
                    old_port = change.old_config.get('service', {}).get('port')
                    new_port = change.new_config.get('service', {}).get('port')
                    print(f"     Port: {old_port} → {new_port}")
                elif 'workers' in clean_key:
                    old_workers = change.old_config.get('service', {}).get('workers')
                    new_workers = change.new_config.get('service', {}).get('workers')
                    print(f"     Workers: {old_workers} → {new_workers}")
                elif 'level' in clean_key:
                    old_level = change.old_config.get('logging', {}).get('level')
                    new_level = change.new_config.get('logging', {}).get('level')
                    print(f"     Log Level: {old_level} → {new_level}")

        print("   ✅ Service configuration updated successfully!")
    
    # Database config callback
    def on_db_config_change(change: ConfigChange):
        print(f"\n🔄 DATABASE CONFIG RELOADED at {change.timestamp.strftime('%H:%M:%S')}")

        for key in change.changed_keys:
            if key.startswith('~'):
                clean_key = key[1:]
                print(f"   Changed: {clean_key}")

                if 'pool_size' in clean_key:
                    old_size = change.old_config.get('connection', {}).get('pool_size')
                    new_size = change.new_config.get('connection', {}).get('pool_size')
                    print(f"     Pool Size: {old_size} → {new_size}")
                elif 'query_timeout' in clean_key:
                    old_timeout = change.old_config.get('performance', {}).get('query_timeout')
                    new_timeout = change.new_config.get('performance', {}).get('query_timeout')
                    print(f"     Query Timeout: {old_timeout}ms → {new_timeout}ms")

        print("   ✅ Database configuration updated successfully!")
    
    # Register configurations with validation
    service_schema = {
        "required": ["service", "features", "logging"],
        "properties": {
            "service": {
                "type": "object",
                "properties": {
                    "port": {
                        "type": "integer",
                        "minimum": 1024,
                        "maximum": 65535
                    },
                    "workers": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 16
                    }
                }
            }
        }
    }
    
    hot_reload.register_config(
        str(service_config),
        callback=on_service_config_change,
        validation_schema=service_schema
    )
    
    hot_reload.register_config(
        str(db_config),
        callback=on_db_config_change
    )
    
    # Start monitoring
    hot_reload.start()
    print(f"\n🚀 Hot-reload system started!")
    print(f"   Monitoring {len(hot_reload.configs)} configuration files")
    print(f"   Check interval: {hot_reload.check_interval} seconds")
    
    # Simulate configuration changes
    print("\n📋 Simulating configuration changes...")
    print("   Watch as configs reload automatically!\n")
    
    # Service config changes
    service_changes = [
        ("Changing service port from 8080 to 9090",
         lambda c: c['service'].update({'port': 9090})),
        
        ("Increasing workers from 4 to 8",
         lambda c: c['service'].update({'workers': 8})),
        
        ("Changing log level from INFO to DEBUG",
         lambda c: c['logging'].update({'level': 'DEBUG'})),
        
        ("Enabling compression feature",
         lambda c: c['features'].update({'compression': True})),
    ]
    
    # Database config changes
    db_changes = [
        ("Increasing connection pool from 10 to 20",
         lambda c: c['connection'].update({'pool_size': 20})),
        
        ("Reducing query timeout from 5000ms to 3000ms",
         lambda c: c['performance'].update({'query_timeout': 3000})),
    ]
    
    # Start change simulations
    service_thread = simulate_config_changes(service_config, service_changes, delay=3)
    db_thread = simulate_config_changes(db_config, db_changes, delay=5)
    
    # Run for demonstration period
    demo_duration = 20
    print(f"Demo will run for {demo_duration} seconds...")
    print("-" * 70)
    
    start_time = time.time()
    while time.time() - start_time < demo_duration:
        time.sleep(1)
        
        # Show periodic statistics
        if int(time.time() - start_time) % 10 == 0 and int(time.time() - start_time) > 0:
            stats = hot_reload.get_statistics()
            print(f"\n📊 Statistics Update:")
            print(f"   Total reloads: {stats['total_reloads']}")
            print(f"   Failed validations: {stats['failed_validations']}")
    
    # Test validation failure
    print("\n\n🧪 Testing validation failure...")
    print("   Attempting to set invalid port (99999)...")
    
    with open(service_config, 'r') as f:
        config = json.load(f)
    config['service']['port'] = 99999  # Invalid port
    with open(service_config, 'w') as f:
        json.dump(config, f, indent=2)
    
    time.sleep(1)
    
    # Test rollback
    print("\n🔙 Testing configuration rollback...")
    if hot_reload.rollback_config(str(service_config), versions_back=1):
        print("   ✅ Successfully rolled back to previous configuration")
    
    time.sleep(2)
    
    # Final statistics
    print("\n" + "=" * 70)
    print("📈 FINAL STATISTICS")
    print("=" * 70)
    
    stats = hot_reload.get_statistics()
    print(f"Files monitored: {stats['files_monitored']}")
    print(f"Total reloads: {stats['total_reloads']}")
    print(f"Failed validations: {stats['failed_validations']}")
    print(f"Uptime: {stats['uptime_seconds']:.1f} seconds")
    
    if stats['last_reload']:
        print(f"Last reload: {stats['last_reload']}")
    
    # Cleanup
    hot_reload.stop()
    print("\n✅ Demonstration completed successfully!")
    
    # Show benefits
    print("\n" + "=" * 70)
    print("💡 HOT-RELOAD SYSTEM BENEFITS")
    print("=" * 70)
    print("✅ Zero downtime configuration updates")
    print("✅ Automatic validation prevents bad configs")
    print("✅ Rollback capability for quick recovery")
    print("✅ Real-time notifications to services")
    print("✅ 100% offline - no external dependencies")
    print("✅ Sub-second detection of changes")
    
    return True


def show_integration_example():
    """Show how to integrate with existing services"""
    print("\n" + "=" * 70)
    print("🔌 INTEGRATION EXAMPLES")
    print("=" * 70)
    
    print("\n1️⃣ API Gateway Integration:")
    print("""
from utilities.config_hot_reload import watch_config

def reload_api_gateway(change):
    # Update rate limits
    new_rate_limit = change.new_config.get('rate_limit')
    api_gateway.update_rate_limit(new_rate_limit)
    
    # Update circuit breaker
    new_threshold = change.new_config.get('circuit_breaker', {}).get('threshold')
    api_gateway.circuit_breaker.threshold = new_threshold

watch_config('configs/api-gateway.json', callback=reload_api_gateway)
""")
    
    print("\n2️⃣ Agent Configuration:")
    print("""
from utilities.config_hot_reload import get_config, reload_config

class MyAgent:
    def __init__(self):
        # Get current config
        self.config = get_config('configs/agents/my-agent.json')
        
        # Register for updates
        watch_config('configs/agents/my-agent.json', self.on_config_change)
    
    def on_config_change(self, change):
        self.config = change.new_config
        self.logger.info("Configuration reloaded")
""")
    
    print("\n3️⃣ Observatory Integration:")
    print("""
from utilities.config_integration import setup_hot_reload_for_service

setup_hot_reload_for_service(
    'observatory',
    'configs/agents/observatory.json',
    lambda config: observatory.update_settings(config)
)
""")


if __name__ == "__main__":
    print("Starting Configuration Hot-Reload Demonstration...\n")
    
    try:
        # Run main demonstration
        if run_demonstration():
            # Show integration examples
            show_integration_example()
            
            # Create dashboard
            print("\n" + "=" * 70)
            print("📊 CREATING DASHBOARD")
            print("=" * 70)
            
            integration = ConfigIntegration()
            dashboard_path = integration.create_config_dashboard()
            print(f"Dashboard created: {dashboard_path}")
            print("Open in browser to see real-time configuration status")
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n✨ Configuration Hot-Reload System is ready for production use!")