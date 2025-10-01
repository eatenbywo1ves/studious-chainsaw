#!/usr/bin/env python3
"""
Monitoring Stack Setup Script for Catalytic Computing Platform

This script sets up the complete monitoring stack including:
- Prometheus configuration validation
- Grafana dashboard deployment
- Alert rules configuration
- Health checks for all components
"""

import os
import sys
import json
import yaml
import subprocess
import time
import requests
from pathlib import Path
from typing import Dict, List, Optional
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MonitoringStackSetup:
    """Handles complete monitoring stack setup and validation."""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.monitoring_dir = project_root / "monitoring"
        self.grafana_dir = self.monitoring_dir / "grafana"
        self.prometheus_dir = self.monitoring_dir / "prometheus"
        
    def validate_docker_compose(self) -> bool:
        """Validate Docker Compose configuration."""
        compose_file = self.project_root / "docker-compose.yml"
        
        if not compose_file.exists():
            logger.error("❌ docker-compose.yml not found")
            return False
            
        try:
            with open(compose_file) as f:
                compose_data = yaml.safe_load(f)
                
            # Check for monitoring services
            services = compose_data.get('services', {})
            required_services = ['prometheus', 'grafana']
            
            missing_services = [svc for svc in required_services if svc not in services]
            if missing_services:
                logger.warning(f"⚠️ Missing monitoring services: {', '.join(missing_services)}")
                return False
                
            logger.info("✅ Docker Compose configuration validated")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error validating Docker Compose: {e}")
            return False
    
    def setup_prometheus_config(self) -> bool:
        """Setup Prometheus configuration."""
        prometheus_config = self.prometheus_dir / "prometheus.yml"
        
        # Create prometheus directory if it doesn't exist
        self.prometheus_dir.mkdir(parents=True, exist_ok=True)
        
        if prometheus_config.exists():
            logger.info("✅ Prometheus configuration already exists")
            return True
            
        # Create default Prometheus configuration
        config = {
            'global': {
                'scrape_interval': '15s',
                'evaluation_interval': '15s'
            },
            'rule_files': [
                "alerts/*.yml"
            ],
            'scrape_configs': [
                {
                    'job_name': 'prometheus',
                    'static_configs': [{'targets': ['localhost:9090']}]
                },
                {
                    'job_name': 'catalytic-api',
                    'static_configs': [{'targets': ['catalytic-api:8082']}]
                },
                {
                    'job_name': 'saas-api',
                    'static_configs': [{'targets': ['saas-api:8001']}]
                },
                {
                    'job_name': 'webhook-system',
                    'static_configs': [{'targets': ['webhook-system:9090']}]
                }
            ]
        }
        
        try:
            with open(prometheus_config, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            
            logger.info("✅ Prometheus configuration created")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error creating Prometheus config: {e}")
            return False
    
    def setup_alert_rules(self) -> bool:
        """Setup Prometheus alert rules."""
        alerts_dir = self.prometheus_dir / "alerts"
        alerts_dir.mkdir(parents=True, exist_ok=True)
        
        alert_rules = {
            'groups': [
                {
                    'name': 'catalytic-computing-alerts',
                    'rules': [
                        {
                            'alert': 'HighAPIResponseTime',
                            'expr': 'histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job="catalytic-api"}[5m])) > 1',
                            'for': '5m',
                            'labels': {'severity': 'warning'},
                            'annotations': {
                                'summary': 'High API response time detected',
                                'description': '95th percentile response time is {{ $value }}s'
                            }
                        },
                        {
                            'alert': 'HighErrorRate',
                            'expr': 'rate(http_requests_total{status=~"5.."}[5m]) > 0.1',
                            'for': '2m',
                            'labels': {'severity': 'critical'},
                            'annotations': {
                                'summary': 'High error rate detected',
                                'description': 'Error rate is {{ $value }} req/sec'
                            }
                        },
                        {
                            'alert': 'MemoryEfficiencyBelowTarget',
                            'expr': 'catalytic_memory_efficiency_ratio < 20000',
                            'for': '10m',
                            'labels': {'severity': 'warning'},
                            'annotations': {
                                'summary': 'Memory efficiency below target',
                                'description': 'Current efficiency ratio: {{ $value }}, target: 28571'
                            }
                        },
                        {
                            'alert': 'ProcessingSpeedBelowTarget',
                            'expr': 'catalytic_processing_speed_ratio < 500',
                            'for': '10m',
                            'labels': {'severity': 'warning'},
                            'annotations': {
                                'summary': 'Processing speed below target',
                                'description': 'Current speed ratio: {{ $value }}, target: 649'
                            }
                        },
                        {
                            'alert': 'DatabaseConnectionPoolExhausted',
                            'expr': 'db_connections_waiting > 10',
                            'for': '2m',
                            'labels': {'severity': 'critical'},
                            'annotations': {
                                'summary': 'Database connection pool exhausted',
                                'description': '{{ $value }} connections waiting'
                            }
                        },
                        {
                            'alert': 'LowCacheHitRate',
                            'expr': 'rate(redis_keyspace_hits_total[5m]) / (rate(redis_keyspace_hits_total[5m]) + rate(redis_keyspace_misses_total[5m])) < 0.8',
                            'for': '5m',
                            'labels': {'severity': 'warning'},
                            'annotations': {
                                'summary': 'Low Redis cache hit rate',
                                'description': 'Cache hit rate: {{ $value | humanizePercentage }}'
                            }
                        }
                    ]
                }
            ]
        }
        
        try:
            alerts_file = alerts_dir / "catalytic-computing.yml"
            with open(alerts_file, 'w') as f:
                yaml.dump(alert_rules, f, default_flow_style=False)
            
            logger.info("✅ Alert rules created")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error creating alert rules: {e}")
            return False
    
    def wait_for_services(self, timeout: int = 300) -> bool:
        """Wait for monitoring services to be ready."""
        services = {
            'Grafana': 'http://localhost:3000/api/health',
            'Prometheus': 'http://localhost:9090/-/healthy'
        }
        
        start_time = time.time()
        
        for service_name, health_url in services.items():
            logger.info(f"⏳ Waiting for {service_name} to be ready...")
            
            while time.time() - start_time < timeout:
                try:
                    response = requests.get(health_url, timeout=5)
                    if response.status_code == 200:
                        logger.info(f"✅ {service_name} is ready")
                        break
                except requests.RequestException:
                    pass
                
                time.sleep(5)
            else:
                logger.error(f"❌ {service_name} failed to become ready within {timeout}s")
                return False
        
        return True
    
    def run_docker_compose(self) -> bool:
        """Start the monitoring stack with Docker Compose."""
        try:
            logger.info("🚀 Starting monitoring stack...")
            
            # Start monitoring services
            result = subprocess.run([
                'docker', 'compose', '--profile', 'monitoring', 'up', '-d'
            ], cwd=self.project_root, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"❌ Failed to start monitoring stack: {result.stderr}")
                return False
            
            logger.info("✅ Monitoring stack started")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error starting monitoring stack: {e}")
            return False

def main():
    """Main setup function."""
    project_root = Path(__file__).parent.parent
    setup = MonitoringStackSetup(project_root)
    
    logger.info("🚀 Setting up Catalytic Computing monitoring stack")
    
    # Validate Docker Compose configuration
    if not setup.validate_docker_compose():
        logger.error("❌ Docker Compose validation failed")
        sys.exit(1)
    
    # Setup Prometheus configuration
    if not setup.setup_prometheus_config():
        logger.error("❌ Prometheus setup failed")
        sys.exit(1)
    
    # Setup alert rules
    if not setup.setup_alert_rules():
        logger.error("❌ Alert rules setup failed")
        sys.exit(1)
    
    # Start monitoring stack
    if not setup.run_docker_compose():
        logger.error("❌ Failed to start monitoring stack")
        sys.exit(1)
    
    # Wait for services to be ready
    if not setup.wait_for_services():
        logger.error("❌ Services failed to become ready")
        sys.exit(1)
    
    logger.info("🎉 Monitoring stack setup completed successfully!")
    logger.info("📊 Grafana: http://localhost:3000")
    logger.info("📈 Prometheus: http://localhost:9090")
    
    # Deploy dashboards if Grafana API key is available
    grafana_api_key = os.environ.get('GRAFANA_API_KEY')
    if grafana_api_key:
        logger.info("🎯 Deploying Grafana dashboards...")
        
        deploy_script = project_root / "scripts" / "deploy-grafana-dashboards.py"
        dashboards_dir = project_root / "monitoring" / "grafana" / "dashboards"
        
        result = subprocess.run([
            sys.executable, str(deploy_script),
            '--grafana-url', 'http://localhost:3000',
            '--api-key', grafana_api_key,
            '--dashboards-dir', str(dashboards_dir)
        ], cwd=project_root)
        
        if result.returncode == 0:
            logger.info("✅ Dashboards deployed successfully!")
        else:
            logger.warning("⚠️ Dashboard deployment failed. You can deploy them manually later.")
    else:
        logger.info("💡 Set GRAFANA_API_KEY environment variable to auto-deploy dashboards")

if __name__ == '__main__':
    main()