#!/usr/bin/env python3
"""
Enhanced Observatory Adapter for Infrastructure Performance Monitoring
Integrates with Performance Monitor MCP and Director Agent for comprehensive monitoring
"""

import asyncio
import websockets
import json
import time
import psutil
import docker
import subprocess
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import uuid
import threading
import queue
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class InfrastructureMonitor:
    """Infrastructure monitoring capabilities for Observatory"""

    def __init__(self):
        self.docker_client = None
        self.monitoring_active = False
        self.metrics_queue = queue.Queue()
        self.last_container_stats = {}

        try:
            self.docker_client = docker.from_env()
            logger.info("Docker client initialized successfully")
        except Exception as e:
            logger.warning(f"Docker client initialization failed: {e}")

    async def collect_system_metrics(self) -> Dict[str, Any]:
        """Collect comprehensive system metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()

            # Memory metrics
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()

            # Disk metrics
            disk_usage = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()

            # Network metrics
            network_io = psutil.net_io_counters()

            # Process metrics
            process_count = len(psutil.pids())

            system_metrics = {
                'timestamp': datetime.now().isoformat(),
                'cpu': {
                    'percent': cpu_percent,
                    'count': cpu_count,
                    'frequency': cpu_freq.current if cpu_freq else None
                },
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'used': memory.used,
                    'free': memory.free
                },
                'swap': {
                    'total': swap.total,
                    'used': swap.used,
                    'free': swap.free,
                    'percent': swap.percent
                },
                'disk': {
                    'total': disk_usage.total,
                    'used': disk_usage.used,
                    'free': disk_usage.free,
                    'percent': (disk_usage.used / disk_usage.total) * 100,
                    'read_bytes': disk_io.read_bytes if disk_io else 0,
                    'write_bytes': disk_io.write_bytes if disk_io else 0
                },
                'network': {
                    'bytes_sent': network_io.bytes_sent,
                    'bytes_recv': network_io.bytes_recv,
                    'packets_sent': network_io.packets_sent,
                    'packets_recv': network_io.packets_recv
                },
                'processes': {
                    'count': process_count
                }
            }

            return system_metrics

        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}

    async def collect_docker_metrics(self) -> Dict[str, Any]:
        """Collect Docker container metrics"""
        if not self.docker_client:
            return {'error': 'Docker client not available'}

        try:
            containers = self.docker_client.containers.list()
            container_metrics = []

            for container in containers:
                try:
                    stats = container.stats(stream=False)

                    # Calculate CPU percentage
                    cpu_percent = self._calculate_cpu_percent(stats)

                    # Memory metrics
                    memory_usage = stats['memory_stats'].get('usage', 0)
                    memory_limit = stats['memory_stats'].get('limit', 0)
                    memory_percent = (memory_usage / memory_limit * 100) if memory_limit > 0 else 0

                    # Network I/O
                    network_io = self._calculate_network_io(stats)

                    # Block I/O
                    block_io = self._calculate_block_io(stats)

                    container_metric = {
                        'id': container.id[:12],
                        'name': container.name,
                        'image': container.image.tags[0] if container.image.tags else 'unknown',
                        'status': container.status,
                        'cpu_percent': cpu_percent,
                        'memory': {
                            'usage': memory_usage,
                            'limit': memory_limit,
                            'percent': memory_percent
                        },
                        'network': network_io,
                        'block_io': block_io,
                        'pids': stats.get('pids_stats', {}).get('current', 0)
                    }

                    container_metrics.append(container_metric)

                except Exception as e:
                    logger.warning(f"Error collecting stats for container {container.name}: {e}")
                    continue

            docker_metrics = {
                'timestamp': datetime.now().isoformat(),
                'containers': container_metrics,
                'total_containers': len(containers),
                'running_containers': len([c for c in containers if c.status == 'running'])
            }

            return docker_metrics

        except Exception as e:
            logger.error(f"Error collecting Docker metrics: {e}")
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}

    def _calculate_cpu_percent(self, stats: Dict[str, Any]) -> float:
        """Calculate CPU percentage from Docker stats"""
        try:
            cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                       stats['precpu_stats']['cpu_usage']['total_usage']
            system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                          stats['precpu_stats']['system_cpu_usage']

            if system_delta > 0 and cpu_delta > 0:
                number_cpus = stats['cpu_stats'].get('online_cpus', 1)
                return (cpu_delta / system_delta) * number_cpus * 100.0

            return 0.0
        except (KeyError, ZeroDivisionError):
            return 0.0

    def _calculate_network_io(self, stats: Dict[str, Any]) -> Dict[str, int]:
        """Calculate network I/O from Docker stats"""
        try:
            networks = stats.get('networks', {})
            rx_bytes = sum(net.get('rx_bytes', 0) for net in networks.values())
            tx_bytes = sum(net.get('tx_bytes', 0) for net in networks.values())
            return {'rx_bytes': rx_bytes, 'tx_bytes': tx_bytes}
        except:
            return {'rx_bytes': 0, 'tx_bytes': 0}

    def _calculate_block_io(self, stats: Dict[str, Any]) -> Dict[str, int]:
        """Calculate block I/O from Docker stats"""
        try:
            blkio_stats = stats.get('blkio_stats', {})
            io_service_bytes = blkio_stats.get('io_service_bytes_recursive', [])

            read_bytes = sum(item['value'] for item in io_service_bytes
                           if item.get('op') == 'Read')
            write_bytes = sum(item['value'] for item in io_service_bytes
                            if item.get('op') == 'Write')

            return {'read_bytes': read_bytes, 'write_bytes': write_bytes}
        except:
            return {'read_bytes': 0, 'write_bytes': 0}

    async def check_service_health(self, services: List[str]) -> Dict[str, Any]:
        """Check health of specific services"""
        health_results = {}

        for service_name in services:
            try:
                if self.docker_client:
                    containers = self.docker_client.containers.list(
                        filters={'name': service_name}
                    )

                    if containers:
                        container = containers[0]
                        health_results[service_name] = {
                            'status': container.status,
                            'health': getattr(container.attrs.get('State', {}), 'Health', {}).get('Status', 'unknown'),
                            'running': container.status == 'running',
                            'restart_count': container.attrs.get('RestartCount', 0),
                            'last_check': datetime.now().isoformat()
                        }
                    else:
                        health_results[service_name] = {
                            'status': 'not_found',
                            'running': False,
                            'last_check': datetime.now().isoformat()
                        }

            except Exception as e:
                health_results[service_name] = {
                    'status': 'error',
                    'error': str(e),
                    'running': False,
                    'last_check': datetime.now().isoformat()
                }

        return {
            'timestamp': datetime.now().isoformat(),
            'service_health': health_results
        }

class EnhancedObservatoryAdapter:
    """Enhanced Observatory Adapter with infrastructure monitoring"""

    def __init__(self, server_url="ws://localhost:8090/ws", agent_name="InfrastructureMonitor"):
        self.server_url = server_url
        self.agent_name = agent_name
        self.websocket = None
        self.is_connected = False
        self.monitoring_interval = 30.0  # seconds
        self.infrastructure_monitor = InfrastructureMonitor()

        # Performance tracking
        self.metrics_history = []
        self.alert_thresholds = {
            'cpu_percent': 80.0,
            'memory_percent': 85.0,
            'disk_percent': 90.0,
            'container_cpu_percent': 85.0,
            'container_memory_percent': 90.0
        }

    async def connect(self):
        """Connect to observatory server"""
        try:
            self.websocket = await websockets.connect(self.server_url)
            self.is_connected = True
            await self.register()
            logger.info(f"{self.agent_name} connected to observatory")

            # Start monitoring tasks
            asyncio.create_task(self.infrastructure_monitoring_loop())
            asyncio.create_task(self.health_monitoring_loop())

            return True

        except Exception as e:
            logger.error(f"Connection failed: {e}")
            self.is_connected = False
            return False

    async def register(self):
        """Register with observatory server"""
        registration_data = {
            'type': 'agent_register',
            'agent_id': self.agent_name,
            'agent_type': 'infrastructure_monitor',
            'capabilities': [
                'system_monitoring',
                'docker_monitoring',
                'performance_analysis',
                'health_checks',
                'alerting'
            ],
            'metadata': {
                'version': '1.0.0',
                'monitoring_interval': self.monitoring_interval
            },
            'timestamp': datetime.now().isoformat()
        }

        await self.send_message(registration_data)

    async def send_message(self, data: Dict[str, Any]):
        """Send message to observatory server"""
        if self.websocket and self.is_connected:
            try:
                await self.websocket.send(json.dumps(data))
            except Exception as e:
                logger.error(f"Error sending message: {e}")
                self.is_connected = False

    async def infrastructure_monitoring_loop(self):
        """Main infrastructure monitoring loop"""
        while self.is_connected:
            try:
                # Collect system metrics
                system_metrics = await self.infrastructure_monitor.collect_system_metrics()

                # Collect Docker metrics
                docker_metrics = await self.infrastructure_monitor.collect_docker_metrics()

                # Combine metrics
                infrastructure_data = {
                    'type': 'infrastructure_metrics',
                    'agent_id': self.agent_name,
                    'system': system_metrics,
                    'docker': docker_metrics,
                    'timestamp': datetime.now().isoformat()
                }

                # Send to observatory
                await self.send_message(infrastructure_data)

                # Store in history
                self.metrics_history.append(infrastructure_data)
                if len(self.metrics_history) > 100:  # Keep last 100 metrics
                    self.metrics_history = self.metrics_history[-100:]

                # Check for alerts
                await self.check_and_send_alerts(infrastructure_data)

                await asyncio.sleep(self.monitoring_interval)

            except Exception as e:
                logger.error(f"Infrastructure monitoring error: {e}")
                await asyncio.sleep(self.monitoring_interval)

    async def health_monitoring_loop(self):
        """Health monitoring loop for critical services"""
        critical_services = [
            'catalytic-saas-api',
            'catalytic-postgres',
            'catalytic-redis',
            'catalytic-webhooks'
        ]

        while self.is_connected:
            try:
                health_data = await self.infrastructure_monitor.check_service_health(critical_services)

                health_message = {
                    'type': 'service_health',
                    'agent_id': self.agent_name,
                    'health_data': health_data,
                    'timestamp': datetime.now().isoformat()
                }

                await self.send_message(health_message)

                await asyncio.sleep(60)  # Check every minute

            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
                await asyncio.sleep(60)

    async def check_and_send_alerts(self, metrics_data: Dict[str, Any]):
        """Check metrics against thresholds and send alerts"""
        alerts = []

        # Check system metrics
        system_metrics = metrics_data.get('system', {})

        if 'cpu' in system_metrics:
            cpu_percent = system_metrics['cpu'].get('percent', 0)
            if cpu_percent > self.alert_thresholds['cpu_percent']:
                alerts.append({
                    'type': 'HIGH_CPU',
                    'severity': 'WARNING',
                    'message': f'System CPU usage at {cpu_percent:.1f}%',
                    'threshold': self.alert_thresholds['cpu_percent'],
                    'current_value': cpu_percent
                })

        if 'memory' in system_metrics:
            memory_percent = system_metrics['memory'].get('percent', 0)
            if memory_percent > self.alert_thresholds['memory_percent']:
                alerts.append({
                    'type': 'HIGH_MEMORY',
                    'severity': 'WARNING',
                    'message': f'System memory usage at {memory_percent:.1f}%',
                    'threshold': self.alert_thresholds['memory_percent'],
                    'current_value': memory_percent
                })

        if 'disk' in system_metrics:
            disk_percent = system_metrics['disk'].get('percent', 0)
            if disk_percent > self.alert_thresholds['disk_percent']:
                alerts.append({
                    'type': 'HIGH_DISK',
                    'severity': 'CRITICAL',
                    'message': f'Disk usage at {disk_percent:.1f}%',
                    'threshold': self.alert_thresholds['disk_percent'],
                    'current_value': disk_percent
                })

        # Check container metrics
        docker_metrics = metrics_data.get('docker', {})
        containers = docker_metrics.get('containers', [])

        for container in containers:
            cpu_percent = container.get('cpu_percent', 0)
            memory_percent = container.get('memory', {}).get('percent', 0)

            if cpu_percent > self.alert_thresholds['container_cpu_percent']:
                alerts.append({
                    'type': 'CONTAINER_HIGH_CPU',
                    'severity': 'WARNING',
                    'message': f'Container {container["name"]} CPU at {cpu_percent:.1f}%',
                    'container': container['name'],
                    'threshold': self.alert_thresholds['container_cpu_percent'],
                    'current_value': cpu_percent
                })

            if memory_percent > self.alert_thresholds['container_memory_percent']:
                alerts.append({
                    'type': 'CONTAINER_HIGH_MEMORY',
                    'severity': 'WARNING',
                    'message': f'Container {container["name"]} memory at {memory_percent:.1f}%',
                    'container': container['name'],
                    'threshold': self.alert_thresholds['container_memory_percent'],
                    'current_value': memory_percent
                })

        # Send alerts if any
        if alerts:
            alert_message = {
                'type': 'infrastructure_alerts',
                'agent_id': self.agent_name,
                'alerts': alerts,
                'alert_count': len(alerts),
                'timestamp': datetime.now().isoformat()
            }

            await self.send_message(alert_message)
            logger.warning(f"Sent {len(alerts)} infrastructure alerts")

    async def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary from recent metrics"""
        if not self.metrics_history:
            return {'error': 'No metrics available'}

        recent_metrics = self.metrics_history[-10:]  # Last 10 metrics

        # Calculate averages
        avg_cpu = sum(m.get('system', {}).get('cpu', {}).get('percent', 0)
                     for m in recent_metrics) / len(recent_metrics)

        avg_memory = sum(m.get('system', {}).get('memory', {}).get('percent', 0)
                        for m in recent_metrics) / len(recent_metrics)

        container_count = recent_metrics[-1].get('docker', {}).get('total_containers', 0) if recent_metrics else 0
        running_containers = recent_metrics[-1].get('docker', {}).get('running_containers', 0) if recent_metrics else 0

        return {
            'timestamp': datetime.now().isoformat(),
            'monitoring_period': f'Last {len(recent_metrics)} samples',
            'system_averages': {
                'cpu_percent': avg_cpu,
                'memory_percent': avg_memory
            },
            'container_summary': {
                'total_containers': container_count,
                'running_containers': running_containers
            },
            'health_status': 'HEALTHY' if avg_cpu < 70 and avg_memory < 80 else 'WARNING'
        }

    async def disconnect(self):
        """Disconnect from observatory server"""
        self.is_connected = False
        if self.websocket:
            await self.websocket.close()

# Test function
async def test_enhanced_observatory():
    """Test the enhanced observatory adapter"""
    adapter = EnhancedObservatoryAdapter()

    # Try to connect
    connected = await adapter.connect()

    if connected:
        logger.info("✅ Enhanced Observatory Adapter connected")

        # Wait for some monitoring cycles
        await asyncio.sleep(10)

        # Get performance summary
        summary = await adapter.get_performance_summary()
        logger.info(f"📊 Performance Summary: {json.dumps(summary, indent=2)}")

        await adapter.disconnect()
        logger.info("✅ Enhanced Observatory Adapter disconnected")
    else:
        logger.error("❌ Failed to connect to Observatory")

if __name__ == "__main__":
    asyncio.run(test_enhanced_observatory())