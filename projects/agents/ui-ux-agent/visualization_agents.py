"""
Data Visualization Sub-Agents
==============================
Agents responsible for charts, metrics, and observatory dashboards
"""

import asyncio
import json
import uuid
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
from datetime import datetime, timedelta
import random
import math

logger = logging.getLogger(__name__)


class ChartType(Enum):
    """Types of charts available"""
    LINE = "line"
    BAR = "bar"
    PIE = "pie"
    SCATTER = "scatter"
    AREA = "area"
    RADAR = "radar"
    HEATMAP = "heatmap"
    TREEMAP = "treemap"
    SANKEY = "sankey"
    GAUGE = "gauge"
    CANDLESTICK = "candlestick"


class MetricType(Enum):
    """Types of metrics that can be displayed"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    TREND = "trend"
    SPARKLINE = "sparkline"


class UpdateFrequency(Enum):
    """Update frequency for real-time data"""
    REALTIME = "realtime"  # WebSocket push
    HIGH = "high"  # 1 second
    MEDIUM = "medium"  # 5 seconds
    LOW = "low"  # 30 seconds
    STATIC = "static"  # No updates


@dataclass
class ChartConfig:
    """Configuration for a chart"""
    type: ChartType
    title: str
    data: Dict[str, Any]
    options: Dict[str, Any] = field(default_factory=dict)
    responsive: bool = True
    animated: bool = True
    interactive: bool = True
    update_frequency: UpdateFrequency = UpdateFrequency.STATIC


@dataclass
class MetricConfig:
    """Configuration for a metric display"""
    type: MetricType
    label: str
    value: Any
    unit: Optional[str] = None
    target: Optional[float] = None
    threshold: Optional[Dict[str, float]] = None
    trend: Optional[str] = None  # up, down, stable
    sparkline_data: Optional[List[float]] = None


class ChartAgent:
    """
    Sub-agent responsible for generating data visualizations
    Creates charts, graphs, and data representations
    """

    def __init__(self):
        self.agent_id = f"chart_{uuid.uuid4().hex[:8]}"
        self.chart_library = self._init_chart_library()
        self.color_schemes = self._init_color_schemes()
        self.active_charts = {}

    async def initialize(self):
        """Initialize the chart agent"""
        logger.info(f"Chart Agent initialized: {self.agent_id}")
        return True

    async def generate_visualizations(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate visualizations based on data
        Returns chart configurations and rendering instructions
        """
        visualizations = {
            'charts': [],
            'metrics': [],
            'layout': None,
            'update_config': {}
        }

        try:
            # Analyze data to determine best visualization types
            chart_types = self._analyze_data_for_charts(data)

            # Generate charts
            for chart_type in chart_types:
                chart = await self._generate_chart(chart_type, data)
                visualizations['charts'].append(chart)

            # Generate metrics
            metrics = await self._generate_metrics(data)
            visualizations['metrics'] = metrics

            # Determine layout for visualizations
            visualizations['layout'] = self._calculate_visualization_layout(
                len(visualizations['charts']),
                len(visualizations['metrics'])
            )

            # Setup update configuration for real-time data
            if data.get('realtime'):
                visualizations['update_config'] = self._setup_realtime_updates(data)

            logger.info(f"Generated {len(visualizations['charts'])} charts and {len(visualizations['metrics'])} metrics")

        except Exception as e:
            logger.error(f"Visualization generation error: {e}")
            visualizations['error'] = str(e)

        return visualizations

    async def _generate_chart(self, chart_type: ChartType, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a specific chart"""
        chart_id = f"chart_{uuid.uuid4().hex[:8]}"

        # Get chart template
        template = self.chart_library[chart_type]

        # Process data for chart
        chart_data = self._process_data_for_chart(chart_type, data)

        # Create chart configuration
        chart = {
            'id': chart_id,
            'type': chart_type.value,
            'config': {
                'type': chart_type.value,
                'data': chart_data,
                'options': self._get_chart_options(chart_type, data)
            },
            'container': {
                'tag': 'canvas',
                'attributes': {
                    'id': f"{chart_id}_canvas",
                    'width': 400,
                    'height': 300
                }
            },
            'library': 'chart.js'  # Could be d3, plotly, etc.
        }

        # Store active chart for updates
        self.active_charts[chart_id] = chart

        return chart

    async def _generate_metrics(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate metric displays from data"""
        metrics = []

        # Extract key metrics from data
        if 'metrics' in data:
            for metric_name, metric_value in data['metrics'].items():
                metric = self._create_metric_display(metric_name, metric_value)
                metrics.append(metric)

        # Auto-generate common metrics
        if 'timeseries' in data:
            # Calculate aggregates
            values = data['timeseries'].get('values', [])
            if values:
                metrics.append(self._create_metric_display('Average', sum(values) / len(values)))
                metrics.append(self._create_metric_display('Max', max(values)))
                metrics.append(self._create_metric_display('Min', min(values)))

        return metrics

    def _create_metric_display(self, label: str, value: Any) -> Dict[str, Any]:
        """Create a metric display configuration"""
        # Determine metric type based on value
        if isinstance(value, (int, float)):
            metric_type = MetricType.COUNTER
        elif isinstance(value, list):
            metric_type = MetricType.SPARKLINE
        else:
            metric_type = MetricType.GAUGE

        # Generate trend if historical data available
        trend = self._calculate_trend(value) if isinstance(value, list) else None

        return {
            'id': f"metric_{uuid.uuid4().hex[:8]}",
            'type': metric_type.value,
            'label': label,
            'value': value if not isinstance(value, list) else value[-1],
            'sparkline': value if isinstance(value, list) else None,
            'trend': trend,
            'animation': 'count-up' if metric_type == MetricType.COUNTER else None,
            'format': self._determine_format(value)
        }

    def _analyze_data_for_charts(self, data: Dict[str, Any]) -> List[ChartType]:
        """Analyze data structure to determine appropriate chart types"""
        chart_types = []

        # Time series data → Line chart
        if 'timeseries' in data:
            chart_types.append(ChartType.LINE)
            if data.get('multiple_series'):
                chart_types.append(ChartType.AREA)

        # Categorical data → Bar chart
        if 'categories' in data:
            chart_types.append(ChartType.BAR)
            if len(data['categories']) <= 8:
                chart_types.append(ChartType.PIE)

        # Correlation data → Scatter plot
        if 'x' in data and 'y' in data:
            chart_types.append(ChartType.SCATTER)

        # Hierarchical data → Treemap
        if 'hierarchy' in data:
            chart_types.append(ChartType.TREEMAP)

        # Matrix data → Heatmap
        if 'matrix' in data:
            chart_types.append(ChartType.HEATMAP)

        # Default to bar chart if no specific type detected
        if not chart_types:
            chart_types.append(ChartType.BAR)

        return chart_types

    def _process_data_for_chart(self, chart_type: ChartType, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process raw data into chart-compatible format"""
        if chart_type == ChartType.LINE:
            return self._process_line_chart_data(data)
        elif chart_type == ChartType.BAR:
            return self._process_bar_chart_data(data)
        elif chart_type == ChartType.PIE:
            return self._process_pie_chart_data(data)
        elif chart_type == ChartType.SCATTER:
            return self._process_scatter_chart_data(data)
        else:
            # Generic processing
            return {
                'labels': data.get('labels', []),
                'datasets': [{
                    'data': data.get('values', []),
                    'label': data.get('label', 'Dataset')
                }]
            }

    def _process_line_chart_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process data for line chart"""
        timeseries = data.get('timeseries', {})
        return {
            'labels': timeseries.get('timestamps', []),
            'datasets': [{
                'label': timeseries.get('label', 'Value'),
                'data': timeseries.get('values', []),
                'borderColor': self.color_schemes['default'][0],
                'backgroundColor': self.color_schemes['default'][0] + '20',
                'tension': 0.4
            }]
        }

    def _process_bar_chart_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process data for bar chart"""
        categories = data.get('categories', {})
        return {
            'labels': list(categories.keys()) if isinstance(categories, dict) else categories,
            'datasets': [{
                'label': data.get('label', 'Values'),
                'data': list(categories.values()) if isinstance(categories, dict) else data.get('values', []),
                'backgroundColor': self.color_schemes['default']
            }]
        }

    def _process_pie_chart_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process data for pie chart"""
        categories = data.get('categories', {})
        return {
            'labels': list(categories.keys()) if isinstance(categories, dict) else [],
            'datasets': [{
                'data': list(categories.values()) if isinstance(categories, dict) else [],
                'backgroundColor': self.color_schemes['default']
            }]
        }

    def _process_scatter_chart_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process data for scatter chart"""
        x_values = data.get('x', [])
        y_values = data.get('y', [])

        points = [{'x': x, 'y': y} for x, y in zip(x_values, y_values)]

        return {
            'datasets': [{
                'label': data.get('label', 'Data Points'),
                'data': points,
                'backgroundColor': self.color_schemes['default'][0]
            }]
        }

    def _get_chart_options(self, chart_type: ChartType, data: Dict[str, Any]) -> Dict[str, Any]:
        """Get chart-specific options"""
        base_options = {
            'responsive': True,
            'maintainAspectRatio': False,
            'plugins': {
                'legend': {
                    'display': True,
                    'position': 'top'
                },
                'tooltip': {
                    'enabled': True
                }
            }
        }

        # Add chart-specific options
        if chart_type == ChartType.LINE:
            base_options['scales'] = {
                'y': {'beginAtZero': True}
            }
        elif chart_type == ChartType.PIE:
            base_options['plugins']['legend']['position'] = 'right'
        elif chart_type == ChartType.SCATTER:
            base_options['scales'] = {
                'x': {'type': 'linear', 'position': 'bottom'},
                'y': {'type': 'linear', 'position': 'left'}
            }

        return base_options

    def _calculate_visualization_layout(self, num_charts: int, num_metrics: int) -> Dict[str, Any]:
        """Calculate optimal layout for visualizations"""
        total_items = num_charts + num_metrics

        if total_items <= 4:
            return {
                'type': 'grid',
                'columns': 2,
                'rows': 2
            }
        elif total_items <= 6:
            return {
                'type': 'grid',
                'columns': 3,
                'rows': 2
            }
        else:
            return {
                'type': 'grid',
                'columns': 4,
                'rows': math.ceil(total_items / 4)
            }

    def _setup_realtime_updates(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Setup configuration for real-time updates"""
        return {
            'enabled': True,
            'frequency': data.get('update_frequency', 'medium'),
            'websocket': data.get('websocket_url', '/ws/charts'),
            'endpoints': data.get('data_endpoints', []),
            'buffer_size': 100,
            'animation': True
        }

    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend from values"""
        if len(values) < 2:
            return 'stable'

        # Simple trend calculation
        recent_avg = sum(values[-3:]) / len(values[-3:])
        older_avg = sum(values[-6:-3]) / len(values[-6:-3]) if len(values) > 3 else values[0]

        if recent_avg > older_avg * 1.05:
            return 'up'
        elif recent_avg < older_avg * 0.95:
            return 'down'
        else:
            return 'stable'

    def _determine_format(self, value: Any) -> str:
        """Determine display format for value"""
        if isinstance(value, float):
            return '.2f'  # Two decimal places
        elif isinstance(value, int) and value > 1000000:
            return 'compact'  # 1M, 2.5K, etc.
        else:
            return 'default'

    def _init_chart_library(self) -> Dict[ChartType, Dict[str, Any]]:
        """Initialize chart template library"""
        return {
            ChartType.LINE: {
                'renderer': 'canvas',
                'interaction': 'hover',
                'animation': 'progressive'
            },
            ChartType.BAR: {
                'renderer': 'canvas',
                'interaction': 'click',
                'animation': 'slide'
            },
            ChartType.PIE: {
                'renderer': 'canvas',
                'interaction': 'click',
                'animation': 'rotation'
            },
            ChartType.SCATTER: {
                'renderer': 'canvas',
                'interaction': 'zoom',
                'animation': 'fade'
            }
        }

    def _init_color_schemes(self) -> Dict[str, List[str]]:
        """Initialize color schemes for charts"""
        return {
            'default': [
                '#4f46e5',  # Indigo
                '#06b6d4',  # Cyan
                '#10b981',  # Emerald
                '#f59e0b',  # Amber
                '#ef4444',  # Red
                '#8b5cf6',  # Violet
                '#ec4899',  # Pink
                '#14b8a6'   # Teal
            ],
            'monochrome': [
                '#1a1a1a',
                '#404040',
                '#666666',
                '#8c8c8c',
                '#b3b3b3',
                '#d9d9d9'
            ],
            'gradient': [
                '#4f46e5',
                '#5b57e6',
                '#6769e7',
                '#737ae8',
                '#7f8ce9',
                '#8b9dea'
            ]
        }


class ObservatoryAgent:
    """
    Sub-agent responsible for system monitoring and observatory dashboards
    Displays agent status, system metrics, and performance data
    """

    def __init__(self):
        self.agent_id = f"observatory_{uuid.uuid4().hex[:8]}"
        self.monitored_agents = {}
        self.system_metrics = {}
        self.alert_thresholds = self._init_alert_thresholds()

    async def initialize(self):
        """Initialize the observatory agent"""
        # Start monitoring loop
        asyncio.create_task(self._monitor_system())
        logger.info(f"Observatory Agent initialized: {self.agent_id}")
        return True

    async def create_monitoring_dashboard(self, agents: List[str],
                                         metrics: List[str]) -> Dict[str, Any]:
        """
        Create a monitoring dashboard for system observability
        Returns dashboard configuration with real-time updates
        """
        dashboard = {
            'id': f"observatory_{uuid.uuid4().hex[:8]}",
            'title': 'System Observatory',
            'layout': {
                'type': 'grid',
                'columns': 3,
                'rows': 'auto'
            },
            'sections': [],
            'refresh_rate': 1000,  # milliseconds
            'alerts': []
        }

        try:
            # Create agent status section
            agent_section = await self._create_agent_status_section(agents)
            dashboard['sections'].append(agent_section)

            # Create system metrics section
            metrics_section = await self._create_metrics_section(metrics)
            dashboard['sections'].append(metrics_section)

            # Create performance graphs section
            performance_section = await self._create_performance_section()
            dashboard['sections'].append(performance_section)

            # Create alerts section
            alerts_section = await self._create_alerts_section()
            dashboard['sections'].append(alerts_section)

            # Setup WebSocket for real-time updates
            dashboard['websocket'] = {
                'url': '/ws/observatory',
                'channels': ['agents', 'metrics', 'alerts']
            }

            logger.info(f"Created monitoring dashboard with {len(dashboard['sections'])} sections")

        except Exception as e:
            logger.error(f"Dashboard creation error: {e}")
            dashboard['error'] = str(e)

        return dashboard

    async def _create_agent_status_section(self, agents: List[str]) -> Dict[str, Any]:
        """Create agent status monitoring section"""
        section = {
            'id': 'agent_status',
            'title': 'Agent Status',
            'type': 'grid',
            'components': []
        }

        for agent_id in agents:
            status = await self._get_agent_status(agent_id)
            component = {
                'type': 'status_card',
                'agent_id': agent_id,
                'status': status['state'],
                'metrics': {
                    'requests': status.get('requests_processed', 0),
                    'errors': status.get('errors', 0),
                    'uptime': status.get('uptime', '0h')
                },
                'health': self._calculate_health_score(status),
                'visualization': {
                    'type': 'gauge',
                    'value': status.get('cpu_usage', 0),
                    'max': 100,
                    'thresholds': {
                        'good': 60,
                        'warning': 80,
                        'critical': 95
                    }
                }
            }
            section['components'].append(component)

        return section

    async def _create_metrics_section(self, metrics: List[str]) -> Dict[str, Any]:
        """Create system metrics section"""
        section = {
            'id': 'system_metrics',
            'title': 'System Metrics',
            'type': 'metrics_grid',
            'components': []
        }

        for metric_name in metrics:
            metric_data = await self._collect_metric(metric_name)
            component = {
                'type': 'metric_display',
                'name': metric_name,
                'value': metric_data['value'],
                'unit': metric_data.get('unit', ''),
                'trend': metric_data.get('trend', 'stable'),
                'sparkline': metric_data.get('history', []),
                'threshold': self.alert_thresholds.get(metric_name)
            }
            section['components'].append(component)

        return section

    async def _create_performance_section(self) -> Dict[str, Any]:
        """Create performance monitoring section"""
        # Generate sample performance data
        timestamps = [datetime.now() - timedelta(minutes=i) for i in range(60, 0, -1)]

        return {
            'id': 'performance',
            'title': 'Performance Metrics',
            'type': 'charts',
            'components': [
                {
                    'type': 'line_chart',
                    'title': 'Request Throughput',
                    'data': {
                        'timestamps': [t.isoformat() for t in timestamps],
                        'values': [random.randint(100, 500) for _ in timestamps]
                    },
                    'unit': 'req/s'
                },
                {
                    'type': 'line_chart',
                    'title': 'Response Time',
                    'data': {
                        'timestamps': [t.isoformat() for t in timestamps],
                        'values': [random.uniform(10, 100) for _ in timestamps]
                    },
                    'unit': 'ms'
                },
                {
                    'type': 'area_chart',
                    'title': 'Memory Usage',
                    'data': {
                        'timestamps': [t.isoformat() for t in timestamps],
                        'values': [random.uniform(60, 90) for _ in timestamps]
                    },
                    'unit': '%'
                }
            ]
        }

    async def _create_alerts_section(self) -> Dict[str, Any]:
        """Create alerts section"""
        # Check for any active alerts
        alerts = await self._check_alerts()

        return {
            'id': 'alerts',
            'title': 'Active Alerts',
            'type': 'alert_list',
            'components': [
                {
                    'type': 'alert',
                    'severity': alert['severity'],
                    'title': alert['title'],
                    'message': alert['message'],
                    'timestamp': alert['timestamp'],
                    'acknowledged': alert.get('acknowledged', False)
                }
                for alert in alerts
            ]
        }

    async def _get_agent_status(self, agent_id: str) -> Dict[str, Any]:
        """Get status of a specific agent"""
        # Simulate agent status (would connect to actual agent in production)
        return {
            'agent_id': agent_id,
            'state': random.choice(['active', 'idle', 'busy']),
            'requests_processed': random.randint(1000, 10000),
            'errors': random.randint(0, 10),
            'uptime': f"{random.randint(1, 24)}h",
            'cpu_usage': random.uniform(10, 90),
            'memory_usage': random.uniform(100, 500)
        }

    async def _collect_metric(self, metric_name: str) -> Dict[str, Any]:
        """Collect a specific metric"""
        # Simulate metric collection
        base_value = {
            'cpu': 45,
            'memory': 62,
            'disk': 35,
            'network': 120,
            'requests': 350
        }.get(metric_name.lower(), 50)

        return {
            'value': base_value + random.uniform(-10, 10),
            'unit': {
                'cpu': '%',
                'memory': '%',
                'disk': '%',
                'network': 'Mbps',
                'requests': 'req/s'
            }.get(metric_name.lower(), ''),
            'trend': random.choice(['up', 'down', 'stable']),
            'history': [base_value + random.uniform(-20, 20) for _ in range(20)]
        }

    async def _check_alerts(self) -> List[Dict[str, Any]]:
        """Check for system alerts"""
        alerts = []

        # Check thresholds
        for metric_name, threshold in self.alert_thresholds.items():
            metric = await self._collect_metric(metric_name)
            if metric['value'] > threshold.get('critical', float('inf')):
                alerts.append({
                    'severity': 'critical',
                    'title': f'{metric_name} Critical',
                    'message': f'{metric_name} is at {metric["value"]:.1f}{metric.get("unit", "")}',
                    'timestamp': datetime.now().isoformat()
                })
            elif metric['value'] > threshold.get('warning', float('inf')):
                alerts.append({
                    'severity': 'warning',
                    'title': f'{metric_name} Warning',
                    'message': f'{metric_name} is at {metric["value"]:.1f}{metric.get("unit", "")}',
                    'timestamp': datetime.now().isoformat()
                })

        return alerts

    def _calculate_health_score(self, status: Dict[str, Any]) -> float:
        """Calculate health score for an agent"""
        score = 100.0

        # Deduct for errors
        error_rate = status.get('errors', 0) / max(status.get('requests_processed', 1), 1)
        score -= error_rate * 50

        # Deduct for high resource usage
        cpu_usage = status.get('cpu_usage', 0)
        if cpu_usage > 80:
            score -= (cpu_usage - 80) * 0.5

        return max(0, min(100, score))

    async def _monitor_system(self):
        """Background task to monitor system metrics"""
        while True:
            try:
                # Collect system metrics
                self.system_metrics = {
                    'timestamp': datetime.now().isoformat(),
                    'cpu': await self._get_cpu_usage(),
                    'memory': await self._get_memory_usage(),
                    'disk': await self._get_disk_usage(),
                    'network': await self._get_network_usage()
                }

                # Check for anomalies
                anomalies = self._detect_anomalies(self.system_metrics)
                if anomalies:
                    logger.warning(f"Anomalies detected: {anomalies}")

            except Exception as e:
                logger.error(f"Monitoring error: {e}")

            await asyncio.sleep(5)  # Monitor every 5 seconds

    async def _get_cpu_usage(self) -> float:
        """Get current CPU usage"""
        # Simulate CPU usage (would use psutil in production)
        return random.uniform(20, 80)

    async def _get_memory_usage(self) -> float:
        """Get current memory usage"""
        return random.uniform(40, 70)

    async def _get_disk_usage(self) -> float:
        """Get current disk usage"""
        return random.uniform(30, 60)

    async def _get_network_usage(self) -> float:
        """Get current network usage"""
        return random.uniform(10, 200)

    def _detect_anomalies(self, metrics: Dict[str, Any]) -> List[str]:
        """Detect anomalies in system metrics"""
        anomalies = []

        if metrics.get('cpu', 0) > 90:
            anomalies.append('High CPU usage')
        if metrics.get('memory', 0) > 85:
            anomalies.append('High memory usage')
        if metrics.get('disk', 0) > 90:
            anomalies.append('Low disk space')

        return anomalies

    def _init_alert_thresholds(self) -> Dict[str, Dict[str, float]]:
        """Initialize alert thresholds"""
        return {
            'cpu': {'warning': 70, 'critical': 90},
            'memory': {'warning': 75, 'critical': 90},
            'disk': {'warning': 80, 'critical': 95},
            'network': {'warning': 150, 'critical': 190},
            'requests': {'warning': 500, 'critical': 700}
        }


# Example usage
async def test_visualization_agents():
    """Test the visualization agents"""

    # Initialize agents
    chart_agent = ChartAgent()
    await chart_agent.initialize()

    observatory_agent = ObservatoryAgent()
    await observatory_agent.initialize()

    # Test data for charts
    chart_data = {
        'timeseries': {
            'timestamps': ['10:00', '10:05', '10:10', '10:15', '10:20'],
            'values': [100, 150, 120, 180, 160],
            'label': 'Requests per minute'
        },
        'categories': {
            'Success': 850,
            'Warning': 120,
            'Error': 30
        },
        'metrics': {
            'Total Requests': 1000,
            'Avg Response Time': 45.2,
            'Error Rate': 3.0
        },
        'realtime': True,
        'update_frequency': 'high'
    }

    # Generate visualizations
    visualizations = await chart_agent.generate_visualizations(chart_data)
    print(f"Generated {len(visualizations['charts'])} charts")
    print(f"Generated {len(visualizations['metrics'])} metrics")

    # Create monitoring dashboard
    dashboard = await observatory_agent.create_monitoring_dashboard(
        agents=['ui_agent_1', 'chart_agent_1', 'input_agent_1'],
        metrics=['CPU', 'Memory', 'Requests']
    )
    print(f"Created dashboard with {len(dashboard['sections'])} sections")

    return {
        'visualizations': visualizations,
        'dashboard': dashboard
    }


if __name__ == "__main__":
    asyncio.run(test_visualization_agents())