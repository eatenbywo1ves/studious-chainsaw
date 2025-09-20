"""
Webhook Monitoring Dashboard and Metrics Exporter
Provides real-time monitoring and visualization for webhook system
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, field
import redis.asyncio as redis
from prometheus_client import (
    generate_latest, CONTENT_TYPE_LATEST,
    Counter, Histogram, Gauge, Summary
)
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response
import aiohttp
import psutil

app = FastAPI(title="Webhook Monitoring Dashboard", version="1.0.0")

# Metrics
webhook_delivery_counter = Counter(
    'webhook_deliveries_total',
    'Total number of webhook deliveries',
    ['event_type', 'endpoint', 'status']
)

webhook_delivery_duration = Histogram(
    'webhook_delivery_duration_seconds',
    'Webhook delivery duration in seconds',
    ['event_type', 'endpoint'],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
)

webhook_retry_counter = Counter(
    'webhook_retries_total',
    'Total number of webhook retries',
    ['event_type', 'endpoint', 'attempt']
)

webhook_queue_depth = Gauge(
    'webhook_queue_depth',
    'Current depth of webhook delivery queue',
    ['priority']
)

webhook_circuit_breaker_status = Gauge(
    'webhook_circuit_breaker_status',
    'Circuit breaker status (0=closed, 1=open, 2=half-open)',
    ['endpoint']
)

webhook_dead_letter_count = Counter(
    'webhook_dead_letter_total',
    'Total webhooks sent to dead letter queue',
    ['event_type', 'endpoint', 'reason']
)

active_webhook_deliveries = Gauge(
    'active_webhook_deliveries',
    'Number of webhooks currently being delivered',
    ['event_type']
)

@dataclass
class WebhookMetric:
    """Individual webhook metric"""
    timestamp: float
    event_type: str
    endpoint: str
    duration: float
    status: str
    retry_count: int = 0
    error_message: Optional[str] = None

@dataclass
class EndpointHealth:
    """Health status of a webhook endpoint"""
    url: str
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    avg_response_time: float = 0.0
    last_success: Optional[float] = None
    last_failure: Optional[float] = None
    circuit_breaker_state: str = "closed"
    recent_errors: List[str] = field(default_factory=list)

class WebhookMonitor:
    """Main monitoring class for webhooks"""

    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis_client: Optional[redis.Redis] = None
        self.metrics_buffer: deque = deque(maxlen=10000)
        self.endpoint_health: Dict[str, EndpointHealth] = defaultdict(EndpointHealth)
        self.event_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "total": 0,
            "success": 0,
            "failed": 0,
            "avg_duration": 0.0,
            "p95_duration": 0.0,
            "p99_duration": 0.0
        })

    async def start(self):
        """Start the monitoring system"""
        self.redis_client = await redis.from_url(self.redis_url)
        asyncio.create_task(self._collect_metrics())
        asyncio.create_task(self._update_health_status())

    async def stop(self):
        """Stop the monitoring system"""
        if self.redis_client:
            await self.redis_client.close()

    async def _collect_metrics(self):
        """Collect metrics from Redis"""
        while True:
            try:
                # Subscribe to webhook events
                pubsub = self.redis_client.pubsub()
                await pubsub.subscribe("webhook:events")

                async for message in pubsub.listen():
                    if message['type'] == 'message':
                        data = json.loads(message['data'])
                        await self._process_metric(data)

            except Exception as e:
                print(f"Error collecting metrics: {e}")
                await asyncio.sleep(5)

    async def _process_metric(self, data: Dict[str, Any]):
        """Process incoming webhook metric"""
        metric = WebhookMetric(
            timestamp=data.get('timestamp', time.time()),
            event_type=data['event_type'],
            endpoint=data['endpoint'],
            duration=data['duration'],
            status=data['status'],
            retry_count=data.get('retry_count', 0),
            error_message=data.get('error_message')
        )

        # Add to buffer
        self.metrics_buffer.append(metric)

        # Update endpoint health
        health = self.endpoint_health[metric.endpoint]
        health.url = metric.endpoint
        health.total_calls += 1

        if metric.status == 'success':
            health.successful_calls += 1
            health.last_success = metric.timestamp
            webhook_delivery_counter.labels(
                event_type=metric.event_type,
                endpoint=metric.endpoint,
                status='success'
            ).inc()
        else:
            health.failed_calls += 1
            health.last_failure = metric.timestamp
            if metric.error_message:
                health.recent_errors.append(metric.error_message)
                if len(health.recent_errors) > 10:
                    health.recent_errors.pop(0)
            webhook_delivery_counter.labels(
                event_type=metric.event_type,
                endpoint=metric.endpoint,
                status='failed'
            ).inc()

        # Update duration metrics
        webhook_delivery_duration.labels(
            event_type=metric.event_type,
            endpoint=metric.endpoint
        ).observe(metric.duration)

        # Update event statistics
        stats = self.event_stats[metric.event_type]
        stats['total'] += 1
        if metric.status == 'success':
            stats['success'] += 1
        else:
            stats['failed'] += 1

    async def _update_health_status(self):
        """Periodically update endpoint health status"""
        while True:
            try:
                for endpoint, health in self.endpoint_health.items():
                    if health.total_calls > 0:
                        health.avg_response_time = await self._calculate_avg_response_time(endpoint)
                        success_rate = health.successful_calls / health.total_calls

                        # Update circuit breaker gauge
                        if success_rate < 0.5 and health.total_calls > 10:
                            health.circuit_breaker_state = "open"
                            webhook_circuit_breaker_status.labels(endpoint=endpoint).set(1)
                        elif success_rate < 0.8:
                            health.circuit_breaker_state = "half-open"
                            webhook_circuit_breaker_status.labels(endpoint=endpoint).set(2)
                        else:
                            health.circuit_breaker_state = "closed"
                            webhook_circuit_breaker_status.labels(endpoint=endpoint).set(0)

            except Exception as e:
                print(f"Error updating health status: {e}")

            await asyncio.sleep(30)  # Update every 30 seconds

    async def _calculate_avg_response_time(self, endpoint: str) -> float:
        """Calculate average response time for an endpoint"""
        recent_metrics = [
            m for m in self.metrics_buffer
            if m.endpoint == endpoint and m.status == 'success'
        ][-100:]  # Last 100 successful calls

        if recent_metrics:
            return sum(m.duration for m in recent_metrics) / len(recent_metrics)
        return 0.0

    async def get_dashboard_data(self) -> Dict[str, Any]:
        """Get data for dashboard display"""
        now = time.time()
        hour_ago = now - 3600

        # Get metrics from last hour
        recent_metrics = [m for m in self.metrics_buffer if m.timestamp > hour_ago]

        # Calculate statistics
        total_deliveries = len(recent_metrics)
        successful_deliveries = sum(1 for m in recent_metrics if m.status == 'success')
        failed_deliveries = total_deliveries - successful_deliveries
        success_rate = (successful_deliveries / total_deliveries * 100) if total_deliveries > 0 else 0

        # Group by event type
        events_by_type = defaultdict(lambda: {"total": 0, "success": 0, "failed": 0})
        for metric in recent_metrics:
            events_by_type[metric.event_type]["total"] += 1
            if metric.status == "success":
                events_by_type[metric.event_type]["success"] += 1
            else:
                events_by_type[metric.event_type]["failed"] += 1

        # Get top slowest endpoints
        endpoint_times = defaultdict(list)
        for metric in recent_metrics:
            if metric.status == "success":
                endpoint_times[metric.endpoint].append(metric.duration)

        slowest_endpoints = []
        for endpoint, times in endpoint_times.items():
            if times:
                avg_time = sum(times) / len(times)
                slowest_endpoints.append({
                    "endpoint": endpoint,
                    "avg_time": avg_time,
                    "call_count": len(times)
                })
        slowest_endpoints.sort(key=lambda x: x["avg_time"], reverse=True)

        return {
            "summary": {
                "total_deliveries": total_deliveries,
                "successful_deliveries": successful_deliveries,
                "failed_deliveries": failed_deliveries,
                "success_rate": success_rate,
                "time_window": "1 hour"
            },
            "events_by_type": dict(events_by_type),
            "endpoint_health": {
                url: {
                    "total_calls": health.total_calls,
                    "success_rate": (health.successful_calls / health.total_calls * 100)
                    if health.total_calls > 0 else 0,
                    "avg_response_time": health.avg_response_time,
                    "circuit_breaker_state": health.circuit_breaker_state,
                    "recent_errors": health.recent_errors[-5:]  # Last 5 errors
                }
                for url, health in self.endpoint_health.items()
            },
            "slowest_endpoints": slowest_endpoints[:10],  # Top 10 slowest
            "recent_failures": [
                {
                    "timestamp": m.timestamp,
                    "event_type": m.event_type,
                    "endpoint": m.endpoint,
                    "error": m.error_message
                }
                for m in recent_metrics
                if m.status != "success" and m.error_message
            ][-20:]  # Last 20 failures
        }

    async def get_time_series_data(self, minutes: int = 60) -> Dict[str, Any]:
        """Get time series data for charting"""
        now = time.time()
        start_time = now - (minutes * 60)

        # Bucket metrics by minute
        buckets = defaultdict(lambda: {"success": 0, "failed": 0})

        for metric in self.metrics_buffer:
            if metric.timestamp > start_time:
                bucket = int(metric.timestamp / 60) * 60  # Round to minute
                if metric.status == "success":
                    buckets[bucket]["success"] += 1
                else:
                    buckets[bucket]["failed"] += 1

        # Convert to sorted list
        time_series = []
        for timestamp in sorted(buckets.keys()):
            time_series.append({
                "timestamp": timestamp,
                "success": buckets[timestamp]["success"],
                "failed": buckets[timestamp]["failed"]
            })

        return {"time_series": time_series, "interval": "1 minute"}

# Global monitor instance
monitor = WebhookMonitor()

# API Endpoints
@app.on_event("startup")
async def startup_event():
    """Initialize monitor on startup"""
    await monitor.start()

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    await monitor.stop()

@app.get("/metrics")
async def get_prometheus_metrics():
    """Prometheus metrics endpoint"""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/api/dashboard")
async def get_dashboard_data():
    """Get dashboard data"""
    return await monitor.get_dashboard_data()

@app.get("/api/time-series")
async def get_time_series(minutes: int = 60):
    """Get time series data"""
    return await monitor.get_time_series_data(minutes)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time updates"""
    await websocket.accept()

    try:
        while True:
            # Send dashboard data every 5 seconds
            data = await monitor.get_dashboard_data()
            await websocket.send_json(data)
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        pass

@app.get("/")
async def dashboard():
    """Serve HTML dashboard"""
    html = """
<!DOCTYPE html>
<html>
<head>
    <title>Webhook Monitoring Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        h1 {
            color: #333;
            margin-bottom: 30px;
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .metric-card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .metric-value {
            font-size: 32px;
            font-weight: bold;
            color: #2563eb;
            margin: 10px 0;
        }
        .metric-label {
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .chart-container {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .table-container {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th {
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #495057;
            border-bottom: 2px solid #dee2e6;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        .status-success {
            background: #d4edda;
            color: #155724;
        }
        .status-failed {
            background: #f8d7da;
            color: #721c24;
        }
        .status-warning {
            background: #fff3cd;
            color: #856404;
        }
        .circuit-open {
            background: #f8d7da;
            color: #721c24;
        }
        .circuit-closed {
            background: #d4edda;
            color: #155724;
        }
        .circuit-half-open {
            background: #fff3cd;
            color: #856404;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔔 Webhook Monitoring Dashboard</h1>

        <div class="metrics-grid" id="metrics-grid">
            <!-- Metrics will be inserted here -->
        </div>

        <div class="chart-container">
            <h2>Delivery Rate (Last Hour)</h2>
            <canvas id="deliveryChart"></canvas>
        </div>

        <div class="table-container">
            <h2>Endpoint Health</h2>
            <table id="endpointTable">
                <thead>
                    <tr>
                        <th>Endpoint</th>
                        <th>Total Calls</th>
                        <th>Success Rate</th>
                        <th>Avg Response Time</th>
                        <th>Circuit Breaker</th>
                        <th>Recent Errors</th>
                    </tr>
                </thead>
                <tbody id="endpointTableBody">
                    <!-- Data will be inserted here -->
                </tbody>
            </table>
        </div>

        <div class="table-container">
            <h2>Recent Failures</h2>
            <table id="failuresTable">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Event Type</th>
                        <th>Endpoint</th>
                        <th>Error</th>
                    </tr>
                </thead>
                <tbody id="failuresTableBody">
                    <!-- Data will be inserted here -->
                </tbody>
            </table>
        </div>
    </div>

    <script>
        // Initialize Chart.js
        const ctx = document.getElementById('deliveryChart').getContext('2d');
        const deliveryChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Successful',
                    data: [],
                    borderColor: 'rgb(75, 192, 192)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    tension: 0.1
                }, {
                    label: 'Failed',
                    data: [],
                    borderColor: 'rgb(255, 99, 132)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        // WebSocket connection for real-time updates
        const ws = new WebSocket(`ws://${window.location.host}/ws`);

        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            updateDashboard(data);
        };

        function updateDashboard(data) {
            // Update metrics cards
            const metricsHtml = `
                <div class="metric-card">
                    <div class="metric-label">Total Deliveries</div>
                    <div class="metric-value">${data.summary.total_deliveries}</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Successful</div>
                    <div class="metric-value" style="color: #10b981">
                        ${data.summary.successful_deliveries}
                    </div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Failed</div>
                    <div class="metric-value" style="color: #ef4444">
                        ${data.summary.failed_deliveries}
                    </div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Success Rate</div>
                    <div class="metric-value">
                        ${data.summary.success_rate.toFixed(1)}%
                    </div>
                </div>
            `;
            document.getElementById('metrics-grid').innerHTML = metricsHtml;

            // Update endpoint health table
            const endpointRows = Object.entries(data.endpoint_health).map(([url, health]) => `
                <tr>
                    <td>${url}</td>
                    <td>${health.total_calls}</td>
                    <td>
                        <span class="status-badge ${health.success_rate > 90 ? 'status-success' : health.success_rate > 70 ? 'status-warning' : 'status-failed'}">
                            ${health.success_rate.toFixed(1)}%
                        </span>
                    </td>
                    <td>${health.avg_response_time.toFixed(2)}s</td>
                    <td>
                        <span class="status-badge circuit-${health.circuit_breaker_state}">
                            ${health.circuit_breaker_state}
                        </span>
                    </td>
                    <td>${health.recent_errors.join(', ') || 'None'}</td>
                </tr>
            `).join('');
            document.getElementById('endpointTableBody').innerHTML = endpointRows;

            // Update failures table
            const failureRows = data.recent_failures.map(failure => `
                <tr>
                    <td>${new Date(failure.timestamp * 1000).toLocaleTimeString()}</td>
                    <td>${failure.event_type}</td>
                    <td>${failure.endpoint}</td>
                    <td>${failure.error || 'Unknown'}</td>
                </tr>
            `).join('');
            document.getElementById('failuresTableBody').innerHTML = failureRows;
        }

        // Fetch time series data for chart
        async function updateChart() {
            const response = await fetch('/api/time-series?minutes=60');
            const data = await response.json();

            const labels = data.time_series.map(point =>
                new Date(point.timestamp * 1000).toLocaleTimeString()
            );
            const successData = data.time_series.map(point => point.success);
            const failedData = data.time_series.map(point => point.failed);

            deliveryChart.data.labels = labels;
            deliveryChart.data.datasets[0].data = successData;
            deliveryChart.data.datasets[1].data = failedData;
            deliveryChart.update();
        }

        // Update chart every 30 seconds
        setInterval(updateChart, 30000);
        updateChart(); // Initial load
    </script>
</body>
</html>
    """
    return HTMLResponse(content=html)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)