#!/usr/bin/env node
/**
 * Monitoring Dashboard Server
 * Serves real-time monitoring dashboard with WebSocket updates
 */

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs').promises;

class MonitoringDashboard {
    constructor(config, performanceMonitor) {
        this.config = config;
        this.performanceMonitor = performanceMonitor;
        this.app = express();
        this.server = http.createServer(this.app);
        this.wss = new WebSocket.Server({ server: this.server });
        this.clients = new Set();
        
        this.setupExpress();
        this.setupWebSocket();
        this.setupEventHandlers();
    }

    setupExpress() {
        // Serve static files
        this.app.use(express.static(path.join(__dirname, 'public')));
        
        // API endpoints
        this.app.get('/api/metrics', (req, res) => {
            const timeRange = parseInt(req.query.range) || 3600000; // 1 hour default
            const metrics = this.performanceMonitor.getMetrics(timeRange);
            res.json(metrics);
        });

        this.app.get('/api/status', (req, res) => {
            const metrics = this.performanceMonitor.getMetrics(300000); // 5 minutes
            const latest = metrics.summary?.latest;

            const status = {
                timestamp: Date.now(),
                overall: this.calculateOverallStatus(latest),
                services: this.getServiceStatuses(latest),
                alerts: metrics.alerts.length,
                uptime: process.uptime()
            };

            res.json(status);
        });

        // Health check endpoint
        this.app.get('/health', (req, res) => {
            res.status(200).json({
                status: 'healthy',
                service: 'monitoring-dashboard',
                uptime: process.uptime(),
                timestamp: Date.now(),
                version: '1.0.0'
            });
        });

        this.app.get('/api/alerts', (req, res) => {
            const metrics = this.performanceMonitor.getMetrics();
            res.json(metrics.alerts);
        });

        this.app.get('/api/export/:format', async (req, res) => {
            const format = req.params.format;
            try {
                const data = this.performanceMonitor.exportMetrics(format);
                const filename = `metrics-${Date.now()}.${format}`;
                
                res.setHeader('Content-Disposition', `attachment; filename=${filename}`);
                res.setHeader('Content-Type', this.getContentType(format));
                res.send(data);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Serve dashboard HTML
        this.app.get('/', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'index.html'));
        });
    }

    setupWebSocket() {
        this.wss.on('connection', (ws) => {
            this.clients.add(ws);
            console.log('Dashboard client connected');

            // Send initial data
            ws.send(JSON.stringify({
                type: 'initial',
                data: this.performanceMonitor.getMetrics(3600000)
            }));

            ws.on('close', () => {
                this.clients.delete(ws);
                console.log('Dashboard client disconnected');
            });

            ws.on('message', (message) => {
                try {
                    const data = JSON.parse(message);
                    this.handleWebSocketMessage(ws, data);
                } catch (error) {
                    console.error('Invalid WebSocket message:', error);
                }
            });
        });
    }

    setupEventHandlers() {
        // Forward performance monitor events to WebSocket clients
        this.performanceMonitor.on('metrics', (metrics) => {
            this.broadcast({
                type: 'metrics',
                data: metrics
            });
        });

        this.performanceMonitor.on('alert', (alert) => {
            this.broadcast({
                type: 'alert',
                data: alert
            });
        });
    }

    handleWebSocketMessage(ws, message) {
        switch (message.type) {
            case 'request_update':
                const metrics = this.performanceMonitor.getMetrics();
                ws.send(JSON.stringify({
                    type: 'update',
                    data: metrics
                }));
                break;
            
            case 'track_build':
                if (message.data) {
                    const buildId = this.performanceMonitor.trackBuildTime(
                        message.data.project,
                        message.data.type,
                        message.data.duration,
                        message.data.success
                    );
                    ws.send(JSON.stringify({
                        type: 'build_tracked',
                        buildId
                    }));
                }
                break;
                
            case 'track_test':
                if (message.data) {
                    const testId = this.performanceMonitor.trackTestTime(
                        message.data.project,
                        message.data.suite,
                        message.data.duration,
                        message.data.passed,
                        message.data.failed,
                        message.data.skipped
                    );
                    ws.send(JSON.stringify({
                        type: 'test_tracked',
                        testId
                    }));
                }
                break;
        }
    }

    broadcast(message) {
        const data = JSON.stringify(message);
        this.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(data);
            }
        });
    }

    calculateOverallStatus(latest) {
        if (!latest) return 'unknown';
        
        let criticalIssues = 0;
        let warnings = 0;
        
        // Check system metrics
        const cpu = latest.system.cpu.usage?.total || 0;
        const memory = (latest.system.memory.used / latest.system.memory.total) * 100;
        
        if (cpu > 90 || memory > 95) criticalIssues++;
        else if (cpu > 80 || memory > 85) warnings++;
        
        // Check service availability
        for (const [name, service] of Object.entries(latest.services)) {
            if (!service.available) criticalIssues++;
            else if (service.responseTime > 5000) warnings++;
        }
        
        if (criticalIssues > 0) return 'critical';
        if (warnings > 0) return 'warning';
        return 'healthy';
    }

    getServiceStatuses(latest) {
        if (!latest) return {};
        
        const statuses = {};
        for (const [name, service] of Object.entries(latest.services)) {
            statuses[name] = {
                status: service.status,
                available: service.available,
                responseTime: service.responseTime,
                lastCheck: latest.timestamp
            };
        }
        return statuses;
    }

    getContentType(format) {
        switch (format) {
            case 'json': return 'application/json';
            case 'csv': return 'text/csv';
            case 'prometheus': return 'text/plain';
            default: return 'application/octet-stream';
        }
    }

    async start() {
        // Ensure public directory exists with dashboard files
        await this.ensureDashboardFiles();
        
        return new Promise((resolve, reject) => {
            this.server.listen(this.config.port, (error) => {
                if (error) {
                    reject(error);
                } else {
                    console.log(`Monitoring dashboard started on port ${this.config.port}`);
                    console.log(`Access dashboard at: http://localhost:${this.config.port}`);
                    resolve();
                }
            });
        });
    }

    async stop() {
        return new Promise((resolve) => {
            this.server.close(() => {
                console.log('Monitoring dashboard stopped');
                resolve();
            });
        });
    }

    async ensureDashboardFiles() {
        const publicDir = path.join(__dirname, 'public');
        
        try {
            await fs.mkdir(publicDir, { recursive: true });
        } catch (error) {
            // Directory might already exist
        }

        // Create index.html if it doesn't exist
        const indexPath = path.join(publicDir, 'index.html');
        try {
            await fs.access(indexPath);
        } catch (error) {
            await this.createDashboardHTML(indexPath);
        }

        // Create dashboard.css if it doesn't exist
        const cssPath = path.join(publicDir, 'dashboard.css');
        try {
            await fs.access(cssPath);
        } catch (error) {
            await this.createDashboardCSS(cssPath);
        }

        // Create dashboard.js if it doesn't exist
        const jsPath = path.join(publicDir, 'dashboard.js');
        try {
            await fs.access(jsPath);
        } catch (error) {
            await this.createDashboardJS(jsPath);
        }
    }

    async createDashboardHTML(filePath) {
        const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${this.config.title || 'Development Environment Monitor'}</title>
    <link rel="stylesheet" href="dashboard.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <header>
        <h1>${this.config.title || 'Development Environment Monitor'}</h1>
        <div class="status-indicator" id="overallStatus">
            <span class="status-dot"></span>
            <span class="status-text">Loading...</span>
        </div>
    </header>

    <main>
        <div class="dashboard-grid">
            <!-- System Overview -->
            <div class="card">
                <h2>System Overview</h2>
                <div class="metrics-grid">
                    <div class="metric">
                        <div class="metric-value" id="cpuUsage">--</div>
                        <div class="metric-label">CPU Usage</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" id="memoryUsage">--</div>
                        <div class="metric-label">Memory Usage</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" id="uptime">--</div>
                        <div class="metric-label">Uptime</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" id="activeAlerts">--</div>
                        <div class="metric-label">Active Alerts</div>
                    </div>
                </div>
            </div>

            <!-- Services Status -->
            <div class="card">
                <h2>Services Status</h2>
                <div class="services-list" id="servicesList">
                    <div class="loading">Loading services...</div>
                </div>
            </div>

            <!-- CPU Chart -->
            <div class="card chart-card">
                <h2>CPU Usage Over Time</h2>
                <canvas id="cpuChart"></canvas>
            </div>

            <!-- Memory Chart -->
            <div class="card chart-card">
                <h2>Memory Usage Over Time</h2>
                <canvas id="memoryChart"></canvas>
            </div>

            <!-- Build Metrics -->
            <div class="card">
                <h2>Build Metrics</h2>
                <div class="metrics-grid">
                    <div class="metric">
                        <div class="metric-value" id="buildCount">--</div>
                        <div class="metric-label">Builds (24h)</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" id="buildSuccessRate">--</div>
                        <div class="metric-label">Success Rate</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" id="avgBuildTime">--</div>
                        <div class="metric-label">Avg Build Time</div>
                    </div>
                </div>
            </div>

            <!-- Test Metrics -->
            <div class="card">
                <h2>Test Metrics</h2>
                <div class="metrics-grid">
                    <div class="metric">
                        <div class="metric-value" id="testCount">--</div>
                        <div class="metric-label">Tests (24h)</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" id="testSuccessRate">--</div>
                        <div class="metric-label">Success Rate</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" id="avgTestTime">--</div>
                        <div class="metric-label">Avg Test Time</div>
                    </div>
                </div>
            </div>

            <!-- Recent Alerts -->
            <div class="card">
                <h2>Recent Alerts</h2>
                <div class="alerts-list" id="alertsList">
                    <div class="no-alerts">No alerts</div>
                </div>
            </div>

            <!-- Actions -->
            <div class="card">
                <h2>Actions</h2>
                <div class="actions-grid">
                    <button onclick="refreshData()">Refresh Data</button>
                    <button onclick="exportMetrics('json')">Export JSON</button>
                    <button onclick="exportMetrics('csv')">Export CSV</button>
                    <button onclick="clearAlerts()">Clear Alerts</button>
                </div>
            </div>
        </div>
    </main>

    <script src="dashboard.js"></script>
</body>
</html>`;
        
        await fs.writeFile(filePath, html);
    }

    async createDashboardCSS(filePath) {
        const css = `/* Dashboard Styles */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: #f5f5f5;
    color: #333;
    line-height: 1.6;
}

header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 1rem 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

header h1 {
    font-size: 1.5rem;
    font-weight: 600;
}

.status-indicator {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1rem;
    background: rgba(255,255,255,0.1);
    border-radius: 20px;
    backdrop-filter: blur(10px);
}

.status-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background-color: #28a745;
    animation: pulse 2s infinite;
}

.status-dot.warning {
    background-color: #ffc107;
}

.status-dot.critical {
    background-color: #dc3545;
}

.status-dot.unknown {
    background-color: #6c757d;
}

@keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.5; }
    100% { opacity: 1; }
}

main {
    padding: 2rem;
}

.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 1.5rem;
    max-width: 1400px;
    margin: 0 auto;
}

.card {
    background: white;
    border-radius: 10px;
    padding: 1.5rem;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    border: 1px solid #e0e0e0;
    transition: transform 0.2s, box-shadow 0.2s;
}

.card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 15px rgba(0,0,0,0.15);
}

.card h2 {
    color: #2c3e50;
    margin-bottom: 1rem;
    font-size: 1.2rem;
    font-weight: 600;
    border-bottom: 2px solid #ecf0f1;
    padding-bottom: 0.5rem;
}

.metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 1rem;
}

.metric {
    text-align: center;
    padding: 1rem;
    background: #f8f9fa;
    border-radius: 8px;
    border-left: 4px solid #667eea;
}

.metric-value {
    font-size: 1.8rem;
    font-weight: bold;
    color: #2c3e50;
    margin-bottom: 0.25rem;
}

.metric-label {
    font-size: 0.9rem;
    color: #6c757d;
    text-transform: uppercase;
    font-weight: 500;
}

.services-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
}

.service-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.75rem;
    background: #f8f9fa;
    border-radius: 6px;
    border-left: 4px solid #28a745;
}

.service-item.warning {
    border-left-color: #ffc107;
}

.service-item.error {
    border-left-color: #dc3545;
}

.service-name {
    font-weight: 600;
    color: #2c3e50;
}

.service-status {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.9rem;
}

.service-response-time {
    color: #6c757d;
    font-size: 0.8rem;
}

.chart-card {
    grid-column: span 2;
}

.chart-card canvas {
    max-height: 300px;
}

.alerts-list {
    max-height: 200px;
    overflow-y: auto;
}

.alert-item {
    padding: 0.75rem;
    margin-bottom: 0.5rem;
    border-radius: 6px;
    border-left: 4px solid #ffc107;
    background: #fff3cd;
}

.alert-item.critical {
    border-left-color: #dc3545;
    background: #f8d7da;
}

.alert-message {
    font-weight: 500;
    color: #2c3e50;
}

.alert-time {
    font-size: 0.8rem;
    color: #6c757d;
    margin-top: 0.25rem;
}

.actions-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 0.75rem;
}

.actions-grid button {
    padding: 0.75rem 1rem;
    border: none;
    border-radius: 6px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
}

.actions-grid button:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 8px rgba(0,0,0,0.2);
}

.loading {
    text-align: center;
    color: #6c757d;
    font-style: italic;
    padding: 2rem;
}

.no-alerts {
    text-align: center;
    color: #28a745;
    font-style: italic;
    padding: 1rem;
}

/* Responsive Design */
@media (max-width: 768px) {
    header {
        flex-direction: column;
        gap: 1rem;
        text-align: center;
    }
    
    .dashboard-grid {
        grid-template-columns: 1fr;
    }
    
    .chart-card {
        grid-column: span 1;
    }
    
    .metrics-grid {
        grid-template-columns: repeat(2, 1fr);
    }
    
    .actions-grid {
        grid-template-columns: repeat(2, 1fr);
    }
}

@media (max-width: 480px) {
    main {
        padding: 1rem;
    }
    
    .card {
        padding: 1rem;
    }
    
    .metrics-grid {
        grid-template-columns: 1fr;
    }
    
    .actions-grid {
        grid-template-columns: 1fr;
    }
}

/* Dark mode support */
@media (prefers-color-scheme: dark) {
    body {
        background-color: #1a1a1a;
        color: #e0e0e0;
    }
    
    .card {
        background: #2d2d2d;
        border-color: #404040;
    }
    
    .card h2 {
        color: #e0e0e0;
        border-bottom-color: #404040;
    }
    
    .metric {
        background: #383838;
    }
    
    .metric-value {
        color: #e0e0e0;
    }
    
    .service-item {
        background: #383838;
    }
    
    .service-name {
        color: #e0e0e0;
    }
}`;
        
        await fs.writeFile(filePath, css);
    }

    async createDashboardJS(filePath) {
        const js = `// Dashboard JavaScript
class MonitoringDashboard {
    constructor() {
        this.ws = null;
        this.charts = {};
        this.isConnected = false;
        this.reconnectInterval = 5000;
        this.refreshInterval = ${this.config.refreshInterval || 5000};
        
        this.init();
    }

    init() {
        this.connectWebSocket();
        this.setupCharts();
        this.startRefreshTimer();
        
        // Initial data load
        this.loadInitialData();
    }

    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = \`\${protocol}//\${window.location.host}\`;
        
        try {
            this.ws = new WebSocket(wsUrl);
            
            this.ws.onopen = () => {
                console.log('WebSocket connected');
                this.isConnected = true;
                this.updateConnectionStatus(true);
            };
            
            this.ws.onmessage = (event) => {
                const message = JSON.parse(event.data);
                this.handleWebSocketMessage(message);
            };
            
            this.ws.onclose = () => {
                console.log('WebSocket disconnected');
                this.isConnected = false;
                this.updateConnectionStatus(false);
                
                // Attempt to reconnect
                setTimeout(() => {
                    this.connectWebSocket();
                }, this.reconnectInterval);
            };
            
            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
            
        } catch (error) {
            console.error('Failed to connect WebSocket:', error);
        }
    }

    handleWebSocketMessage(message) {
        switch (message.type) {
            case 'initial':
                this.updateDashboard(message.data);
                break;
            case 'metrics':
                this.updateMetrics(message.data);
                break;
            case 'alert':
                this.addAlert(message.data);
                break;
            case 'update':
                this.updateDashboard(message.data);
                break;
        }
    }

    async loadInitialData() {
        try {
            const response = await fetch('/api/metrics');
            const data = await response.json();
            this.updateDashboard(data);
        } catch (error) {
            console.error('Failed to load initial data:', error);
        }
    }

    updateDashboard(data) {
        this.updateSystemMetrics(data.summary?.latest);
        this.updateServices(data.summary?.latest?.services);
        this.updateBuildMetrics(data.build);
        this.updateTestMetrics(data.test);
        this.updateAlerts(data.alerts);
        this.updateCharts(data.metrics);
    }

    updateSystemMetrics(latest) {
        if (!latest) return;
        
        const cpu = latest.system.cpu.usage?.total || 0;
        const memory = (latest.system.memory.used / latest.system.memory.total) * 100;
        const uptime = this.formatUptime(latest.system.uptime);
        
        document.getElementById('cpuUsage').textContent = \`\${cpu.toFixed(1)}%\`;
        document.getElementById('memoryUsage').textContent = \`\${memory.toFixed(1)}%\`;
        document.getElementById('uptime').textContent = uptime;
        
        // Update overall status
        this.updateOverallStatus(latest);
    }

    updateOverallStatus(latest) {
        const statusElement = document.getElementById('overallStatus');
        const statusDot = statusElement.querySelector('.status-dot');
        const statusText = statusElement.querySelector('.status-text');
        
        let status = 'healthy';
        let text = 'All Systems Operational';
        
        // Check for critical issues
        const cpu = latest.system.cpu.usage?.total || 0;
        const memory = (latest.system.memory.used / latest.system.memory.total) * 100;
        
        if (cpu > 90 || memory > 95) {
            status = 'critical';
            text = 'Critical System Load';
        } else if (cpu > 80 || memory > 85) {
            status = 'warning';
            text = 'High System Load';
        }
        
        // Check service availability
        if (latest.services) {
            for (const [name, service] of Object.entries(latest.services)) {
                if (!service.available) {
                    status = 'critical';
                    text = 'Service Unavailable';
                    break;
                } else if (service.responseTime > 5000) {
                    if (status !== 'critical') {
                        status = 'warning';
                        text = 'Slow Response Times';
                    }
                }
            }
        }
        
        statusDot.className = \`status-dot \${status}\`;
        statusText.textContent = text;
    }

    updateServices(services) {
        const servicesList = document.getElementById('servicesList');
        
        if (!services || Object.keys(services).length === 0) {
            servicesList.innerHTML = '<div class="loading">No services configured</div>';
            return;
        }
        
        const servicesHTML = Object.entries(services).map(([name, service]) => {
            const statusClass = !service.available ? 'error' : 
                               service.responseTime > 5000 ? 'warning' : '';
            const statusText = service.status || 'unknown';
            const responseTime = service.responseTime ? 
                \`<span class="service-response-time">(\${service.responseTime}ms)</span>\` : '';
            
            return \`
                <div class="service-item \${statusClass}">
                    <span class="service-name">\${name}</span>
                    <div class="service-status">
                        <span>\${statusText}</span>
                        \${responseTime}
                    </div>
                </div>
            \`;
        }).join('');
        
        servicesList.innerHTML = servicesHTML;
    }

    updateBuildMetrics(build) {
        if (!build) return;
        
        document.getElementById('buildCount').textContent = build.last24h || 0;
        document.getElementById('buildSuccessRate').textContent = \`\${build.successRate || 0}%\`;
        document.getElementById('avgBuildTime').textContent = \`\${build.averageDuration || 0}ms\`;
    }

    updateTestMetrics(test) {
        if (!test) return;
        
        document.getElementById('testCount').textContent = test.last24h || 0;
        document.getElementById('testSuccessRate').textContent = \`\${test.successRate || 0}%\`;
        document.getElementById('avgTestTime').textContent = \`\${test.averageDuration || 0}ms\`;
    }

    updateAlerts(alerts) {
        const alertsList = document.getElementById('alertsList');
        const alertCount = document.getElementById('activeAlerts');
        
        alertCount.textContent = alerts ? alerts.length : 0;
        
        if (!alerts || alerts.length === 0) {
            alertsList.innerHTML = '<div class="no-alerts">No active alerts</div>';
            return;
        }
        
        const alertsHTML = alerts.slice(0, 5).map(alert => {
            const severity = alert.severity === 'critical' ? 'critical' : '';
            const time = new Date(alert.timestamp).toLocaleTimeString();
            
            return \`
                <div class="alert-item \${severity}">
                    <div class="alert-message">\${alert.message}</div>
                    <div class="alert-time">\${time}</div>
                </div>
            \`;
        }).join('');
        
        alertsList.innerHTML = alertsHTML;
    }

    setupCharts() {
        // CPU Chart
        const cpuCtx = document.getElementById('cpuChart').getContext('2d');
        this.charts.cpu = new Chart(cpuCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'CPU Usage (%)',
                    data: [],
                    borderColor: 'rgb(75, 192, 192)',
                    backgroundColor: 'rgba(75, 192, 192, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
        
        // Memory Chart
        const memoryCtx = document.getElementById('memoryChart').getContext('2d');
        this.charts.memory = new Chart(memoryCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Memory Usage (%)',
                    data: [],
                    borderColor: 'rgb(255, 99, 132)',
                    backgroundColor: 'rgba(255, 99, 132, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }

    updateCharts(metrics) {
        if (!metrics || metrics.length === 0) return;
        
        // Get last 20 data points for charts
        const chartData = metrics.slice(-20);
        
        // Update CPU chart
        const cpuData = chartData.map(m => m.system.cpu.usage?.total || 0);
        const labels = chartData.map(m => new Date(m.timestamp).toLocaleTimeString());
        
        this.charts.cpu.data.labels = labels;
        this.charts.cpu.data.datasets[0].data = cpuData;
        this.charts.cpu.update('none');
        
        // Update Memory chart
        const memoryData = chartData.map(m => (m.system.memory.used / m.system.memory.total) * 100);
        
        this.charts.memory.data.labels = labels;
        this.charts.memory.data.datasets[0].data = memoryData;
        this.charts.memory.update('none');
    }

    updateMetrics(metrics) {
        // Update charts with new metric point
        if (this.charts.cpu && this.charts.memory) {
            const time = new Date(metrics.timestamp).toLocaleTimeString();
            const cpu = metrics.system.cpu.usage?.total || 0;
            const memory = (metrics.system.memory.used / metrics.system.memory.total) * 100;
            
            // Add new data point
            this.charts.cpu.data.labels.push(time);
            this.charts.cpu.data.datasets[0].data.push(cpu);
            
            this.charts.memory.data.labels.push(time);
            this.charts.memory.data.datasets[0].data.push(memory);
            
            // Keep only last 20 points
            if (this.charts.cpu.data.labels.length > 20) {
                this.charts.cpu.data.labels.shift();
                this.charts.cpu.data.datasets[0].data.shift();
                this.charts.memory.data.labels.shift();
                this.charts.memory.data.datasets[0].data.shift();
            }
            
            this.charts.cpu.update('none');
            this.charts.memory.update('none');
        }
        
        // Update current metrics display
        this.updateSystemMetrics(metrics);
    }

    addAlert(alert) {
        // Update alert count
        const alertCount = document.getElementById('activeAlerts');
        const currentCount = parseInt(alertCount.textContent) || 0;
        alertCount.textContent = currentCount + 1;
        
        // Add alert to list
        const alertsList = document.getElementById('alertsList');
        const noAlerts = alertsList.querySelector('.no-alerts');
        if (noAlerts) {
            alertsList.innerHTML = '';
        }
        
        const severity = alert.severity === 'critical' ? 'critical' : '';
        const time = new Date(alert.timestamp).toLocaleTimeString();
        
        const alertHTML = \`
            <div class="alert-item \${severity}">
                <div class="alert-message">\${alert.message}</div>
                <div class="alert-time">\${time}</div>
            </div>
        \`;
        
        alertsList.insertAdjacentHTML('afterbegin', alertHTML);
        
        // Keep only last 5 alerts visible
        const alerts = alertsList.querySelectorAll('.alert-item');
        if (alerts.length > 5) {
            alerts[alerts.length - 1].remove();
        }
    }

    startRefreshTimer() {
        setInterval(() => {
            if (!this.isConnected) {
                this.loadInitialData();
            }
        }, this.refreshInterval);
    }

    updateConnectionStatus(connected) {
        // Could add connection status indicator to UI
        console.log(connected ? 'Connected to monitoring server' : 'Disconnected from monitoring server');
    }

    formatUptime(seconds) {
        if (!seconds) return '0s';
        
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        
        if (days > 0) return \`\${days}d \${hours}h\`;
        if (hours > 0) return \`\${hours}h \${minutes}m\`;
        return \`\${minutes}m\`;
    }
}

// Global functions for button actions
function refreshData() {
    if (dashboard.isConnected && dashboard.ws) {
        dashboard.ws.send(JSON.stringify({ type: 'request_update' }));
    } else {
        dashboard.loadInitialData();
    }
}

function exportMetrics(format) {
    window.open(\`/api/export/\${format}\`, '_blank');
}

function clearAlerts() {
    document.getElementById('alertsList').innerHTML = '<div class="no-alerts">No active alerts</div>';
    document.getElementById('activeAlerts').textContent = '0';
}

// Initialize dashboard when page loads
let dashboard;
document.addEventListener('DOMContentLoaded', () => {
    dashboard = new MonitoringDashboard();
});`;
        
        await fs.writeFile(filePath, js);
    }
}

module.exports = MonitoringDashboard;