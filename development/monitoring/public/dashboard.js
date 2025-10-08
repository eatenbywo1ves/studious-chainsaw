// Dashboard JavaScript
class MonitoringDashboard {
    constructor() {
        this.ws = null;
        this.charts = {};
        this.isConnected = false;
        this.reconnectInterval = 5000;
        this.refreshInterval = 5000;
        
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
        const wsUrl = `${protocol}//${window.location.host}`;
        
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
        
        document.getElementById('cpuUsage').textContent = `${cpu.toFixed(1)}%`;
        document.getElementById('memoryUsage').textContent = `${memory.toFixed(1)}%`;
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
        
        statusDot.className = `status-dot ${status}`;
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
                `<span class="service-response-time">(${service.responseTime}ms)</span>` : '';
            
            return `
                <div class="service-item ${statusClass}">
                    <span class="service-name">${name}</span>
                    <div class="service-status">
                        <span>${statusText}</span>
                        ${responseTime}
                    </div>
                </div>
            `;
        }).join('');
        
        servicesList.innerHTML = servicesHTML;
    }

    updateBuildMetrics(build) {
        if (!build) return;
        
        document.getElementById('buildCount').textContent = build.last24h || 0;
        document.getElementById('buildSuccessRate').textContent = `${build.successRate || 0}%`;
        document.getElementById('avgBuildTime').textContent = `${build.averageDuration || 0}ms`;
    }

    updateTestMetrics(test) {
        if (!test) return;
        
        document.getElementById('testCount').textContent = test.last24h || 0;
        document.getElementById('testSuccessRate').textContent = `${test.successRate || 0}%`;
        document.getElementById('avgTestTime').textContent = `${test.averageDuration || 0}ms`;
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
            
            return `
                <div class="alert-item ${severity}">
                    <div class="alert-message">${alert.message}</div>
                    <div class="alert-time">${time}</div>
                </div>
            `;
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
        
        const alertHTML = `
            <div class="alert-item ${severity}">
                <div class="alert-message">${alert.message}</div>
                <div class="alert-time">${time}</div>
            </div>
        `;
        
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
        
        if (days > 0) return `${days}d ${hours}h`;
        if (hours > 0) return `${hours}h ${minutes}m`;
        return `${minutes}m`;
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
    window.open(`/api/export/${format}`, '_blank');
}

function clearAlerts() {
    document.getElementById('alertsList').innerHTML = '<div class="no-alerts">No active alerts</div>';
    document.getElementById('activeAlerts').textContent = '0';
}

// Initialize dashboard when page loads
let dashboard;
document.addEventListener('DOMContentLoaded', () => {
    dashboard = new MonitoringDashboard();
});