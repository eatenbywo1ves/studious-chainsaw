// Multi-Agent Observatory Dashboard
class ObservatoryDashboard {
    constructor() {
        this.ws = null;
        this.reconnectInterval = 5000;
        this.maxReconnectAttempts = 10;
        this.reconnectAttempts = 0;
        this.isConnected = false;
        
        this.agents = new Map();
        this.metrics = [];
        this.events = [];
        this.stats = {
            totalAgents: 0,
            activeAgents: 0,
            totalEvents: 0,
            totalMetrics: 0
        };
        
        this.chart = null;
        
        this.init();
    }

    init() {
        console.log('🚀 Initializing Observatory Dashboard...');
        this.connect();
        this.initChart();
        this.fetchInitialData();
        
        // Update UI every 5 seconds
        setInterval(() => {
            this.updateUI();
        }, 5000);
    }

    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//localhost:8080/ws`;
        
        console.log(`🔌 Connecting to ${wsUrl}...`);
        
        try {
            this.ws = new WebSocket(wsUrl);
            this.setupWebSocketHandlers();
        } catch (error) {
            console.error('❌ Connection failed:', error);
            this.scheduleReconnect();
        }
    }

    setupWebSocketHandlers() {
        this.ws.onopen = () => {
            console.log('✅ Connected to Observatory Server');
            this.isConnected = true;
            this.reconnectAttempts = 0;
            this.updateConnectionStatus(true);
            
            // Register as dashboard client
            this.sendMessage({
                type: 'register',
                agentName: 'Dashboard-Client',
                metadata: {
                    type: 'dashboard',
                    userAgent: navigator.userAgent,
                    timestamp: new Date().toISOString()
                }
            });
        };

        this.ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                this.handleServerMessage(message);
            } catch (error) {
                console.error('❌ Invalid message from server:', error);
            }
        };

        this.ws.onclose = (event) => {
            console.log(`🔌 Disconnected from server: ${event.code} ${event.reason}`);
            this.isConnected = false;
            this.updateConnectionStatus(false);
            this.scheduleReconnect();
        };

        this.ws.onerror = (error) => {
            console.error('❌ WebSocket error:', error);
        };
    }

    handleServerMessage(message) {
        switch (message.type) {
            case 'welcome':
                console.log('👋 Server welcome:', message.message);
                break;
                
            case 'agent_registered':
                this.handleAgentRegistered(message);
                break;
                
            case 'agent_status_update':
                this.handleAgentStatusUpdate(message);
                break;
                
            case 'metrics_update':
                this.handleMetricsUpdate(message);
                break;
                
            case 'event_update':
                this.handleEventUpdate(message);
                break;
                
            default:
                console.log('📨 Unknown message type:', message.type, message);
        }
    }

    handleAgentRegistered(message) {
        const agent = {
            name: message.agentName,
            status: message.status,
            metadata: message.metadata,
            lastSeen: new Date(message.timestamp),
            metrics: {},
            eventCount: 0
        };
        
        this.agents.set(message.agentName, agent);
        this.updateAgentCard(agent);
        this.updateStats();
        
        console.log(`✅ Agent registered: ${message.agentName}`);
    }

    handleAgentStatusUpdate(message) {
        const agent = this.agents.get(message.agentName);
        if (agent) {
            agent.status = message.status;
            agent.lastSeen = new Date(message.timestamp);
            this.updateAgentCard(agent);
            this.updateStats();
        }
    }

    handleMetricsUpdate(message) {
        const agent = this.agents.get(message.agentName);
        if (agent) {
            // Update agent's latest metrics
            for (const metric of message.metrics) {
                agent.metrics[metric.name] = metric;
            }
            agent.lastSeen = new Date(message.timestamp);
            this.updateAgentCard(agent);
        }
        
        // Add to global metrics for charting
        this.metrics.push({
            agentName: message.agentName,
            metrics: message.metrics,
            timestamp: new Date(message.timestamp)
        });
        
        // Keep only last 50 metric updates
        if (this.metrics.length > 50) {
            this.metrics = this.metrics.slice(-50);
        }
        
        this.updateChart();
        this.updateStats();
    }

    handleEventUpdate(message) {
        const event = {
            agentName: message.agentName,
            eventType: message.eventType,
            severity: message.severity,
            message: message.message,
            data: message.data,
            timestamp: new Date(message.timestamp)
        };
        
        this.events.unshift(event); // Add to beginning
        
        // Keep only last 100 events
        if (this.events.length > 100) {
            this.events = this.events.slice(0, 100);
        }
        
        // Update agent event count
        const agent = this.agents.get(message.agentName);
        if (agent) {
            agent.eventCount++;
            this.updateAgentCard(agent);
        }
        
        this.updateEventsList();
        this.updateStats();
    }

    updateAgentCard(agent) {
        const agentsGrid = document.getElementById('agentsGrid');
        let card = document.getElementById(`agent-${agent.name}`);
        
        if (!card) {
            card = document.createElement('div');
            card.id = `agent-${agent.name}`;
            card.className = 'agent-card';
            agentsGrid.appendChild(card);
        }
        
        // Update card status
        card.className = `agent-card ${agent.status}`;
        
        // Get latest metrics for display
        const latestMetrics = Object.values(agent.metrics).slice(0, 3);
        const metricsHtml = latestMetrics.map(metric => 
            `<div>${metric.name}: ${typeof metric.value === 'number' ? metric.value.toFixed(2) : metric.value}${metric.unit || ''}</div>`
        ).join('');
        
        card.innerHTML = `
            <div class="agent-name">${agent.name}</div>
            <div class="agent-status status-${agent.status}">${agent.status.toUpperCase()}</div>
            <div class="agent-metrics">
                ${metricsHtml || '<div>No metrics yet</div>'}
                <div style="margin-top: 8px; font-size: 0.8rem; color: #94a3b8;">
                    Events: ${agent.eventCount} | Last seen: ${this.formatTime(agent.lastSeen)}
                </div>
            </div>
        `;
        
        // Add pulse animation for updates
        card.classList.add('pulse');
        setTimeout(() => card.classList.remove('pulse'), 500);
    }

    updateEventsList() {
        const eventsList = document.getElementById('eventsList');
        
        eventsList.innerHTML = this.events.map(event => `
            <div class="event-item event-${event.severity}">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                    <div>
                        <strong>${event.agentName}</strong> - ${event.eventType}
                        <div style="margin-top: 4px;">${event.message}</div>
                    </div>
                    <div class="event-timestamp">${this.formatTime(event.timestamp)}</div>
                </div>
            </div>
        `).join('');
    }

    initChart() {
        const ctx = document.getElementById('metricsChart').getContext('2d');
        
        this.chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: []
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Real-time Metrics',
                        color: '#e2e8f0'
                    },
                    legend: {
                        labels: {
                            color: '#e2e8f0'
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#94a3b8' },
                        grid: { color: 'rgba(148, 163, 184, 0.2)' }
                    },
                    y: {
                        ticks: { color: '#94a3b8' },
                        grid: { color: 'rgba(148, 163, 184, 0.2)' }
                    }
                },
                animation: {
                    duration: 300
                }
            }
        });
    }

    updateChart() {
        if (!this.chart || this.metrics.length === 0) return;
        
        // Get last 20 data points
        const recentMetrics = this.metrics.slice(-20);
        
        // Create datasets for different metric types
        const datasets = new Map();
        const colors = ['#4f46e5', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4'];
        let colorIndex = 0;
        
        for (const metricUpdate of recentMetrics) {
            for (const metric of metricUpdate.metrics) {
                if (metric.name === 'memory_usage_percent' || metric.name === 'cpu_usage' || metric.name === 'load_1min') {
                    const key = `${metricUpdate.agentName}-${metric.name}`;
                    
                    if (!datasets.has(key)) {
                        datasets.set(key, {
                            label: `${metricUpdate.agentName} ${metric.name}`,
                            data: [],
                            borderColor: colors[colorIndex % colors.length],
                            backgroundColor: colors[colorIndex % colors.length] + '20',
                            tension: 0.4,
                            fill: false
                        });
                        colorIndex++;
                    }
                    
                    datasets.get(key).data.push({
                        x: metricUpdate.timestamp,
                        y: metric.value
                    });
                }
            }
        }
        
        // Update chart
        this.chart.data.labels = recentMetrics.map(m => this.formatTime(m.timestamp, true));
        this.chart.data.datasets = Array.from(datasets.values()).slice(0, 6); // Limit to 6 datasets
        this.chart.update('none'); // No animation for smoother updates
    }

    updateStats() {
        this.stats.totalAgents = this.agents.size;
        this.stats.activeAgents = Array.from(this.agents.values()).filter(a => a.status === 'active').length;
        this.stats.totalEvents = this.events.length;
        this.stats.totalMetrics = this.metrics.length;
        
        document.getElementById('totalAgents').textContent = this.stats.totalAgents;
        document.getElementById('activeAgents').textContent = this.stats.activeAgents;
        document.getElementById('totalEvents').textContent = this.stats.totalEvents;
        document.getElementById('totalMetrics').textContent = this.stats.totalMetrics;
    }

    updateConnectionStatus(connected) {
        const statusEl = document.getElementById('connectionStatus');
        if (connected) {
            statusEl.textContent = 'Connected';
            statusEl.className = 'status-indicator status-connected';
        } else {
            statusEl.textContent = 'Disconnected';
            statusEl.className = 'status-indicator status-disconnected';
        }
    }

    updateUI() {
        // Update last seen times and check for stale agents
        const now = new Date();
        for (const [name, agent] of this.agents) {
            const timeSinceLastSeen = now - agent.lastSeen;
            if (timeSinceLastSeen > 60000 && agent.status === 'active') { // 1 minute
                agent.status = 'inactive';
                this.updateAgentCard(agent);
            }
        }
        this.updateStats();
    }

    async fetchInitialData() {
        try {
            // Fetch agents
            const agentsResponse = await fetch('http://localhost:8080/api/agents');
            const agents = await agentsResponse.json();
            
            for (const agentData of agents) {
                const agent = {
                    name: agentData.name,
                    status: agentData.status,
                    metadata: JSON.parse(agentData.metadata || '{}'),
                    lastSeen: new Date(agentData.last_seen),
                    metrics: {},
                    eventCount: 0
                };
                this.agents.set(agent.name, agent);
                this.updateAgentCard(agent);
            }
            
            // Fetch recent events
            const eventsResponse = await fetch('http://localhost:8080/api/events');
            const eventsData = await eventsResponse.json();
            
            this.events = eventsData.map(event => ({
                agentName: event.agent_name,
                eventType: event.event_type,
                severity: event.severity,
                message: event.message,
                data: JSON.parse(event.data || '{}'),
                timestamp: new Date(event.timestamp)
            }));
            
            this.updateEventsList();
            this.updateStats();
            
            console.log('✅ Initial data loaded');
        } catch (error) {
            console.error('❌ Failed to fetch initial data:', error);
        }
    }

    sendMessage(message) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(message));
        }
    }

    scheduleReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('❌ Max reconnection attempts reached');
            return;
        }
        
        this.reconnectAttempts++;
        console.log(`🔄 Reconnecting in ${this.reconnectInterval}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
        
        setTimeout(() => {
            this.connect();
        }, this.reconnectInterval);
    }

    formatTime(date, short = false) {
        if (short) {
            return date.toLocaleTimeString('en-US', { 
                hour12: false, 
                hour: '2-digit', 
                minute: '2-digit' 
            });
        }
        return date.toLocaleTimeString('en-US', { 
            hour12: false, 
            hour: '2-digit', 
            minute: '2-digit', 
            second: '2-digit' 
        });
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new ObservatoryDashboard();
});