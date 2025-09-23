// MCP Server Communication Tracker
// Real-time visualization of MCP server interactions

class MCPTracker {
    constructor() {
        this.width = window.innerWidth - 650; // Account for sidebars
        this.height = window.innerHeight - 80;
        this.servers = new Map();
        this.messages = [];
        this.selectedMessage = null;
        this.isPaused = false;
        this.timeRange = 3600000; // 1 hour in ms

        this.messageTypes = {
            'request': { color: '#06b6d4', icon: '→' },
            'response': { color: '#10b981', icon: '←' },
            'error': { color: '#ef4444', icon: '✗' },
            'webhook': { color: '#f59e0b', icon: '🔔' },
            'health': { color: '#8b5cf6', icon: '💓' }
        };

        this.initializeVisualization();
        this.loadMCPServers();
        this.startMessageSimulation();
        this.setupEventListeners();
    }

    initializeVisualization() {
        // Initialize SVG
        this.svg = d3.select('#timeline-svg')
            .attr('width', this.width)
            .attr('height', this.height);

        // Create scales
        this.timeScale = d3.scaleTime()
            .domain([new Date(Date.now() - this.timeRange), new Date()])
            .range([50, this.width - 50]);

        this.serverScale = d3.scaleBand()
            .range([50, this.height - 100])
            .padding(0.2);

        // Create main groups
        this.axisGroup = this.svg.append('g').attr('class', 'axis-group');
        this.laneGroup = this.svg.append('g').attr('class', 'lane-group');
        this.messageGroup = this.svg.append('g').attr('class', 'message-group');

        this.renderAxes();
    }

    loadMCPServers() {
        const mcpServers = [
            {
                id: 'financial-mcp',
                name: 'Financial MCP',
                url: 'http://localhost:8001',
                status: 'online',
                type: 'financial',
                lastSeen: Date.now(),
                messageCount: 0,
                errorCount: 0,
                avgResponseTime: 150
            },
            {
                id: 'prims-mcp',
                name: 'PRIMS MCP',
                url: 'http://localhost:8002',
                status: 'online',
                type: 'search',
                lastSeen: Date.now(),
                messageCount: 0,
                errorCount: 0,
                avgResponseTime: 230
            },
            {
                id: 'repo-mapper-mcp',
                name: 'RepoMapper MCP',
                url: 'http://localhost:8003',
                status: 'online',
                type: 'analysis',
                lastSeen: Date.now(),
                messageCount: 0,
                errorCount: 0,
                avgResponseTime: 180
            },
            {
                id: 'js-executor-mcp',
                name: 'JS Executor MCP',
                url: 'http://localhost:8004',
                status: 'online',
                type: 'execution',
                lastSeen: Date.now(),
                messageCount: 0,
                errorCount: 0,
                avgResponseTime: 320
            },
            {
                id: 'desktop-notify-mcp',
                name: 'Desktop Notify MCP',
                url: 'http://localhost:8005',
                status: 'warning',
                type: 'notification',
                lastSeen: Date.now() - 30000,
                messageCount: 0,
                errorCount: 0,
                avgResponseTime: 95
            },
            {
                id: 'webhook-audio-tracker',
                name: 'Audio Tracker',
                url: 'http://localhost:8081',
                status: 'online',
                type: 'webhook',
                lastSeen: Date.now(),
                messageCount: 0,
                errorCount: 0,
                avgResponseTime: 75
            }
        ];

        mcpServers.forEach(server => {
            this.servers.set(server.id, server);
        });

        this.updateServerScale();
        this.renderServerList();
        this.renderServerLanes();
        this.updateStats();
    }

    updateServerScale() {
        const serverIds = Array.from(this.servers.keys());
        this.serverScale.domain(serverIds);
    }

    renderAxes() {
        // Clear existing axes
        this.axisGroup.selectAll('*').remove();

        // Time axis
        const timeAxis = d3.axisBottom(this.timeScale)
            .tickFormat(d3.timeFormat('%H:%M:%S'))
            .ticks(8);

        this.axisGroup.append('g')
            .attr('class', 'time-axis')
            .attr('transform', `translate(0, ${this.height - 80})`)
            .call(timeAxis)
            .selectAll('text')
            .style('fill', '#94a3b8')
            .style('font-size', '11px');

        this.axisGroup.selectAll('.time-axis path, .time-axis line')
            .style('stroke', '#475569');

        // Grid lines
        this.axisGroup.selectAll('.grid-line')
            .data(this.timeScale.ticks(8))
            .enter()
            .append('line')
            .attr('class', 'grid-line')
            .attr('x1', d => this.timeScale(d))
            .attr('x2', d => this.timeScale(d))
            .attr('y1', 50)
            .attr('y2', this.height - 80)
            .style('stroke', '#334155')
            .style('stroke-width', 1)
            .style('opacity', 0.3);
    }

    renderServerList() {
        const serverContainer = document.getElementById('server-items');
        serverContainer.innerHTML = '';

        this.servers.forEach(server => {
            const serverElement = document.createElement('div');
            serverElement.className = 'server-item';
            serverElement.dataset.serverId = server.id;

            const statusClass = `status-${server.status}`;
            const icon = this.getServerIcon(server.type);

            serverElement.innerHTML = `
                <div class="server-name">
                    ${icon} ${server.name}
                </div>
                <div class="server-status">
                    <span class="status-dot ${statusClass}"></span>
                    ${server.status} • ${server.messageCount} msgs
                </div>
            `;

            serverElement.addEventListener('click', () => {
                document.querySelectorAll('.server-item').forEach(el =>
                    el.classList.remove('active'));
                serverElement.classList.add('active');
                this.highlightServerMessages(server.id);
            });

            serverContainer.appendChild(serverElement);
        });
    }

    renderServerLanes() {
        // Clear existing lanes
        this.laneGroup.selectAll('*').remove();

        // Draw server lanes
        this.servers.forEach((server, serverId) => {
            const y = this.serverScale(serverId);
            const laneHeight = this.serverScale.bandwidth();

            // Lane background
            this.laneGroup.append('rect')
                .attr('class', 'server-lane-bg')
                .attr('x', 50)
                .attr('y', y)
                .attr('width', this.width - 100)
                .attr('height', laneHeight)
                .attr('fill', 'rgba(168, 85, 247, 0.02)')
                .attr('stroke', 'rgba(168, 85, 247, 0.1)')
                .attr('stroke-width', 1);

            // Server label
            this.laneGroup.append('text')
                .attr('class', 'server-label')
                .attr('x', 45)
                .attr('y', y + laneHeight / 2)
                .attr('text-anchor', 'end')
                .attr('dominant-baseline', 'middle')
                .style('fill', '#94a3b8')
                .style('font-size', '10px')
                .text(server.name.split(' ')[0]);
        });
    }

    startMessageSimulation() {
        // Simulate real-time MCP messages
        const generateMessage = () => {
            if (this.isPaused) return;

            const serverIds = Array.from(this.servers.keys());
            const randomServerId = serverIds[Math.floor(Math.random() * serverIds.length)];
            const server = this.servers.get(randomServerId);

            if (!server || server.status === 'offline') return;

            const messageTypes = ['request', 'response', 'health'];
            if (Math.random() > 0.9) messageTypes.push('error');
            if (server.type === 'webhook') messageTypes.push('webhook');

            const messageType = messageTypes[Math.floor(Math.random() * messageTypes.length)];

            const message = {
                id: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                serverId: randomServerId,
                type: messageType,
                timestamp: Date.now(),
                method: this.getRandomMethod(server.type),
                size: Math.floor(Math.random() * 5000) + 100,
                responseTime: messageType === 'request' ?
                    server.avgResponseTime + (Math.random() - 0.5) * 100 : null,
                payload: this.generatePayload(messageType, server.type),
                status: messageType === 'error' ? 'error' : 'success'
            };

            this.addMessage(message);
            server.messageCount++;
            if (messageType === 'error') server.errorCount++;

            // Update last seen
            server.lastSeen = Date.now();
        };

        // Generate messages at varying intervals
        const scheduleNext = () => {
            const interval = Math.random() * 3000 + 500; // 0.5-3.5 seconds
            setTimeout(() => {
                generateMessage();
                scheduleNext();
            }, interval);
        };

        scheduleNext();

        // Update visualization periodically
        setInterval(() => {
            this.updateTimeline();
            this.updateStats();
        }, 1000);
    }

    addMessage(message) {
        this.messages.push(message);

        // Keep only messages within time range
        const cutoff = Date.now() - this.timeRange;
        this.messages = this.messages.filter(msg => msg.timestamp >= cutoff);

        this.renderMessage(message);
    }

    renderMessage(message) {
        const server = this.servers.get(message.serverId);
        if (!server) return;

        const x = this.timeScale(new Date(message.timestamp));
        const y = this.serverScale(message.serverId) + this.serverScale.bandwidth() / 2;

        const messageConfig = this.messageTypes[message.type];

        // Create message bubble
        const bubble = this.messageGroup.append('circle')
            .attr('class', 'message-bubble')
            .attr('cx', x)
            .attr('cy', y)
            .attr('r', 0)
            .attr('fill', messageConfig.color)
            .attr('data-message-id', message.id)
            .style('opacity', 0.8)
            .on('click', () => this.selectMessage(message))
            .on('mouseover', (event) => this.showMessageTooltip(event, message))
            .on('mouseout', () => this.hideTooltip());

        // Animate bubble appearance
        bubble.transition()
            .duration(300)
            .attr('r', Math.min(8, Math.max(3, message.size / 500)));

        // Add pulse effect for errors
        if (message.type === 'error') {
            bubble.style('filter', 'drop-shadow(0 0 5px #ef4444)');
        }

        // Fade out after time
        setTimeout(() => {
            bubble.transition()
                .duration(500)
                .style('opacity', 0.3);
        }, 5000);
    }

    updateTimeline() {
        // Update time scale
        this.timeScale.domain([new Date(Date.now() - this.timeRange), new Date()]);

        // Re-render axes
        this.renderAxes();

        // Update message positions
        this.messageGroup.selectAll('.message-bubble')
            .transition()
            .duration(1000)
            .attr('cx', d => {
                const messageId = d3.select(this).attr('data-message-id');
                const message = this.messages.find(m => m.id === messageId);
                return message ? this.timeScale(new Date(message.timestamp)) : -100;
            })
            .style('opacity', d => {
                const messageId = d3.select(this).attr('data-message-id');
                const message = this.messages.find(m => m.id === messageId);
                if (!message) return 0;
                const age = Date.now() - message.timestamp;
                return age > this.timeRange * 0.8 ? 0.2 : 0.8;
            });

        // Remove old messages
        this.messageGroup.selectAll('.message-bubble')
            .filter(function() {
                const messageId = d3.select(this).attr('data-message-id');
                return !this.messages.find(m => m.id === messageId);
            })
            .remove();
    }

    selectMessage(message) {
        this.selectedMessage = message;
        this.showMessageDetails(message);

        // Highlight selected message
        this.messageGroup.selectAll('.message-bubble')
            .style('stroke', 'none')
            .style('stroke-width', 0);

        this.messageGroup.selectAll(`[data-message-id="${message.id}"]`)
            .style('stroke', '#fbbf24')
            .style('stroke-width', 3);
    }

    showMessageDetails(message) {
        const server = this.servers.get(message.serverId);
        const detailsContainer = document.getElementById('message-details');

        detailsContainer.innerHTML = `
            <h3>📨 Message Details</h3>

            <div class="detail-section">
                <h4>Basic Information</h4>
                <div class="detail-row">
                    <span class="detail-label">Message ID:</span>
                    <span class="detail-value">${message.id}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Server:</span>
                    <span class="detail-value">${server.name}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Type:</span>
                    <span class="detail-value">${message.type}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Method:</span>
                    <span class="detail-value">${message.method}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Timestamp:</span>
                    <span class="detail-value">${new Date(message.timestamp).toLocaleTimeString()}</span>
                </div>
            </div>

            <div class="detail-section">
                <h4>Performance</h4>
                <div class="detail-row">
                    <span class="detail-label">Size:</span>
                    <span class="detail-value">${this.formatBytes(message.size)}</span>
                </div>
                ${message.responseTime ? `
                    <div class="detail-row">
                        <span class="detail-label">Response Time:</span>
                        <span class="detail-value">${message.responseTime.toFixed(1)}ms</span>
                    </div>
                ` : ''}
                <div class="detail-row">
                    <span class="detail-label">Status:</span>
                    <span class="detail-value" style="color: ${message.status === 'success' ? '#10b981' : '#ef4444'}">
                        ${message.status}
                    </span>
                </div>
            </div>

            <div class="detail-section">
                <h4>Payload</h4>
                <div class="payload-content">${JSON.stringify(message.payload, null, 2)}</div>
            </div>
        `;
    }

    showMessageTooltip(event, message) {
        const tooltip = document.getElementById('tooltip');
        const server = this.servers.get(message.serverId);

        tooltip.innerHTML = `
            <h4>${server.name}</h4>
            <p><strong>Type:</strong> ${message.type}</p>
            <p><strong>Method:</strong> ${message.method}</p>
            <p><strong>Size:</strong> ${this.formatBytes(message.size)}</p>
            <p><strong>Time:</strong> ${new Date(message.timestamp).toLocaleTimeString()}</p>
        `;

        tooltip.style.display = 'block';
        tooltip.style.left = (event.pageX + 10) + 'px';
        tooltip.style.top = (event.pageY - 10) + 'px';
    }

    hideTooltip() {
        document.getElementById('tooltip').style.display = 'none';
    }

    highlightServerMessages(serverId) {
        this.messageGroup.selectAll('.message-bubble')
            .style('opacity', function() {
                const messageId = d3.select(this).attr('data-message-id');
                const message = this.messages.find(m => m.id === messageId);
                return (message && message.serverId === serverId) ? 1 : 0.2;
            }.bind(this));
    }

    updateStats() {
        const activeServers = Array.from(this.servers.values())
            .filter(s => s.status === 'online').length;

        const recentMessages = this.messages.filter(m =>
            Date.now() - m.timestamp < 60000); // Last minute

        const errorMessages = recentMessages.filter(m => m.type === 'error').length;
        const errorRate = recentMessages.length > 0 ?
            (errorMessages / recentMessages.length * 100).toFixed(1) : 0;

        document.getElementById('active-servers').textContent = activeServers;
        document.getElementById('total-messages').textContent = recentMessages.length;
        document.getElementById('error-rate').textContent = errorRate + '%';

        // Update server list
        this.renderServerList();
    }

    getServerIcon(type) {
        const icons = {
            'financial': '💰',
            'search': '🔍',
            'analysis': '📊',
            'execution': '⚡',
            'notification': '🔔',
            'webhook': '🔗'
        };
        return icons[type] || '🔌';
    }

    getRandomMethod(serverType) {
        const methods = {
            'financial': ['getQuote', 'getHistoricalData', 'calculateMetrics', 'getBalance'],
            'search': ['search', 'index', 'query', 'suggest'],
            'analysis': ['analyze', 'generateReport', 'getMetrics', 'compare'],
            'execution': ['execute', 'run', 'eval', 'compile'],
            'notification': ['notify', 'alert', 'message', 'broadcast'],
            'webhook': ['trigger', 'receive', 'process', 'forward']
        };

        const typeMethods = methods[serverType] || ['request', 'process', 'handle'];
        return typeMethods[Math.floor(Math.random() * typeMethods.length)];
    }

    generatePayload(messageType, serverType) {
        const basePayload = {
            jsonrpc: '2.0',
            id: Math.floor(Math.random() * 10000),
            timestamp: Date.now()
        };

        if (messageType === 'request') {
            return {
                ...basePayload,
                method: this.getRandomMethod(serverType),
                params: {
                    query: 'sample query',
                    options: { timeout: 5000 }
                }
            };
        } else if (messageType === 'response') {
            return {
                ...basePayload,
                result: {
                    status: 'success',
                    data: { processed: true, items: Math.floor(Math.random() * 100) }
                }
            };
        } else if (messageType === 'error') {
            return {
                ...basePayload,
                error: {
                    code: -32000,
                    message: 'Internal server error',
                    data: { details: 'Connection timeout' }
                }
            };
        } else {
            return basePayload;
        }
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    setupEventListeners() {
        // Time slider
        document.getElementById('time-slider').addEventListener('input', (e) => {
            const value = parseInt(e.target.value);
            this.timeRange = (value / 100) * 3600000; // Max 1 hour
            this.updateTimeline();
        });

        // Window resize
        window.addEventListener('resize', () => {
            this.width = window.innerWidth - 650;
            this.height = window.innerHeight - 80;
            this.svg.attr('width', this.width).attr('height', this.height);
            this.timeScale.range([50, this.width - 50]);
            this.serverScale.range([50, this.height - 100]);
            this.renderAxes();
            this.renderServerLanes();
        });
    }
}

// Global functions for controls
let mcpTracker;

document.addEventListener('DOMContentLoaded', () => {
    mcpTracker = new MCPTracker();
});

function togglePause() {
    mcpTracker.isPaused = !mcpTracker.isPaused;
    const btn = document.querySelector('.control-btn');
    btn.innerHTML = mcpTracker.isPaused ? '▶️ Resume' : '⏸️ Pause';
}

function showMetrics() {
    const overlay = document.getElementById('metrics-overlay');
    const isVisible = overlay.style.display !== 'none';
    overlay.style.display = isVisible ? 'none' : 'block';

    if (!isVisible) {
        // Calculate and display metrics
        const messages = mcpTracker.messages;
        const responses = messages.filter(m => m.responseTime);
        const avgResponseTime = responses.length > 0 ?
            responses.reduce((sum, m) => sum + m.responseTime, 0) / responses.length : 0;

        const throughput = messages.filter(m =>
            Date.now() - m.timestamp < 60000).length / 60; // per second

        const uptime = Array.from(mcpTracker.servers.values())
            .filter(s => s.status === 'online').length / mcpTracker.servers.size * 100;

        document.getElementById('avg-response-time').textContent = avgResponseTime.toFixed(0);
        document.getElementById('throughput').textContent = throughput.toFixed(1);
        document.getElementById('uptime').textContent = uptime.toFixed(1);
    }
}

function exportData() {
    const data = {
        servers: Array.from(mcpTracker.servers.values()),
        messages: mcpTracker.messages,
        exportTime: new Date().toISOString()
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mcp-communication-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

function clearTimeline() {
    mcpTracker.messages = [];
    mcpTracker.messageGroup.selectAll('*').remove();
    document.getElementById('message-details').innerHTML = `
        <h3>📨 Message Details</h3>
        <div style="opacity: 0.7; text-align: center; margin-top: 2rem;">
            Select a message bubble to view details
        </div>
    `;
}