// Service Dependency Map Visualization
// Real-time tracking of service interactions

class ServiceMap {
    constructor() {
        this.width = window.innerWidth;
        this.height = window.innerHeight - 80;
        this.services = new Map();
        this.connections = [];
        this.animationRunning = true;
        this.layoutType = 'hierarchical';

        this.serviceTypes = {
            'api-gateway': { color: '#4fc3f7', icon: '🌐', priority: 1 },
            'mcp-server': { color: '#66bb6a', icon: '🔌', priority: 2 },
            'database': { color: '#ff7043', icon: '💾', priority: 3 },
            'cache': { color: '#ab47bc', icon: '⚡', priority: 3 },
            'webhook': { color: '#ffd54f', icon: '🔔', priority: 2 },
            'monitoring': { color: '#26c6da', icon: '📊', priority: 4 },
            'catalytic': { color: '#81c784', icon: '🧬', priority: 1 },
            'saas': { color: '#64b5f6', icon: '☁️', priority: 1 }
        };

        this.initializeSVG();
        this.loadServiceData();
        this.startWebSocket();
        this.startAnimation();
    }

    initializeSVG() {
        this.svg = d3.select('#service-map')
            .attr('width', this.width)
            .attr('height', this.height);

        // Define gradients
        const defs = this.svg.append('defs');

        // Connection gradient
        const gradient = defs.append('linearGradient')
            .attr('id', 'connection-gradient')
            .attr('gradientUnits', 'userSpaceOnUse');

        gradient.append('stop')
            .attr('offset', '0%')
            .attr('stop-color', '#4fc3f7')
            .attr('stop-opacity', 0.6);

        gradient.append('stop')
            .attr('offset', '100%')
            .attr('stop-color', '#66bb6a')
            .attr('stop-opacity', 0.6);

        // Glow filter
        const filter = defs.append('filter')
            .attr('id', 'glow');

        filter.append('feGaussianBlur')
            .attr('stdDeviation', '3')
            .attr('result', 'coloredBlur');

        const feMerge = filter.append('feMerge');
        feMerge.append('feMergeNode')
            .attr('in', 'coloredBlur');
        feMerge.append('feMergeNode')
            .attr('in', 'SourceGraphic');

        // Arrow marker
        defs.append('marker')
            .attr('id', 'arrow')
            .attr('viewBox', '0 -5 10 10')
            .attr('refX', 25)
            .attr('refY', 0)
            .attr('markerWidth', 6)
            .attr('markerHeight', 6)
            .attr('orient', 'auto')
            .append('path')
            .attr('d', 'M0,-5L10,0L0,5')
            .attr('class', 'link-arrow');

        // Create main groups
        this.linkGroup = this.svg.append('g').attr('class', 'links');
        this.nodeGroup = this.svg.append('g').attr('class', 'nodes');

        // Setup zoom
        const zoom = d3.zoom()
            .scaleExtent([0.5, 3])
            .on('zoom', (event) => {
                this.linkGroup.attr('transform', event.transform);
                this.nodeGroup.attr('transform', event.transform);
            });

        this.svg.call(zoom);
    }

    loadServiceData() {
        // Initialize with discovered services
        const services = [
            { id: 'api-gateway', name: 'API Gateway', type: 'api-gateway', status: 'healthy', port: 3000 },
            { id: 'postgres', name: 'PostgreSQL', type: 'database', status: 'healthy', port: 5432 },
            { id: 'redis', name: 'Redis Cache', type: 'cache', status: 'healthy', port: 6380 },
            { id: 'mcp-financial', name: 'Financial MCP', type: 'mcp-server', status: 'healthy', port: 8001 },
            { id: 'mcp-prims', name: 'PRIMS MCP', type: 'mcp-server', status: 'healthy', port: 8002 },
            { id: 'mcp-repo-mapper', name: 'RepoMapper MCP', type: 'mcp-server', status: 'healthy', port: 8003 },
            { id: 'mcp-js-executor', name: 'JS Executor MCP', type: 'mcp-server', status: 'healthy', port: 8004 },
            { id: 'webhook-server', name: 'Webhook Server', type: 'webhook', status: 'healthy', port: 8080 },
            { id: 'webhook-audio', name: 'Audio Tracker', type: 'webhook', status: 'healthy', port: 8081 },
            { id: 'monitoring', name: 'Monitoring', type: 'monitoring', status: 'healthy', port: 9090 },
            { id: 'ka-lattice', name: 'KA Lattice', type: 'catalytic', status: 'healthy', port: 7000 },
            { id: 'saas-api', name: 'SaaS API', type: 'saas', status: 'healthy', port: 4000 },
            { id: 'nginx', name: 'Nginx Proxy', type: 'api-gateway', status: 'healthy', port: 80 }
        ];

        services.forEach(service => {
            this.services.set(service.id, {
                ...service,
                x: Math.random() * this.width,
                y: Math.random() * this.height,
                connections: 0,
                dataFlow: 0
            });
        });

        // Define connections
        this.connections = [
            { source: 'nginx', target: 'api-gateway', strength: 1.0, active: true },
            { source: 'api-gateway', target: 'postgres', strength: 0.8, active: true },
            { source: 'api-gateway', target: 'redis', strength: 0.9, active: true },
            { source: 'api-gateway', target: 'saas-api', strength: 0.7, active: true },
            { source: 'saas-api', target: 'postgres', strength: 0.8, active: true },
            { source: 'saas-api', target: 'redis', strength: 0.7, active: true },
            { source: 'mcp-financial', target: 'api-gateway', strength: 0.6, active: false },
            { source: 'mcp-prims', target: 'api-gateway', strength: 0.5, active: false },
            { source: 'mcp-repo-mapper', target: 'api-gateway', strength: 0.5, active: false },
            { source: 'mcp-js-executor', target: 'api-gateway', strength: 0.6, active: true },
            { source: 'webhook-server', target: 'api-gateway', strength: 0.7, active: true },
            { source: 'webhook-audio', target: 'webhook-server', strength: 0.8, active: true },
            { source: 'ka-lattice', target: 'api-gateway', strength: 0.9, active: true },
            { source: 'ka-lattice', target: 'redis', strength: 0.6, active: false },
            { source: 'monitoring', target: 'api-gateway', strength: 0.4, active: true },
            { source: 'monitoring', target: 'postgres', strength: 0.3, active: false },
            { source: 'monitoring', target: 'redis', strength: 0.3, active: false },
            { source: 'monitoring', target: 'ka-lattice', strength: 0.5, active: true }
        ];

        this.updateVisualization();
        this.updateStats();
    }

    updateVisualization() {
        // Update links
        const links = this.linkGroup.selectAll('.link')
            .data(this.connections, d => `${d.source}-${d.target}`);

        links.exit().remove();

        const linksEnter = links.enter()
            .append('path')
            .attr('class', 'link')
            .attr('marker-end', 'url(#arrow)');

        links.merge(linksEnter)
            .attr('stroke', d => d.active ? 'url(#connection-gradient)' : '#555')
            .attr('stroke-width', d => Math.max(1, d.strength * 4))
            .classed('active', d => d.active);

        // Update nodes
        const nodes = this.nodeGroup.selectAll('.node-group')
            .data(Array.from(this.services.values()), d => d.id);

        nodes.exit().remove();

        const nodesEnter = nodes.enter()
            .append('g')
            .attr('class', 'node-group')
            .call(d3.drag()
                .on('start', this.dragStarted.bind(this))
                .on('drag', this.dragged.bind(this))
                .on('end', this.dragEnded.bind(this)));

        // Add circles
        nodesEnter.append('circle')
            .attr('class', 'node')
            .attr('r', 25)
            .on('mouseover', this.showTooltip.bind(this))
            .on('mouseout', this.hideTooltip.bind(this));

        // Add icons
        nodesEnter.append('text')
            .attr('class', 'node-icon')
            .attr('text-anchor', 'middle')
            .attr('dy', '0.3em')
            .style('font-size', '20px')
            .style('pointer-events', 'none');

        // Add labels
        nodesEnter.append('text')
            .attr('class', 'node-label')
            .attr('dy', '40');

        // Update all nodes
        const allNodes = nodes.merge(nodesEnter);

        allNodes.select('.node')
            .attr('fill', d => this.serviceTypes[d.type]?.color || '#999')
            .attr('filter', d => d.status === 'healthy' ? 'url(#glow)' : 'none')
            .attr('opacity', d => d.status === 'healthy' ? 1 : 0.5);

        allNodes.select('.node-icon')
            .text(d => this.serviceTypes[d.type]?.icon || '📦');

        allNodes.select('.node-label')
            .text(d => d.name);

        if (this.layoutType === 'hierarchical') {
            this.applyHierarchicalLayout();
        } else {
            this.applyForceLayout();
        }
    }

    applyHierarchicalLayout() {
        const levels = new Map();

        // Assign levels based on service type priority
        this.services.forEach(service => {
            const priority = this.serviceTypes[service.type]?.priority || 5;
            if (!levels.has(priority)) {
                levels.set(priority, []);
            }
            levels.get(priority).push(service);
        });

        // Position nodes
        const levelHeight = this.height / (levels.size + 1);
        let currentY = levelHeight;

        levels.forEach((services, level) => {
            const levelWidth = this.width / (services.length + 1);
            services.forEach((service, index) => {
                service.x = levelWidth * (index + 1);
                service.y = currentY;
            });
            currentY += levelHeight;
        });

        this.updatePositions();
    }

    applyForceLayout() {
        const simulation = d3.forceSimulation(Array.from(this.services.values()))
            .force('link', d3.forceLink(this.connections)
                .id(d => d.id)
                .distance(100)
                .strength(d => d.strength))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(this.width / 2, this.height / 2))
            .force('collision', d3.forceCollide().radius(40));

        simulation.on('tick', () => {
            this.updatePositions();
        });

        simulation.alpha(1).restart();
    }

    updatePositions() {
        // Update node positions
        this.nodeGroup.selectAll('.node-group')
            .attr('transform', d => `translate(${d.x},${d.y})`);

        // Update link paths
        this.linkGroup.selectAll('.link')
            .attr('d', d => {
                const source = this.services.get(d.source);
                const target = this.services.get(d.target);
                if (!source || !target) return '';

                const dx = target.x - source.x;
                const dy = target.y - source.y;
                const dr = Math.sqrt(dx * dx + dy * dy) * 2;

                return `M${source.x},${source.y}A${dr},${dr} 0 0,1 ${target.x},${target.y}`;
            });
    }

    dragStarted(event, d) {
        d3.select(event.sourceEvent.target).style('cursor', 'grabbing');
    }

    dragged(event, d) {
        d.x = event.x;
        d.y = event.y;
        this.updatePositions();
    }

    dragEnded(event, d) {
        d3.select(event.sourceEvent.target).style('cursor', 'pointer');
    }

    showTooltip(event, d) {
        const tooltip = document.getElementById('tooltip');
        tooltip.style.display = 'block';
        tooltip.style.left = (event.pageX + 10) + 'px';
        tooltip.style.top = (event.pageY - 10) + 'px';

        const activeConnections = this.connections.filter(c =>
            (c.source === d.id || c.target === d.id) && c.active
        ).length;

        tooltip.innerHTML = `
            <h3>${d.name}</h3>
            <div class="info">
                <span class="label">Type:</span>
                <span>${d.type}</span>
                <span class="label">Status:</span>
                <span style="color: ${d.status === 'healthy' ? '#66bb6a' : '#ff7043'}">${d.status}</span>
                <span class="label">Port:</span>
                <span>${d.port}</span>
                <span class="label">Connections:</span>
                <span>${activeConnections}</span>
                <span class="label">Data Flow:</span>
                <span>${(d.dataFlow * 100).toFixed(1)}%</span>
            </div>
        `;
    }

    hideTooltip() {
        document.getElementById('tooltip').style.display = 'none';
    }

    startWebSocket() {
        // Simulate WebSocket connection for real-time updates
        setInterval(() => {
            // Randomly update service status
            const serviceArray = Array.from(this.services.values());
            const randomService = serviceArray[Math.floor(Math.random() * serviceArray.length)];
            randomService.dataFlow = Math.random();

            // Randomly toggle connection activity
            if (Math.random() > 0.7) {
                const randomConnection = this.connections[Math.floor(Math.random() * this.connections.length)];
                randomConnection.active = !randomConnection.active;
            }

            this.updateVisualization();
        }, 3000);
    }

    startAnimation() {
        const animate = () => {
            if (!this.animationRunning) return;

            // Animate data flow
            this.linkGroup.selectAll('.link.active')
                .attr('stroke-dasharray', '10 5')
                .attr('stroke-dashoffset', function() {
                    const currentOffset = parseFloat(d3.select(this).attr('stroke-dashoffset') || 0);
                    return currentOffset - 1;
                });

            requestAnimationFrame(animate);
        };

        animate();
    }

    updateStats() {
        document.getElementById('service-count').textContent = this.services.size;
        document.getElementById('connection-count').textContent =
            this.connections.filter(c => c.active).length;

        const healthyServices = Array.from(this.services.values())
            .filter(s => s.status === 'healthy').length;
        const healthScore = (healthyServices / this.services.size * 100).toFixed(0);
        document.getElementById('health-score').textContent = healthScore + '%';
    }
}

// Global functions for controls
let serviceMap;

window.addEventListener('DOMContentLoaded', () => {
    serviceMap = new ServiceMap();
});

window.addEventListener('resize', () => {
    if (serviceMap) {
        serviceMap.width = window.innerWidth;
        serviceMap.height = window.innerHeight - 80;
        serviceMap.svg.attr('width', serviceMap.width).attr('height', serviceMap.height);
        serviceMap.updatePositions();
    }
});

function toggleAnimation() {
    serviceMap.animationRunning = !serviceMap.animationRunning;
    document.getElementById('animate-btn').textContent =
        serviceMap.animationRunning ? 'Pause Animation' : 'Resume Animation';
    if (serviceMap.animationRunning) {
        serviceMap.startAnimation();
    }
}

function resetView() {
    serviceMap.svg.transition()
        .duration(750)
        .call(d3.zoom().transform, d3.zoomIdentity);
}

function toggleLayout() {
    serviceMap.layoutType = serviceMap.layoutType === 'hierarchical' ? 'force' : 'hierarchical';
    document.getElementById('layout-btn').textContent =
        serviceMap.layoutType === 'hierarchical' ? 'Force Layout' : 'Hierarchical Layout';
    serviceMap.updateVisualization();
}