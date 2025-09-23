// Docker Container Flow Diagram
// Visualizes container interactions and resource flows

class ContainerFlowDiagram {
    constructor() {
        this.width = window.innerWidth;
        this.height = window.innerHeight - 80;
        this.containers = new Map();
        this.networks = new Map();
        this.volumes = new Map();
        this.currentEnvironment = 'local';
        this.autoRefresh = false;
        this.selectedContainer = null;

        this.initializeVisualization();
        this.loadContainerData();
        this.setupEventListeners();
        this.startResourceMonitoring();
    }

    initializeVisualization() {
        // Initialize SVG
        this.svg = d3.select('#flow-diagram')
            .attr('width', this.width)
            .attr('height', this.height);

        // Define markers for arrows
        const defs = this.svg.append('defs');

        // Network arrow
        defs.append('marker')
            .attr('id', 'arrow')
            .attr('viewBox', '0 -5 10 10')
            .attr('refX', 15)
            .attr('refY', 0)
            .attr('markerWidth', 6)
            .attr('markerHeight', 6)
            .attr('orient', 'auto')
            .append('path')
            .attr('d', 'M0,-5L10,0L0,5')
            .attr('fill', '#38bdf8');

        // Gradient for container backgrounds
        const gradient = defs.append('linearGradient')
            .attr('id', 'containerGradient')
            .attr('x1', '0%')
            .attr('y1', '0%')
            .attr('x2', '0%')
            .attr('y2', '100%');

        gradient.append('stop')
            .attr('offset', '0%')
            .attr('stop-color', 'rgba(56, 189, 248, 0.3)')
            .attr('stop-opacity', 1);

        gradient.append('stop')
            .attr('offset', '100%')
            .attr('stop-color', 'rgba(56, 189, 248, 0.1)')
            .attr('stop-opacity', 1);

        // Create main groups
        this.networkGroup = this.svg.append('g').attr('class', 'networks');
        this.volumeGroup = this.svg.append('g').attr('class', 'volumes');
        this.containerGroup = this.svg.append('g').attr('class', 'containers');

        // Setup zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.5, 3])
            .on('zoom', (event) => {
                this.containerGroup.attr('transform', event.transform);
                this.networkGroup.attr('transform', event.transform);
                this.volumeGroup.attr('transform', event.transform);
            });

        this.svg.call(zoom);
    }

    loadContainerData() {
        // Load container data based on environment
        const containerData = this.getContainerDataForEnvironment(this.currentEnvironment);

        this.containers.clear();
        this.networks.clear();
        this.volumes.clear();

        containerData.containers.forEach(container => {
            this.containers.set(container.id, {
                ...container,
                x: Math.random() * (this.width - 200) + 100,
                y: Math.random() * (this.height - 200) + 100
            });
        });

        containerData.networks.forEach(network => {
            this.networks.set(network.name, network);
        });

        containerData.volumes.forEach(volume => {
            this.volumes.set(volume.name, volume);
        });

        this.updateVisualization();
    }

    getContainerDataForEnvironment(env) {
        const environments = {
            local: {
                containers: [
                    {
                        id: 'catalytic-postgres',
                        name: 'PostgreSQL',
                        image: 'postgres:15-alpine',
                        status: 'running',
                        ports: ['5432:5432'],
                        networks: ['catalytic-network'],
                        volumes: ['postgres_data:/var/lib/postgresql/data'],
                        cpu: 15.2,
                        memory: 45.8,
                        type: 'database',
                        health: 'healthy'
                    },
                    {
                        id: 'catalytic-redis',
                        name: 'Redis Cache',
                        image: 'redis:7-alpine',
                        status: 'running',
                        ports: ['6380:6379'],
                        networks: ['catalytic-network'],
                        volumes: ['redis_data:/data'],
                        cpu: 8.5,
                        memory: 23.1,
                        type: 'cache',
                        health: 'healthy'
                    },
                    {
                        id: 'catalytic-api',
                        name: 'API Gateway',
                        image: 'catalytic/api-gateway:latest',
                        status: 'running',
                        ports: ['3000:3000'],
                        networks: ['catalytic-network'],
                        volumes: [],
                        cpu: 22.7,
                        memory: 38.9,
                        type: 'api',
                        health: 'healthy'
                    },
                    {
                        id: 'catalytic-saas',
                        name: 'SaaS API',
                        image: 'catalytic/saas-api:latest',
                        status: 'running',
                        ports: ['4000:4000'],
                        networks: ['catalytic-network'],
                        volumes: [],
                        cpu: 18.3,
                        memory: 42.1,
                        type: 'api',
                        health: 'healthy'
                    },
                    {
                        id: 'catalytic-nginx',
                        name: 'Nginx Proxy',
                        image: 'nginx:alpine',
                        status: 'running',
                        ports: ['80:80', '443:443'],
                        networks: ['catalytic-network'],
                        volumes: ['nginx_config:/etc/nginx'],
                        cpu: 5.2,
                        memory: 12.4,
                        type: 'proxy',
                        health: 'healthy'
                    },
                    {
                        id: 'catalytic-monitor',
                        name: 'Monitoring',
                        image: 'catalytic/monitoring:latest',
                        status: 'running',
                        ports: ['9090:9090'],
                        networks: ['catalytic-network'],
                        volumes: [],
                        cpu: 12.8,
                        memory: 28.7,
                        type: 'monitoring',
                        health: 'healthy'
                    },
                    {
                        id: 'ka-lattice',
                        name: 'KA Lattice',
                        image: 'catalytic/ka-lattice:latest',
                        status: 'running',
                        ports: ['7000:7000'],
                        networks: ['catalytic-network'],
                        volumes: ['lattice_data:/data'],
                        cpu: 45.6,
                        memory: 78.2,
                        type: 'compute',
                        health: 'healthy'
                    }
                ],
                networks: [
                    {
                        name: 'catalytic-network',
                        driver: 'bridge',
                        containers: ['catalytic-postgres', 'catalytic-redis', 'catalytic-api', 'catalytic-saas', 'catalytic-nginx', 'catalytic-monitor', 'ka-lattice']
                    }
                ],
                volumes: [
                    { name: 'postgres_data', driver: 'local', size: '2.3GB' },
                    { name: 'redis_data', driver: 'local', size: '45MB' },
                    { name: 'nginx_config', driver: 'local', size: '12MB' },
                    { name: 'lattice_data', driver: 'local', size: '1.8GB' }
                ]
            },
            staging: {
                containers: [
                    // Staging containers would be defined here
                ],
                networks: [],
                volumes: []
            },
            production: {
                containers: [
                    // Production containers would be defined here
                ],
                networks: [],
                volumes: []
            }
        };

        return environments[env] || environments.local;
    }

    updateVisualization() {
        this.renderContainers();
        this.renderNetworks();
        this.renderVolumes();
        this.positionContainers();
    }

    renderContainers() {
        const containers = Array.from(this.containers.values());

        const containerNodes = this.containerGroup.selectAll('.container-node')
            .data(containers, d => d.id);

        containerNodes.exit().remove();

        const containerEnter = containerNodes.enter()
            .append('g')
            .attr('class', 'container-node')
            .on('click', (event, d) => this.selectContainer(d))
            .on('mouseover', (event, d) => this.showTooltip(event, d))
            .on('mouseout', () => this.hideTooltip())
            .call(d3.drag()
                .on('start', this.dragStarted.bind(this))
                .on('drag', this.dragged.bind(this))
                .on('end', this.dragEnded.bind(this)));

        // Container body
        containerEnter.append('rect')
            .attr('class', 'container-body')
            .attr('width', 160)
            .attr('height', 120)
            .attr('fill', 'url(#containerGradient)');

        // Container header
        containerEnter.append('rect')
            .attr('class', 'container-header')
            .attr('width', 160)
            .attr('height', 30);

        // Container icon
        containerEnter.append('text')
            .attr('class', 'container-icon')
            .attr('x', 15)
            .attr('y', 20)
            .attr('font-size', '16px')
            .text(d => this.getContainerIcon(d.type));

        // Container name
        containerEnter.append('text')
            .attr('class', 'container-name')
            .attr('x', 80)
            .attr('y', 20);

        // Status indicator
        containerEnter.append('circle')
            .attr('class', 'status-circle')
            .attr('cx', 145)
            .attr('cy', 15)
            .attr('r', 5);

        // CPU usage bar
        containerEnter.append('rect')
            .attr('class', 'cpu-bg')
            .attr('x', 10)
            .attr('y', 45)
            .attr('width', 140)
            .attr('height', 6)
            .attr('fill', 'rgba(255,255,255,0.1)')
            .attr('rx', 3);

        containerEnter.append('rect')
            .attr('class', 'cpu-bar')
            .attr('x', 10)
            .attr('y', 45)
            .attr('height', 6)
            .attr('fill', '#fbbf24')
            .attr('rx', 3);

        // Memory usage bar
        containerEnter.append('rect')
            .attr('class', 'memory-bg')
            .attr('x', 10)
            .attr('y', 58)
            .attr('width', 140)
            .attr('height', 6)
            .attr('fill', 'rgba(255,255,255,0.1)')
            .attr('rx', 3);

        containerEnter.append('rect')
            .attr('class', 'memory-bar')
            .attr('x', 10)
            .attr('y', 58)
            .attr('height', 6)
            .attr('fill', '#10b981')
            .attr('rx', 3);

        // Labels
        containerEnter.append('text')
            .attr('class', 'cpu-label')
            .attr('x', 10)
            .attr('y', 42)
            .attr('font-size', '10px')
            .attr('fill', '#94a3b8')
            .text('CPU');

        containerEnter.append('text')
            .attr('class', 'memory-label')
            .attr('x', 10)
            .attr('y', 78)
            .attr('font-size', '10px')
            .attr('fill', '#94a3b8')
            .text('Memory');

        // Ports info
        containerEnter.append('text')
            .attr('class', 'ports-info')
            .attr('x', 10)
            .attr('y', 95)
            .attr('font-size', '10px')
            .attr('fill', '#94a3b8');

        // Update all containers
        const allContainers = containerNodes.merge(containerEnter);

        allContainers.select('.container-name')
            .text(d => d.name);

        allContainers.select('.status-circle')
            .attr('fill', d => d.status === 'running' ? '#10b981' :
                            d.status === 'stopped' ? '#ef4444' : '#f59e0b');

        allContainers.select('.cpu-bar')
            .attr('width', d => (d.cpu / 100) * 140);

        allContainers.select('.memory-bar')
            .attr('width', d => (d.memory / 100) * 140);

        allContainers.select('.ports-info')
            .text(d => d.ports.length > 0 ? `Ports: ${d.ports[0]}` : 'No exposed ports');

        allContainers.select('.cpu-label')
            .text(d => `CPU: ${d.cpu}%`);

        allContainers.select('.memory-label')
            .text(d => `Memory: ${d.memory}%`);
    }

    renderNetworks() {
        // Clear existing network connections
        this.networkGroup.selectAll('*').remove();

        // Draw network connections between containers
        this.networks.forEach(network => {
            const connectedContainers = network.containers
                .map(id => this.containers.get(id))
                .filter(container => container);

            for (let i = 0; i < connectedContainers.length; i++) {
                for (let j = i + 1; j < connectedContainers.length; j++) {
                    this.drawNetworkConnection(connectedContainers[i], connectedContainers[j], network);
                }
            }
        });
    }

    drawNetworkConnection(source, target, network) {
        const line = this.networkGroup.append('line')
            .attr('class', 'network-link')
            .attr('x1', source.x + 80)
            .attr('y1', source.y + 60)
            .attr('x2', target.x + 80)
            .attr('y2', target.y + 60)
            .attr('data-network', network.name);

        // Add network label
        const midX = (source.x + target.x) / 2 + 80;
        const midY = (source.y + target.y) / 2 + 60;

        this.networkGroup.append('text')
            .attr('class', 'network-label')
            .attr('x', midX)
            .attr('y', midY - 5)
            .text(network.name);
    }

    renderVolumes() {
        // Clear existing volume connections
        this.volumeGroup.selectAll('*').remove();

        // Draw volume mount connections
        this.containers.forEach(container => {
            container.volumes.forEach(volumeMount => {
                const volumeName = volumeMount.split(':')[0];
                this.drawVolumeConnection(container, volumeName);
            });
        });
    }

    drawVolumeConnection(container, volumeName) {
        // Draw a connection to represent volume mount
        this.volumeGroup.append('line')
            .attr('class', 'volume-mount')
            .attr('x1', container.x + 160)
            .attr('y1', container.y + 60)
            .attr('x2', container.x + 200)
            .attr('y2', container.y + 60);

        this.volumeGroup.append('text')
            .attr('class', 'volume-label')
            .attr('x', container.x + 205)
            .attr('y', container.y + 64)
            .attr('font-size', '8px')
            .attr('fill', '#10b981')
            .text(volumeName);
    }

    positionContainers() {
        // Apply force-directed layout for better positioning
        const containers = Array.from(this.containers.values());

        const simulation = d3.forceSimulation(containers)
            .force('charge', d3.forceManyBody().strength(-1000))
            .force('center', d3.forceCenter(this.width / 2, this.height / 2))
            .force('collision', d3.forceCollide().radius(100))
            .on('tick', () => {
                this.containerGroup.selectAll('.container-node')
                    .attr('transform', d => `translate(${d.x},${d.y})`);

                this.renderNetworks();
                this.renderVolumes();
            });

        simulation.alpha(0.3).restart();
    }

    getContainerIcon(type) {
        const icons = {
            'database': '🗄️',
            'cache': '⚡',
            'api': '🌐',
            'proxy': '🔀',
            'monitoring': '📊',
            'compute': '🧬'
        };
        return icons[type] || '📦';
    }

    selectContainer(container) {
        this.selectedContainer = container;
        this.showContainerDetails(container);
    }

    showContainerDetails(container) {
        const sidebar = document.getElementById('sidebar');
        const content = document.getElementById('sidebar-content');

        content.innerHTML = `
            <div class="info-section">
                <h4>Container Info</h4>
                <div class="info-row">
                    <span class="info-label">Name:</span>
                    <span class="info-value">${container.name}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Image:</span>
                    <span class="info-value">${container.image}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Status:</span>
                    <span class="info-value">
                        <span class="status-indicator status-${container.status}"></span>
                        ${container.status}
                    </span>
                </div>
                <div class="info-row">
                    <span class="info-label">Health:</span>
                    <span class="info-value">${container.health}</span>
                </div>
            </div>

            <div class="info-section">
                <h4>Resource Usage</h4>
                <div class="info-row">
                    <span class="info-label">CPU:</span>
                    <span class="info-value">${container.cpu}%</span>
                </div>
                <div class="resource-bar">
                    <div class="resource-fill" style="width: ${container.cpu}%"></div>
                </div>
                <div class="info-row">
                    <span class="info-label">Memory:</span>
                    <span class="info-value">${container.memory}%</span>
                </div>
                <div class="resource-bar">
                    <div class="resource-fill" style="width: ${container.memory}%"></div>
                </div>
            </div>

            <div class="info-section">
                <h4>Network</h4>
                ${container.networks.map(network => `
                    <div class="info-row">
                        <span class="info-label">Network:</span>
                        <span class="info-value">${network}</span>
                    </div>
                `).join('')}
                ${container.ports.map(port => `
                    <div class="info-row">
                        <span class="info-label">Port:</span>
                        <span class="info-value">${port}</span>
                    </div>
                `).join('')}
            </div>

            <div class="info-section">
                <h4>Volumes</h4>
                ${container.volumes.length > 0 ?
                    container.volumes.map(volume => `
                        <div class="info-row">
                            <span class="info-label">Mount:</span>
                            <span class="info-value">${volume}</span>
                        </div>
                    `).join('') :
                    '<div class="info-row"><span style="opacity: 0.7;">No volumes mounted</span></div>'
                }
            </div>
        `;

        sidebar.classList.add('open');
    }

    showTooltip(event, container) {
        const tooltip = document.getElementById('tooltip');
        tooltip.innerHTML = `
            <h4>${container.name}</h4>
            <p><strong>Status:</strong> ${container.status}</p>
            <p><strong>CPU:</strong> ${container.cpu}%</p>
            <p><strong>Memory:</strong> ${container.memory}%</p>
            <p><strong>Type:</strong> ${container.type}</p>
        `;

        tooltip.style.display = 'block';
        tooltip.style.left = (event.pageX + 10) + 'px';
        tooltip.style.top = (event.pageY - 10) + 'px';
    }

    hideTooltip() {
        document.getElementById('tooltip').style.display = 'none';
    }

    dragStarted(event, d) {
        d3.select(event.sourceEvent.target.parentNode).raise();
    }

    dragged(event, d) {
        d.x = event.x;
        d.y = event.y;
        d3.select(event.sourceEvent.target.parentNode)
            .attr('transform', `translate(${d.x},${d.y})`);

        this.renderNetworks();
        this.renderVolumes();
    }

    dragEnded(event, d) {
        // Container position updated
    }

    setupEventListeners() {
        // Environment selector
        document.querySelectorAll('.env-button').forEach(button => {
            button.addEventListener('click', (e) => {
                document.querySelectorAll('.env-button').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                this.currentEnvironment = e.target.dataset.env;
                this.loadContainerData();
            });
        });
    }

    startResourceMonitoring() {
        // Simulate real-time resource updates
        setInterval(() => {
            this.containers.forEach(container => {
                // Simulate CPU and memory fluctuations
                container.cpu = Math.max(0, Math.min(100, container.cpu + (Math.random() - 0.5) * 10));
                container.memory = Math.max(0, Math.min(100, container.memory + (Math.random() - 0.5) * 5));
            });

            this.renderContainers();

            // Update sidebar if container is selected
            if (this.selectedContainer) {
                this.showContainerDetails(this.selectedContainer);
            }
        }, 2000);
    }
}

// Global functions for controls
let containerFlow;

document.addEventListener('DOMContentLoaded', () => {
    containerFlow = new ContainerFlowDiagram();
});

function refreshContainers() {
    containerFlow.loadContainerData();
}

function toggleAutoRefresh() {
    containerFlow.autoRefresh = !containerFlow.autoRefresh;
    // Implementation for auto-refresh toggle
}

function showNetworkView() {
    // Toggle network visibility
    const networks = containerFlow.networkGroup.selectAll('.network-link');
    const visible = networks.style('opacity') !== '0';
    networks.style('opacity', visible ? 0 : 0.6);
}

function showVolumeView() {
    // Toggle volume visibility
    const volumes = containerFlow.volumeGroup.selectAll('.volume-mount');
    const visible = volumes.style('opacity') !== '0';
    volumes.style('opacity', visible ? 0 : 0.7);
}

function closeSidebar() {
    document.getElementById('sidebar').classList.remove('open');
}

// Handle window resize
window.addEventListener('resize', () => {
    if (containerFlow) {
        containerFlow.width = window.innerWidth;
        containerFlow.height = window.innerHeight - 80;
        containerFlow.svg.attr('width', containerFlow.width).attr('height', containerFlow.height);
        containerFlow.positionContainers();
    }
});