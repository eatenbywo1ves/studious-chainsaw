// File System Activity Heatmap Visualization
// Tracks and visualizes file system interactions

class FileSystemHeatmap {
    constructor() {
        this.width = window.innerWidth - 270;
        this.height = window.innerHeight - 100;
        this.cellSize = 40;
        this.fileActivity = new Map();
        this.directoryStructure = this.buildDirectoryStructure();
        this.currentDirectory = '/';
        this.timeRange = '24h';
        this.activityType = 'all';

        this.colorScale = d3.scaleSequential()
            .domain([0, 100])
            .interpolator(d3.interpolateInferno);

        this.initializeVisualization();
        this.loadActivityData();
        this.setupEventListeners();
        this.startActivityMonitor();
    }

    buildDirectoryStructure() {
        return {
            '/': {
                name: 'development',
                type: 'directory',
                children: {
                    'apps': {
                        name: 'apps',
                        type: 'directory',
                        children: {
                            'api-gateway': { name: 'api-gateway', type: 'directory', activity: 0 },
                            'catalytic': { name: 'catalytic', type: 'directory', activity: 0 }
                        }
                    },
                    'services': {
                        name: 'services',
                        type: 'directory',
                        children: {
                            'mcp': { name: 'mcp', type: 'directory', activity: 0 },
                            'webhooks': { name: 'webhooks', type: 'directory', activity: 0 }
                        }
                    },
                    'monitoring': {
                        name: 'monitoring',
                        type: 'directory',
                        children: {
                            'visual-aids': { name: 'visual-aids', type: 'directory', activity: 0 },
                            'grafana-dashboards.json': { name: 'grafana-dashboards.json', type: 'file', activity: 0 },
                            'prometheus.yml': { name: 'prometheus.yml', type: 'file', activity: 0 }
                        }
                    },
                    'libs': {
                        name: 'libs',
                        type: 'directory',
                        children: {
                            'config': { name: 'config', type: 'directory', activity: 0 },
                            'core': { name: 'core', type: 'directory', activity: 0 },
                            'utils': { name: 'utils', type: 'directory', activity: 0 }
                        }
                    },
                    'tests': {
                        name: 'tests',
                        type: 'directory',
                        children: {
                            'unit': { name: 'unit', type: 'directory', activity: 0 },
                            'integration': { name: 'integration', type: 'directory', activity: 0 }
                        }
                    },
                    'docker-compose.yml': { name: 'docker-compose.yml', type: 'file', activity: 0 },
                    'package.json': { name: 'package.json', type: 'file', activity: 0 },
                    '.env': { name: '.env', type: 'file', activity: 0 },
                    'README.md': { name: 'README.md', type: 'file', activity: 0 }
                }
            }
        };
    }

    initializeVisualization() {
        // Initialize SVG
        this.svg = d3.select('#heatmap')
            .attr('width', this.width)
            .attr('height', this.height);

        // Create main group for heatmap
        this.heatmapGroup = this.svg.append('g')
            .attr('class', 'heatmap-group');

        // Render directory tree
        this.renderDirectoryTree();

        // Setup zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.5, 5])
            .on('zoom', (event) => {
                this.heatmapGroup.attr('transform', event.transform);
            });

        this.svg.call(zoom);
    }

    renderDirectoryTree() {
        const treeContainer = document.getElementById('tree-content');
        treeContainer.innerHTML = '';

        const renderNode = (node, level = 0) => {
            const item = document.createElement('div');
            item.className = 'tree-item';
            item.style.paddingLeft = `${level * 20}px`;

            const icon = document.createElement('span');
            icon.className = 'tree-icon';
            icon.textContent = node.type === 'directory' ? '📁' : '📄';

            const name = document.createElement('span');
            name.textContent = node.name;

            item.appendChild(icon);
            item.appendChild(name);

            item.addEventListener('click', () => {
                document.querySelectorAll('.tree-item').forEach(el =>
                    el.classList.remove('selected'));
                item.classList.add('selected');

                if (node.type === 'directory') {
                    this.currentDirectory = node.name;
                    this.updateHeatmap();
                }
            });

            treeContainer.appendChild(item);

            if (node.children) {
                Object.values(node.children).forEach(child => {
                    renderNode(child, level + 1);
                });
            }
        };

        renderNode(this.directoryStructure['/']);
    }

    loadActivityData() {
        // Generate simulated activity data
        const generateActivity = () => {
            const activities = [];
            const now = Date.now();
            const filePatterns = [
                { path: '/apps/api-gateway/server.js', weight: 0.8 },
                { path: '/services/mcp/base-server.js', weight: 0.7 },
                { path: '/monitoring/dashboard.js', weight: 0.9 },
                { path: '/docker-compose.yml', weight: 0.6 },
                { path: '/.env', weight: 0.5 },
                { path: '/libs/config/index.js', weight: 0.4 },
                { path: '/tests/unit/api.test.js', weight: 0.3 },
                { path: '/package.json', weight: 0.7 },
                { path: '/services/webhooks/server.py', weight: 0.6 }
            ];

            filePatterns.forEach(pattern => {
                const activityCount = Math.floor(Math.random() * 100 * pattern.weight);
                for (let i = 0; i < activityCount; i++) {
                    activities.push({
                        path: pattern.path,
                        type: ['read', 'write', 'modify'][Math.floor(Math.random() * 3)],
                        timestamp: now - Math.random() * 86400000, // Random time within 24h
                        size: Math.floor(Math.random() * 10000),
                        user: ['system', 'user', 'service'][Math.floor(Math.random() * 3)]
                    });
                }
            });

            return activities;
        };

        this.activities = generateActivity();
        this.processActivityData();
        this.updateHeatmap();
    }

    processActivityData() {
        this.fileActivity.clear();

        // Filter activities based on time range and type
        const now = Date.now();
        const timeRanges = {
            '1h': 3600000,
            '6h': 21600000,
            '24h': 86400000,
            '7d': 604800000,
            '30d': 2592000000
        };

        const cutoff = now - timeRanges[this.timeRange];

        this.activities
            .filter(activity => {
                if (activity.timestamp < cutoff) return false;
                if (this.activityType !== 'all' && activity.type !== this.activityType) return false;
                return true;
            })
            .forEach(activity => {
                const key = activity.path;
                if (!this.fileActivity.has(key)) {
                    this.fileActivity.set(key, {
                        reads: 0,
                        writes: 0,
                        modifications: 0,
                        lastAccess: 0,
                        totalSize: 0
                    });
                }

                const stats = this.fileActivity.get(key);
                if (activity.type === 'read') stats.reads++;
                else if (activity.type === 'write') stats.writes++;
                else if (activity.type === 'modify') stats.modifications++;

                stats.lastAccess = Math.max(stats.lastAccess, activity.timestamp);
                stats.totalSize += activity.size;
            });

        this.updateStats();
    }

    updateHeatmap() {
        // Clear existing heatmap
        this.heatmapGroup.selectAll('*').remove();

        // Get files for current directory
        const files = this.getFilesForDirectory(this.currentDirectory);

        // Calculate grid dimensions
        const cols = Math.floor(this.width / (this.cellSize + 5));
        const rows = Math.ceil(files.length / cols);

        // Create cells
        const cells = this.heatmapGroup.selectAll('.cell-group')
            .data(files)
            .enter()
            .append('g')
            .attr('class', 'cell-group')
            .attr('transform', (d, i) => {
                const x = (i % cols) * (this.cellSize + 5) + 20;
                const y = Math.floor(i / cols) * (this.cellSize + 5) + 20;
                return `translate(${x},${y})`;
            });

        // Add rectangles
        cells.append('rect')
            .attr('class', 'heatmap-cell')
            .attr('width', this.cellSize)
            .attr('height', this.cellSize)
            .attr('rx', 4)
            .attr('fill', d => {
                const activity = this.getActivityLevel(d.path);
                return this.colorScale(activity);
            })
            .on('mouseover', (event, d) => this.showTooltip(event, d))
            .on('mouseout', () => this.hideTooltip())
            .on('click', (event, d) => this.handleCellClick(d));

        // Add labels
        cells.append('text')
            .attr('class', 'cell-label')
            .attr('x', this.cellSize / 2)
            .attr('y', this.cellSize / 2)
            .attr('dy', '0.35em')
            .text(d => {
                const name = d.name.split('/').pop();
                return name.length > 8 ? name.substring(0, 6) + '...' : name;
            });

        // Add file type icons
        cells.append('text')
            .attr('x', this.cellSize / 2)
            .attr('y', this.cellSize / 2 - 10)
            .attr('text-anchor', 'middle')
            .style('font-size', '16px')
            .text(d => this.getFileIcon(d));
    }

    getFilesForDirectory(directory) {
        const files = [];
        const collectFiles = (node, path = '') => {
            if (node.children) {
                Object.entries(node.children).forEach(([name, child]) => {
                    const fullPath = path + '/' + name;
                    files.push({
                        name: name,
                        path: fullPath,
                        type: child.type,
                        ...child
                    });
                });
            }
        };

        if (directory === 'development' || directory === '/') {
            collectFiles(this.directoryStructure['/']);
        }

        return files;
    }

    getActivityLevel(path) {
        const stats = this.fileActivity.get(path);
        if (!stats) return 0;

        const total = stats.reads + stats.writes * 2 + stats.modifications * 1.5;
        return Math.min(100, total);
    }

    getFileIcon(file) {
        if (file.type === 'directory') return '📁';

        const ext = file.name.split('.').pop().toLowerCase();
        const iconMap = {
            'js': '📜',
            'json': '📋',
            'yml': '⚙️',
            'yaml': '⚙️',
            'md': '📝',
            'py': '🐍',
            'html': '🌐',
            'css': '🎨',
            'env': '🔐',
            'dockerfile': '🐳'
        };

        return iconMap[ext] || '📄';
    }

    showTooltip(event, file) {
        const tooltip = document.getElementById('tooltip');
        const stats = this.fileActivity.get(file.path) || {
            reads: 0, writes: 0, modifications: 0, lastAccess: 0, totalSize: 0
        };

        const lastAccessTime = stats.lastAccess ?
            new Date(stats.lastAccess).toLocaleTimeString() : 'Never';

        tooltip.innerHTML = `
            <h4>${file.name}</h4>
            <div class="metric">
                <span class="metric-label">Path:</span>
                <span>${file.path}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Reads:</span>
                <span>${stats.reads}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Writes:</span>
                <span>${stats.writes}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Modifications:</span>
                <span>${stats.modifications}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Last Access:</span>
                <span>${lastAccessTime}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Total Size:</span>
                <span>${this.formatSize(stats.totalSize)}</span>
            </div>
        `;

        tooltip.style.display = 'block';
        tooltip.style.left = (event.pageX + 10) + 'px';
        tooltip.style.top = (event.pageY - 10) + 'px';
    }

    hideTooltip() {
        document.getElementById('tooltip').style.display = 'none';
    }

    formatSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    handleCellClick(file) {
        if (file.type === 'directory') {
            this.currentDirectory = file.name;
            this.updateHeatmap();
        }
    }

    updateStats() {
        const totalOps = Array.from(this.fileActivity.values())
            .reduce((sum, stats) => sum + stats.reads + stats.writes + stats.modifications, 0);

        const activeFiles = this.fileActivity.size;

        const hotDirs = new Set();
        this.fileActivity.forEach((stats, path) => {
            const dir = path.split('/').slice(0, -1).join('/');
            if (this.getActivityLevel(path) > 50) {
                hotDirs.add(dir);
            }
        });

        // Find peak activity time
        const hourlyActivity = new Array(24).fill(0);
        this.activities.forEach(activity => {
            const hour = new Date(activity.timestamp).getHours();
            hourlyActivity[hour]++;
        });
        const peakHour = hourlyActivity.indexOf(Math.max(...hourlyActivity));

        document.getElementById('total-ops').textContent = totalOps.toLocaleString();
        document.getElementById('active-files').textContent = activeFiles;
        document.getElementById('hot-dirs').textContent = hotDirs.size;
        document.getElementById('peak-time').textContent = `${peakHour}:00`;
    }

    setupEventListeners() {
        // Time range filter
        document.getElementById('time-range').addEventListener('change', (e) => {
            this.timeRange = e.target.value;
            this.processActivityData();
            this.updateHeatmap();
        });

        // Activity type filter
        document.getElementById('activity-type').addEventListener('change', (e) => {
            this.activityType = e.target.value;
            this.processActivityData();
            this.updateHeatmap();
        });

        // Search functionality
        document.getElementById('search').addEventListener('input', (e) => {
            const searchTerm = e.target.value.toLowerCase();
            this.highlightSearchResults(searchTerm);
        });

        // Time slider
        document.getElementById('time-range-slider').addEventListener('input', (e) => {
            const value = parseInt(e.target.value);
            const hoursAgo = 24 * (1 - value / 100);
            document.getElementById('current-time').textContent =
                hoursAgo === 0 ? 'Now' : `${hoursAgo.toFixed(1)}h ago`;

            // Filter activities based on slider position
            this.filterByTimeSlider(value);
        });
    }

    highlightSearchResults(searchTerm) {
        this.heatmapGroup.selectAll('.heatmap-cell')
            .attr('opacity', d => {
                if (!searchTerm) return 1;
                return d.name.toLowerCase().includes(searchTerm) ? 1 : 0.2;
            });
    }

    filterByTimeSlider(value) {
        const now = Date.now();
        const timeWindow = now - (86400000 * (1 - value / 100));

        this.activities = this.activities.filter(a => a.timestamp >= timeWindow);
        this.processActivityData();
        this.updateHeatmap();
    }

    startActivityMonitor() {
        // Simulate real-time file activity
        setInterval(() => {
            const files = this.getFilesForDirectory(this.currentDirectory);
            if (files.length > 0) {
                const randomFile = files[Math.floor(Math.random() * files.length)];
                const activity = {
                    path: randomFile.path,
                    type: ['read', 'write', 'modify'][Math.floor(Math.random() * 3)],
                    timestamp: Date.now(),
                    size: Math.floor(Math.random() * 1000),
                    user: 'system'
                };

                this.activities.push(activity);
                this.processActivityData();

                // Animate the affected cell
                this.animateCell(randomFile.path);
            }
        }, 5000);
    }

    animateCell(path) {
        const cell = this.heatmapGroup.selectAll('.heatmap-cell')
            .filter(d => d.path === path);

        cell.transition()
            .duration(300)
            .attr('transform', 'scale(1.2)')
            .transition()
            .duration(300)
            .attr('transform', 'scale(1)');
    }
}

// Initialize the heatmap when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const heatmap = new FileSystemHeatmap();

    // Handle window resize
    window.addEventListener('resize', () => {
        heatmap.width = window.innerWidth - 270;
        heatmap.height = window.innerHeight - 100;
        heatmap.svg.attr('width', heatmap.width).attr('height', heatmap.height);
        heatmap.updateHeatmap();
    });
});