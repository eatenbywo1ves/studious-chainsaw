# Immediate MCP & Agent Architecture Improvements

## Quick Wins (Can Implement Today)

### 1. Enhanced Service Discovery
Create a unified service discovery configuration:

```python
# C:\Users\Corbin\development\shared\libraries\service_discovery.py
import json
import os
from typing import Dict, List, Optional
from dataclasses import dataclass
import socket

@dataclass
class Service:
    name: str
    type: str  # 'mcp' or 'agent'
    host: str
    port: Optional[int]
    health_endpoint: Optional[str]
    capabilities: List[str]
    status: str = 'unknown'

class ServiceDiscovery:
    def __init__(self):
        self.services = {}
        self.health_check_interval = 30  # seconds
        
    def register_service(self, service: Service):
        """Register a new service"""
        self.services[service.name] = service
        self.check_health(service.name)
        
    def discover_services(self, service_type: Optional[str] = None):
        """Discover available services"""
        if service_type:
            return {k: v for k, v in self.services.items() 
                   if v.type == service_type}
        return self.services
        
    def check_health(self, service_name: str):
        """Check if a service is healthy"""
        service = self.services.get(service_name)
        if not service:
            return False
            
        if service.health_endpoint:
            # Implement health check logic
            try:
                # Check if port is open
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((service.host, service.port))
                sock.close()
                service.status = 'healthy' if result == 0 else 'unhealthy'
                return result == 0
            except:
                service.status = 'unhealthy'
                return False
        return True
```

### 2. Centralized Configuration
Consolidate all configurations:

```json
// C:\Users\Corbin\development\configs\unified_config.json
{
  "services": {
    "mcp_servers": {
      "filesystem": {
        "enabled": true,
        "path": "C:\\Users\\Corbin\\development",
        "health_check": "/health",
        "retry_policy": {
          "max_retries": 3,
          "backoff": "exponential"
        }
      },
      "financial-stochastic": {
        "enabled": true,
        "port": 3001,
        "capabilities": ["gbm", "heston", "merton"],
        "rate_limit": {
          "requests_per_minute": 100
        }
      }
    },
    "agents": {
      "director": {
        "enabled": true,
        "port": 8000,
        "max_concurrent_tasks": 10,
        "scheduling_algorithm": "priority_queue"
      },
      "observatory": {
        "enabled": true,
        "port": 8080,
        "metrics_interval": 5000,
        "retention_days": 30
      }
    }
  },
  "infrastructure": {
    "logging": {
      "level": "INFO",
      "format": "json",
      "destinations": ["file", "console"],
      "rotation": {
        "max_size": "100MB",
        "max_files": 10
      }
    },
    "monitoring": {
      "metrics_enabled": true,
      "tracing_enabled": true,
      "sample_rate": 0.1
    }
  }
}
```

### 3. Standard Agent Template
Enhanced template with best practices:

```python
# C:\Users\Corbin\development\agents\templates\enhanced-agent-template\agent.py
import asyncio
import logging
import json
from typing import Dict, Any, Optional
from dataclasses import dataclass
from abc import ABC, abstractmethod
import aiohttp
from datetime import datetime

@dataclass
class AgentConfig:
    name: str
    version: str = "1.0.0"
    capabilities: list = None
    health_check_interval: int = 30
    observatory_url: str = "http://localhost:8080"
    
class BaseAgent(ABC):
    """Base class for all agents with standard functionality"""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.logger = self._setup_logging()
        self.health_status = "initializing"
        self.metrics = {}
        self.running = False
        
    def _setup_logging(self):
        """Setup structured logging"""
        logger = logging.getLogger(self.config.name)
        logger.setLevel(logging.INFO)
        
        # JSON formatter for structured logs
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "agent": "%(name)s", '
            '"level": "%(levelname)s", "message": "%(message)s"}'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
        
    async def start(self):
        """Start the agent"""
        self.running = True
        self.health_status = "healthy"
        
        # Start background tasks
        tasks = [
            asyncio.create_task(self._health_check_loop()),
            asyncio.create_task(self._metrics_collection_loop()),
            asyncio.create_task(self._register_with_observatory()),
            asyncio.create_task(self.run())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"Agent error: {e}")
            self.health_status = "error"
        finally:
            self.running = False
            
    @abstractmethod
    async def run(self):
        """Main agent logic - override in subclass"""
        pass
        
    async def _health_check_loop(self):
        """Periodic health checks"""
        while self.running:
            await asyncio.sleep(self.config.health_check_interval)
            self.logger.info(f"Health check: {self.health_status}")
            
    async def _metrics_collection_loop(self):
        """Collect and report metrics"""
        while self.running:
            await asyncio.sleep(5)
            self.metrics.update({
                "timestamp": datetime.now().isoformat(),
                "status": self.health_status,
                "uptime": asyncio.get_event_loop().time()
            })
            
    async def _register_with_observatory(self):
        """Register with observatory for monitoring"""
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "name": self.config.name,
                    "version": self.config.version,
                    "capabilities": self.config.capabilities or [],
                    "status": self.health_status
                }
                async with session.post(
                    f"{self.config.observatory_url}/api/agents/register",
                    json=payload
                ) as response:
                    if response.status == 200:
                        self.logger.info("Registered with observatory")
                    else:
                        self.logger.error(f"Registration failed: {response.status}")
        except Exception as e:
            self.logger.error(f"Failed to register: {e}")
```

### 4. API Gateway Prototype
Simple API gateway for unified access:

```python
# C:\Users\Corbin\development\shared\gateway\api_gateway.py
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any
import httpx
import asyncio
from datetime import datetime
import json

app = FastAPI(title="MCP & Agent API Gateway")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Service registry
SERVICES = {
    "observatory": "http://localhost:8080",
    "director": "http://localhost:8000",
    "mcp-financial": "http://localhost:3001",
    "mcp-filesystem": "http://localhost:3002"
}

# Rate limiting
rate_limits = {}
RATE_LIMIT_PER_MINUTE = 100

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Simple rate limiting"""
    client_ip = request.client.host
    current_minute = datetime.now().strftime("%Y%m%d%H%M")
    
    key = f"{client_ip}:{current_minute}"
    if key not in rate_limits:
        rate_limits[key] = 0
    
    rate_limits[key] += 1
    
    if rate_limits[key] > RATE_LIMIT_PER_MINUTE:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    response = await call_next(request)
    return response

@app.get("/health")
async def health_check():
    """Gateway health check"""
    return {"status": "healthy", "services": len(SERVICES)}

@app.get("/services")
async def list_services():
    """List available services"""
    service_status = {}
    async with httpx.AsyncClient() as client:
        for name, url in SERVICES.items():
            try:
                response = await client.get(f"{url}/health", timeout=2)
                service_status[name] = "healthy" if response.status_code == 200 else "unhealthy"
            except:
                service_status[name] = "unreachable"
    
    return service_status

@app.post("/mcp/{server}/{tool}")
async def mcp_proxy(server: str, tool: str, request: Dict[Any, Any]):
    """Proxy MCP tool calls"""
    if f"mcp-{server}" not in SERVICES:
        raise HTTPException(status_code=404, detail=f"MCP server {server} not found")
    
    url = SERVICES[f"mcp-{server}"]
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{url}/tools/{tool}",
                json=request,
                timeout=30
            )
            return response.json()
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

@app.post("/agent/{agent}/task")
async def agent_task(agent: str, task: Dict[Any, Any]):
    """Submit task to agent"""
    if agent not in SERVICES:
        raise HTTPException(status_code=404, detail=f"Agent {agent} not found")
    
    url = SERVICES[agent]
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{url}/task",
                json=task,
                timeout=60
            )
            return response.json()
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
```

### 5. Enhanced Monitoring Dashboard
Add real-time metrics visualization:

```javascript
// C:\Users\Corbin\development\agents\production\observatory-agent\dashboard\enhanced.html
<!DOCTYPE html>
<html>
<head>
    <title>System Observatory Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', sans-serif;
            background: #1e1e1e;
            color: #fff;
            margin: 0;
            padding: 20px;
        }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
        }
        .card {
            background: #2d2d2d;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        .metric {
            font-size: 2em;
            font-weight: bold;
            color: #4CAF50;
        }
        .status-healthy { color: #4CAF50; }
        .status-unhealthy { color: #f44336; }
        .status-unknown { color: #ff9800; }
    </style>
</head>
<body>
    <h1>System Observatory Dashboard</h1>
    
    <div class="dashboard">
        <div class="card">
            <h2>System Health</h2>
            <div id="health-status"></div>
        </div>
        
        <div class="card">
            <h2>Active Services</h2>
            <div id="service-list"></div>
        </div>
        
        <div class="card">
            <h2>Real-time Metrics</h2>
            <canvas id="metrics-chart"></canvas>
        </div>
        
        <div class="card">
            <h2>Agent Performance</h2>
            <canvas id="performance-chart"></canvas>
        </div>
    </div>
    
    <script>
        // WebSocket connection for real-time updates
        const ws = new WebSocket('ws://localhost:8080/ws');
        
        // Initialize charts
        const metricsChart = new Chart(document.getElementById('metrics-chart'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Memory Usage',
                    data: [],
                    borderColor: '#4CAF50',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
        
        // Update dashboard with real-time data
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            
            if (data.type === 'metrics_update') {
                updateMetrics(data);
            } else if (data.type === 'health_update') {
                updateHealth(data);
            }
        };
        
        function updateMetrics(data) {
            // Update charts with new data
            const timestamp = new Date().toLocaleTimeString();
            metricsChart.data.labels.push(timestamp);
            
            if (metricsChart.data.labels.length > 20) {
                metricsChart.data.labels.shift();
                metricsChart.data.datasets[0].data.shift();
            }
            
            const memoryMetric = data.metrics.find(m => m.name === 'memory_usage_percent');
            if (memoryMetric) {
                metricsChart.data.datasets[0].data.push(memoryMetric.value);
            }
            
            metricsChart.update();
        }
        
        function updateHealth(data) {
            const healthDiv = document.getElementById('health-status');
            healthDiv.innerHTML = `
                <div class="metric status-${data.status}">
                    ${data.status.toUpperCase()}
                </div>
                <p>Uptime: ${Math.floor(data.uptime / 60)} minutes</p>
                <p>Active Agents: ${data.activeAgents}</p>
            `;
        }
        
        // Initial data fetch
        fetch('http://localhost:8080/api/agents')
            .then(res => res.json())
            .then(agents => {
                const serviceList = document.getElementById('service-list');
                serviceList.innerHTML = agents.map(agent => `
                    <div class="service-item">
                        <span class="status-${agent.status}">${agent.name}</span>
                        <small> - ${agent.status}</small>
                    </div>
                `).join('');
            });
    </script>
</body>
</html>
```

## Implementation Checklist

### Today's Tasks
- [ ] Implement service discovery module
- [ ] Create unified configuration file
- [ ] Set up enhanced agent template
- [ ] Deploy API gateway prototype
- [ ] Update monitoring dashboard

### This Week
- [ ] Add health checks to all services
- [ ] Implement structured logging
- [ ] Create service registry
- [ ] Set up rate limiting
- [ ] Add metrics collection

### Next Week
- [ ] Implement message queue
- [ ] Add distributed tracing
- [ ] Create CI/CD pipeline
- [ ] Enhance security layer
- [ ] Performance optimization

## Testing Strategy

### Unit Tests
```python
# C:\Users\Corbin\development\tests\test_service_discovery.py
import pytest
from shared.libraries.service_discovery import ServiceDiscovery, Service

def test_service_registration():
    sd = ServiceDiscovery()
    service = Service(
        name="test-service",
        type="mcp",
        host="localhost",
        port=3000,
        health_endpoint="/health",
        capabilities=["test"]
    )
    sd.register_service(service)
    assert "test-service" in sd.services

def test_service_discovery_by_type():
    sd = ServiceDiscovery()
    sd.register_service(Service("mcp1", "mcp", "localhost", 3001, None, []))
    sd.register_service(Service("agent1", "agent", "localhost", 8001, None, []))
    
    mcp_services = sd.discover_services("mcp")
    assert len(mcp_services) == 1
    assert "mcp1" in mcp_services
```

### Integration Tests
```python
# C:\Users\Corbin\development\tests\test_integration.py
import asyncio
import aiohttp
import pytest

@pytest.mark.asyncio
async def test_gateway_health():
    async with aiohttp.ClientSession() as session:
        async with session.get("http://localhost:9000/health") as response:
            assert response.status == 200
            data = await response.json()
            assert data["status"] == "healthy"

@pytest.mark.asyncio
async def test_end_to_end_flow():
    # Test complete flow through gateway to services
    async with aiohttp.ClientSession() as session:
        # Submit task to director
        task = {"type": "process", "data": "test"}
        async with session.post(
            "http://localhost:9000/agent/director/task",
            json=task
        ) as response:
            assert response.status == 200
```

## Monitoring & Alerts

### Key Metrics to Track
1. **Service Health**: All services responding
2. **Response Time**: < 200ms p95
3. **Error Rate**: < 0.1%
4. **Memory Usage**: < 80%
5. **CPU Usage**: < 70%

### Alert Rules
```yaml
alerts:
  - name: ServiceDown
    condition: service.status == "unhealthy"
    duration: 1m
    action: notify
    
  - name: HighErrorRate
    condition: error_rate > 1%
    duration: 5m
    action: page
    
  - name: HighMemoryUsage
    condition: memory_usage > 90%
    duration: 5m
    action: alert
```

---

**Ready for Implementation**: These improvements can be started immediately and will provide significant architectural benefits.