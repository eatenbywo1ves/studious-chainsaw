"""
Observatory Adapter for Director Agent
Connects the Director Agent to the Multi-Agent Observatory System
"""

import asyncio
import websockets
import json
import time
import psutil
import threading
from datetime import datetime
from typing import Dict, Any, Optional, List
import uuid

class DirectorAgentObservatoryAdapter:
    def __init__(self, director_instance, server_url="ws://localhost:8080/ws", agent_name="DirectorAgent"):
        self.director = director_instance
        self.server_url = server_url
        self.agent_name = agent_name
        self.websocket = None
        self.is_connected = False
        self.start_time = time.time()
        self.metrics_interval = 5.0  # seconds
        self.heartbeat_interval = 30.0  # seconds
        
        # Director-specific metrics
        self.projects_managed = 0
        self.agents_orchestrated = 0
        self.pipeline_executions = 0
        self.resource_allocations = 0
        self.error_count = 0
        self.active_projects = {}
        
    async def connect(self):
        """Connect to observatory server"""
        try:
            self.websocket = await websockets.connect(self.server_url)
            self.is_connected = True
            await self.register()
            print(f"{self.agent_name} connected to observatory")
            
            # Start monitoring tasks
            asyncio.create_task(self.metrics_loop())
            asyncio.create_task(self.heartbeat_loop())
            
        except Exception as e:
            print(f"Connection failed: {e}")
            self.is_connected = False
    
    async def register(self):
        """Register with observatory server"""
        registration = {
            "type": "register",
            "agentName": self.agent_name,
            "agentType": "orchestrator",
            "capabilities": [
                "project_management",
                "agent_orchestration",
                "resource_allocation",
                "pipeline_execution",
                "multi_agent_coordination",
                "video_generation_management"
            ]
        }
        await self.send_message(registration)
    
    async def send_message(self, message: Dict[str, Any]):
        """Send message to observatory server"""
        if self.websocket and self.is_connected:
            try:
                await self.websocket.send(json.dumps(message))
            except Exception as e:
                print(f"Send error: {e}")
                self.is_connected = False
    
    async def metrics_loop(self):
        """Periodic metrics collection"""
        while self.is_connected:
            await self.collect_and_send_metrics()
            await asyncio.sleep(self.metrics_interval)
    
    async def heartbeat_loop(self):
        """Periodic heartbeat"""
        while self.is_connected:
            await self.send_heartbeat()
            await asyncio.sleep(self.heartbeat_interval)
    
    async def collect_and_send_metrics(self):
        """Collect director metrics and send to observatory"""
        metrics = {
            "type": "metrics_update",
            "agentName": self.agent_name,
            "metrics": [
                {"name": "uptime", "value": time.time() - self.start_time, "unit": "seconds"},
                {"name": "projects_managed", "value": self.projects_managed, "unit": "count"},
                {"name": "agents_orchestrated", "value": self.agents_orchestrated, "unit": "count"},
                {"name": "pipeline_executions", "value": self.pipeline_executions, "unit": "count"},
                {"name": "resource_allocations", "value": self.resource_allocations, "unit": "count"},
                {"name": "active_projects", "value": len(self.active_projects), "unit": "count"},
                {"name": "error_count", "value": self.error_count, "unit": "count"},
                {"name": "memory_usage", "value": psutil.Process().memory_info().rss / 1024 / 1024, "unit": "MB"},
                {"name": "cpu_percent", "value": psutil.Process().cpu_percent(), "unit": "%"}
            ],
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        await self.send_message(metrics)
    
    async def send_heartbeat(self):
        """Send heartbeat to observatory"""
        heartbeat = {
            "type": "heartbeat",
            "agentName": self.agent_name,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "status": "active",
            "metadata": {
                "active_projects": len(self.active_projects),
                "managed_agents": self.agents_orchestrated
            }
        }
        await self.send_message(heartbeat)
    
    async def send_event(self, event_type: str, severity: str, message: str, data: Dict = None):
        """Send event to observatory"""
        event = {
            "type": "event_update",
            "agentName": self.agent_name,
            "eventType": event_type,
            "severity": severity,
            "message": message,
            "data": data or {},
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        await self.send_message(event)
    
    # Director-specific event hooks
    def on_project_start(self, project_id: str, project_type: str, agents: List[str]):
        """Called when a new project starts"""
        self.projects_managed += 1
        self.active_projects[project_id] = {
            "type": project_type,
            "agents": agents,
            "start_time": time.time()
        }
        asyncio.create_task(self.send_event(
            "project_start", "info", 
            f"Started project: {project_id} ({project_type})",
            {"project_id": project_id, "agents": agents}
        ))
    
    def on_project_complete(self, project_id: str, duration_s: float, status: str):
        """Called when a project completes"""
        if project_id in self.active_projects:
            del self.active_projects[project_id]
        
        asyncio.create_task(self.send_event(
            "project_complete", "info", 
            f"Project completed: {project_id} ({status}) in {duration_s:.2f}s",
            {"project_id": project_id, "duration": duration_s, "status": status}
        ))
    
    def on_agent_orchestration(self, agent_type: str, task: str, priority: int):
        """Called when orchestrating an agent"""
        self.agents_orchestrated += 1
        asyncio.create_task(self.send_event(
            "agent_orchestration", "info",
            f"Orchestrated {agent_type} for task: {task}",
            {"agent_type": agent_type, "task": task, "priority": priority}
        ))
    
    def on_pipeline_execution(self, pipeline_name: str, steps: List[str]):
        """Called when executing a pipeline"""
        self.pipeline_executions += 1
        asyncio.create_task(self.send_event(
            "pipeline_execution", "info",
            f"Executing pipeline: {pipeline_name}",
            {"pipeline": pipeline_name, "steps": steps}
        ))
    
    def on_resource_allocation(self, resource_type: str, amount: float, agent: str):
        """Called when allocating resources"""
        self.resource_allocations += 1
        asyncio.create_task(self.send_event(
            "resource_allocation", "info",
            f"Allocated {amount} {resource_type} to {agent}",
            {"resource_type": resource_type, "amount": amount, "agent": agent}
        ))
    
    def on_coordination_event(self, event_type: str, agents: List[str], details: str):
        """Called during multi-agent coordination"""
        asyncio.create_task(self.send_event(
            "coordination", "info",
            f"Coordination event: {event_type} with {len(agents)} agents",
            {"coordination_type": event_type, "agents": agents, "details": details}
        ))
    
    def on_error(self, error_type: str, message: str, data: Dict = None):
        """Called when an error occurs"""
        self.error_count += 1
        asyncio.create_task(self.send_event(
            "error", "error", f"{error_type}: {message}", data
        ))

# Enhanced Director Agent with Observatory Integration  
class ObservatoryEnabledDirectorAgent:
    def __init__(self, original_director, server_url="ws://localhost:8080/ws"):
        self.director = original_director
        self.adapter = DirectorAgentObservatoryAdapter(original_director, server_url)
        
    async def start_monitoring(self):
        """Start observatory monitoring"""
        await self.adapter.connect()
    
    # Wrap director methods to add monitoring
    def create_project(self, project_type: str, agents: List[str], *args, **kwargs):
        project_id = f"project_{uuid.uuid4().hex[:8]}"
        self.adapter.on_project_start(project_id, project_type, agents)
        
        try:
            result = self.director.create_project(*args, **kwargs)
            return result
        except Exception as e:
            self.adapter.on_error("project_creation_error", str(e))
            raise
    
    def orchestrate_agent(self, agent_type: str, task: str, priority: int = 1, *args, **kwargs):
        self.adapter.on_agent_orchestration(agent_type, task, priority)
        
        try:
            result = self.director.orchestrate_agent(agent_type, task, *args, **kwargs)
            return result
        except Exception as e:
            self.adapter.on_error("orchestration_error", str(e))
            raise
    
    def execute_pipeline(self, pipeline_name: str, steps: List[str], *args, **kwargs):
        self.adapter.on_pipeline_execution(pipeline_name, steps)
        
        try:
            result = self.director.execute_pipeline(pipeline_name, steps, *args, **kwargs)
            return result
        except Exception as e:
            self.adapter.on_error("pipeline_error", str(e))
            raise
    
    def allocate_resources(self, resource_type: str, amount: float, agent: str, *args, **kwargs):
        self.adapter.on_resource_allocation(resource_type, amount, agent)
        
        try:
            result = self.director.allocate_resources(resource_type, amount, agent, *args, **kwargs)
            return result
        except Exception as e:
            self.adapter.on_error("resource_error", str(e))
            raise

# Usage example and runner
async def main():
    # Simulate director agent (replace with your actual director)
    class MockDirectorAgent:
        def create_project(self, *args, **kwargs):
            return {"status": "created", "id": "test_project"}
        
        def orchestrate_agent(self, agent_type, task, *args, **kwargs):
            return {"status": "orchestrated", "agent": agent_type, "task": task}
        
        def execute_pipeline(self, pipeline_name, steps, *args, **kwargs):
            return {"status": "executed", "pipeline": pipeline_name}
        
        def allocate_resources(self, resource_type, amount, agent, *args, **kwargs):
            return {"status": "allocated", "resource": resource_type, "amount": amount}
    
    # Create original director
    original_director = MockDirectorAgent()
    
    # Create observatory-enabled version
    monitored_director = ObservatoryEnabledDirectorAgent(original_director)
    
    # Start monitoring
    await monitored_director.start_monitoring()
    
    print("Director Agent connected to observatory! Running example operations...")
    
    # Simulate director operations
    for i in range(3):
        await asyncio.sleep(3)
        try:
            # Example operations
            monitored_director.create_project("video_generation", ["script_agent", "visual_agent"])
            monitored_director.orchestrate_agent("script_agent", f"generate_script_{i}", priority=1)
            monitored_director.execute_pipeline("video_pipeline", ["script", "visual", "audio", "edit"])
            monitored_director.allocate_resources("gpu_memory", 4.0, "visual_agent")
        except Exception as e:
            print(f"Operation error: {e}")
    
    # Keep running
    await asyncio.sleep(300)  # Run for 5 minutes

if __name__ == "__main__":
    asyncio.run(main())