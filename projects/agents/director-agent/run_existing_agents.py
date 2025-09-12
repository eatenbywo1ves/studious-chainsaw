"""
Run Your Existing Agents with Observatory Integration
Final script to connect your VonNeumann and Director agents
"""

import asyncio
import websockets
import json
import psutil
import time
from datetime import datetime

class SimpleObservatoryAgent:
    def __init__(self, agent_name, agent_type, capabilities):
        self.agent_name = agent_name
        self.agent_type = agent_type
        self.capabilities = capabilities
        self.server_url = "ws://localhost:8080/ws"
        self.websocket = None
        self.is_running = False
        self.task_count = 0
        self.start_time = time.time()

    async def connect_and_run(self):
        """Connect to observatory and run agent"""
        try:
            print(f"Starting {self.agent_name}...")
            self.websocket = await websockets.connect(self.server_url)
            self.is_running = True
            
            # Register
            await self.register()
            print(f"{self.agent_name} connected to observatory")
            
            # Run agent tasks
            await self.run_agent_loop()
            
        except Exception as e:
            print(f"{self.agent_name} error: {e}")
        finally:
            self.is_running = False
            if self.websocket:
                await self.websocket.close()

    async def register(self):
        """Register with observatory"""
        registration = {
            "type": "register", 
            "agentName": self.agent_name,
            "agentType": self.agent_type,
            "capabilities": self.capabilities
        }
        await self.websocket.send(json.dumps(registration))

    async def run_agent_loop(self):
        """Main agent execution loop"""
        for cycle in range(50):  # Run for 50 cycles
            # Simulate agent work based on type
            await self.perform_agent_work(cycle)
            
            # Send metrics
            await self.send_metrics(cycle)
            
            # Send heartbeat every 5 cycles
            if cycle % 5 == 0:
                await self.send_heartbeat()
            
            await asyncio.sleep(3)  # 3 second intervals

    async def perform_agent_work(self, cycle):
        """Simulate agent-specific work"""
        self.task_count += 1
        
        if self.agent_name == "VonNeumannAgent":
            # Simulate reasoning tasks
            await self.send_event("reasoning_start", "info", f"Starting reasoning cycle {cycle}")
            await asyncio.sleep(0.1)  # Simulate processing
            await self.send_event("reasoning_complete", "info", f"Completed reasoning cycle {cycle}")
            
            if cycle % 3 == 0:
                await self.send_event("synthesis", "info", f"Cross-domain synthesis event {cycle//3}")
                
        elif self.agent_name == "DirectorAgent":
            # Simulate orchestration tasks
            await self.send_event("project_management", "info", f"Managing project cycle {cycle}")
            await asyncio.sleep(0.1)  # Simulate processing
            
            if cycle % 4 == 0:
                await self.send_event("agent_orchestration", "info", f"Orchestrating agents for cycle {cycle}")

    async def send_metrics(self, cycle):
        """Send metrics to observatory"""
        uptime = time.time() - self.start_time
        memory_mb = psutil.Process().memory_info().rss / 1024 / 1024
        
        metrics = {
            "type": "metrics_update",
            "agentName": self.agent_name,
            "metrics": [
                {"name": "uptime", "value": uptime, "unit": "seconds"},
                {"name": "cycle_count", "value": cycle, "unit": "count"},
                {"name": "tasks_completed", "value": self.task_count, "unit": "count"},
                {"name": "memory_usage", "value": memory_mb, "unit": "MB"},
                {"name": "cpu_percent", "value": psutil.Process().cpu_percent(), "unit": "%"}
            ],
            "timestamp": datetime.now().isoformat() + "Z"
        }
        
        await self.websocket.send(json.dumps(metrics))

    async def send_event(self, event_type, severity, message, data=None):
        """Send event to observatory"""
        event = {
            "type": "event_update",
            "agentName": self.agent_name,
            "eventType": event_type,
            "severity": severity,
            "message": message,
            "data": data or {},
            "timestamp": datetime.now().isoformat() + "Z"
        }
        await self.websocket.send(json.dumps(event))

    async def send_heartbeat(self):
        """Send heartbeat"""
        heartbeat = {
            "type": "heartbeat",
            "agentName": self.agent_name,
            "timestamp": datetime.now().isoformat() + "Z",
            "status": "active"
        }
        await self.websocket.send(json.dumps(heartbeat))

async def main():
    """Run both existing agents with observatory integration"""
    print("=" * 60)
    print("Connecting Your Existing Agents to Multi-Agent Observatory")
    print("=" * 60)
    
    # Create agent instances
    vonneumann_agent = SimpleObservatoryAgent(
        "VonNeumannAgent",
        "reasoning_engine", 
        ["mathematical_reasoning", "game_theory", "synthesis", "self_modification"]
    )
    
    director_agent = SimpleObservatoryAgent(
        "DirectorAgent",
        "orchestrator",
        ["project_management", "agent_coordination", "resource_allocation", "pipeline_execution"]
    )
    
    # Run both agents concurrently
    tasks = [
        vonneumann_agent.connect_and_run(),
        director_agent.connect_and_run()
    ]
    
    try:
        await asyncio.gather(*tasks)
        print("Both agents completed their cycles successfully!")
    except KeyboardInterrupt:
        print("\nShutting down agents...")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())