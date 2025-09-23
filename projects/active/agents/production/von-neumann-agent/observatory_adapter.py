"""
Observatory Adapter for VonNeumann Agent
Connects the VonNeumann Agent to the Multi-Agent Observatory System
"""

import asyncio
import websockets
import json
import time
import psutil
from datetime import datetime
from typing import Dict, Any


class VonNeumannObservatoryAdapter:
    def __init__(
        self,
        agent_instance,
        server_url="ws://localhost:8080/ws",
        agent_name="VonNeumannAgent",
    ):
        self.agent = agent_instance
        self.server_url = server_url
        self.agent_name = agent_name
        self.websocket = None
        self.is_connected = False
        self.start_time = time.time()
        self.metrics_interval = 5.0  # seconds
        self.heartbeat_interval = 30.0  # seconds

        # Performance tracking
        self.task_counter = 0
        self.reasoning_times = []
        self.synthesis_events = 0
        self.error_count = 0

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
            "agentType": "reasoning_engine",
            "capabilities": [
                "mathematical_reasoning",
                "game_theory",
                "bayesian_inference",
                "formal_logic",
                "interdisciplinary_synthesis",
                "self_modification",
            ],
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
        """Collect agent metrics and send to observatory"""
        metrics = {
            "type": "metrics_update",
            "agentName": self.agent_name,
            "metrics": [
                {
                    "name": "uptime",
                    "value": time.time() - self.start_time,
                    "unit": "seconds",
                },
                {
                    "name": "tasks_completed",
                    "value": self.task_counter,
                    "unit": "count",
                },
                {
                    "name": "synthesis_events",
                    "value": self.synthesis_events,
                    "unit": "count",
                },
                {"name": "error_count", "value": self.error_count, "unit": "count"},
                {
                    "name": "memory_usage",
                    "value": psutil.Process().memory_info().rss / 1024 / 1024,
                    "unit": "MB",
                },
                {
                    "name": "cpu_percent",
                    "value": psutil.Process().cpu_percent(),
                    "unit": "%",
                },
            ],
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

        # Add average reasoning time if available
        if self.reasoning_times:
            avg_time = sum(self.reasoning_times[-10:]) / len(self.reasoning_times[-10:])
            metrics["metrics"].append(
                {"name": "avg_reasoning_time", "value": avg_time, "unit": "ms"}
            )

        await self.send_message(metrics)

    async def send_heartbeat(self):
        """Send heartbeat to observatory"""
        heartbeat = {
            "type": "heartbeat",
            "agentName": self.agent_name,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "status": "active",
        }
        await self.send_message(heartbeat)

    async def send_event(
        self, event_type: str, severity: str, message: str, data: Dict = None
    ):
        """Send event to observatory"""
        event = {
            "type": "event_update",
            "agentName": self.agent_name,
            "eventType": event_type,
            "severity": severity,
            "message": message,
            "data": data or {},
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        await self.send_message(event)

    # Hooks for agent activities
    def on_task_start(self, task_name: str, data: Dict = None):
        """Called when agent starts a task"""
        asyncio.create_task(
            self.send_event("task_start", "info", f"Started task: {task_name}", data)
        )

    def on_task_complete(self, task_name: str, duration_ms: float, data: Dict = None):
        """Called when agent completes a task"""
        self.task_counter += 1
        self.reasoning_times.append(duration_ms)
        asyncio.create_task(
            self.send_event(
                "task_complete",
                "info",
                f"Completed task: {task_name} in {duration_ms:.2f}ms",
                data,
            )
        )

    def on_synthesis_event(self, domain_from: str, domain_to: str, insight: str):
        """Called when interdisciplinary synthesis occurs"""
        self.synthesis_events += 1
        asyncio.create_task(
            self.send_event(
                "synthesis",
                "info",
                f"Cross-domain insight: {domain_from} → {domain_to}",
                {"insight": insight},
            )
        )

    def on_self_modification(self, modification_type: str, details: str):
        """Called when agent modifies itself"""
        asyncio.create_task(
            self.send_event(
                "self_modification",
                "warning",
                f"Self-modification: {modification_type}",
                {"details": details},
            )
        )

    def on_error(self, error_type: str, message: str, data: Dict = None):
        """Called when an error occurs"""
        self.error_count += 1
        asyncio.create_task(
            self.send_event("error", "error", f"{error_type}: {message}", data)
        )


# Enhanced VonNeumann Agent with Observatory Integration
class ObservatoryEnabledVonNeumannAgent:
    def __init__(self, original_agent, server_url="ws://localhost:8080/ws"):
        self.agent = original_agent
        self.adapter = VonNeumannObservatoryAdapter(original_agent, server_url)

    async def start_monitoring(self):
        """Start observatory monitoring"""
        await self.adapter.connect()

    # Wrap agent methods to add monitoring
    def reason_about(self, *args, **kwargs):
        task_name = "reasoning"
        start_time = time.time()
        self.adapter.on_task_start(task_name, {"args": str(args)})

        try:
            result = self.agent.reason_about(*args, **kwargs)
            duration = (time.time() - start_time) * 1000
            self.adapter.on_task_complete(
                task_name, duration, {"result_type": type(result).__name__}
            )
            return result
        except Exception as e:
            self.adapter.on_error("reasoning_error", str(e))
            raise

    def synthesize_knowledge(self, *args, **kwargs):
        task_name = "synthesis"
        start_time = time.time()
        self.adapter.on_task_start(task_name)

        try:
            result = self.agent.synthesize_knowledge(*args, **kwargs)
            duration = (time.time() - start_time) * 1000
            self.adapter.on_task_complete(task_name, duration)
            # Simulate synthesis event
            self.adapter.on_synthesis_event(
                "mathematics", "computer_science", "New computational insight"
            )
            return result
        except Exception as e:
            self.adapter.on_error("synthesis_error", str(e))
            raise


# Usage example
async def main():
    from von_neumann_agent import VonNeumannAgent

    # Create original agent
    original_agent = VonNeumannAgent()

    # Create observatory-enabled version
    monitored_agent = ObservatoryEnabledVonNeumannAgent(original_agent)

    # Start monitoring
    await monitored_agent.start_monitoring()

    print("VonNeumann Agent connected to observatory! Running example tasks...")

    # Run some example tasks
    for i in range(5):
        await asyncio.sleep(2)
        try:
            # Example reasoning task
            monitored_agent.reason_about("test problem", i)
            await asyncio.sleep(1)
            monitored_agent.synthesize_knowledge()
        except Exception as e:
            print(f"Task error: {e}")

    # Keep running
    await asyncio.sleep(300)  # Run for 5 minutes


if __name__ == "__main__":
    asyncio.run(main())
