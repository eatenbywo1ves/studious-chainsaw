"""
Basic Agent Template

This template provides a foundation for creating autonomous agents in the development environment.
Customize this template to create agents for your specific use cases.
"""

import asyncio
import logging
import json
import time
from typing import Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum
import sys
import os

# Add shared libraries to path
sys.path.append(
    os.path.join(os.path.dirname(__file__), "..", "..", "shared", "libraries")
)

try:
    from agent_registry import AgentRegistry, AgentInfo, AgentStatus, AgentType
except ImportError:
    print("Warning: Could not import agent_registry. Running in standalone mode.")


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Task:
    id: str
    name: str
    description: str
    status: TaskStatus = TaskStatus.PENDING
    priority: int = 1
    created_at: float = 0
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.created_at == 0:
            self.created_at = time.time()


class BasicAgent:
    def __init__(self, name: str, agent_id: str = None):
        """Initialize the basic agent."""
        self.name = name
        self.agent_id = agent_id or f"agent_{int(time.time())}"
        self.status = AgentStatus.ACTIVE
        self.tasks = {}
        self.is_running = False

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format=f"[{self.name}] %(asctime)s - %(levelname)s - %(message)s",
        )
        self.logger = logging.getLogger(self.name)

        # Agent capabilities
        self.capabilities = ["task_processing", "basic_operations", "status_reporting"]

        # Performance metrics
        self.metrics = {
            "tasks_completed": 0,
            "tasks_failed": 0,
            "uptime": 0,
            "start_time": time.time(),
        }

    def register_with_system(self):
        """Register this agent with the agent registry."""
        try:
            registry = AgentRegistry()
            agent_info = AgentInfo(
                name=self.name,
                description="Basic autonomous agent",
                path=os.path.dirname(os.path.abspath(__file__)),
                main="agent.py",
                type=AgentType.AUTONOMOUS,
                status=self.status,
                dependencies=["asyncio", "logging"],
                capabilities=self.capabilities,
            )
            registry.register_agent(self.agent_id, agent_info)
            self.logger.info(f"Registered agent {self.agent_id} with system")
        except Exception as e:
            self.logger.warning(f"Could not register with system: {e}")

    async def add_task(self, task: Task) -> str:
        """Add a task to the agent's queue."""
        self.tasks[task.id] = task
        self.logger.info(f"Added task: {task.name}")
        return task.id

    async def process_task(self, task: Task) -> Dict[str, Any]:
        """Process a single task. Override this method in subclasses."""
        self.logger.info(f"Processing task: {task.name}")

        # Simulate task processing
        await asyncio.sleep(1)

        # Example task processing logic
        result = {
            "task_id": task.id,
            "task_name": task.name,
            "processed_at": time.time(),
            "status": "completed",
            "message": f"Successfully processed task: {task.name}",
        }

        return result

    async def run_task(self, task_id: str):
        """Run a specific task."""
        if task_id not in self.tasks:
            self.logger.error(f"Task {task_id} not found")
            return

        task = self.tasks[task_id]
        task.status = TaskStatus.RUNNING
        task.started_at = time.time()

        try:
            result = await self.process_task(task)
            task.status = TaskStatus.COMPLETED
            task.result = result
            task.completed_at = time.time()

            self.metrics["tasks_completed"] += 1
            self.logger.info(f"Completed task: {task.name}")

        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)
            task.completed_at = time.time()

            self.metrics["tasks_failed"] += 1
            self.logger.error(f"Failed task {task.name}: {e}")

    async def run_continuously(self):
        """Run the agent continuously, processing tasks as they come."""
        self.is_running = True
        self.logger.info(f"Agent {self.name} starting continuous operation")

        while self.is_running:
            # Find pending tasks
            pending_tasks = [
                task
                for task in self.tasks.values()
                if task.status == TaskStatus.PENDING
            ]

            if pending_tasks:
                # Sort by priority and creation time
                pending_tasks.sort(key=lambda t: (t.priority, t.created_at))

                # Process the highest priority task
                task = pending_tasks[0]
                await self.run_task(task.id)
            else:
                # No tasks to process, wait a bit
                await asyncio.sleep(0.5)

            # Update uptime metrics
            self.metrics["uptime"] = time.time() - self.metrics["start_time"]

    def stop(self):
        """Stop the agent."""
        self.is_running = False
        self.logger.info(f"Agent {self.name} stopping")

    def get_status(self) -> Dict[str, Any]:
        """Get current agent status."""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "status": self.status.value,
            "is_running": self.is_running,
            "capabilities": self.capabilities,
            "metrics": self.metrics,
            "task_summary": {
                "total_tasks": len(self.tasks),
                "pending": len(
                    [t for t in self.tasks.values() if t.status == TaskStatus.PENDING]
                ),
                "running": len(
                    [t for t in self.tasks.values() if t.status == TaskStatus.RUNNING]
                ),
                "completed": len(
                    [t for t in self.tasks.values() if t.status == TaskStatus.COMPLETED]
                ),
                "failed": len(
                    [t for t in self.tasks.values() if t.status == TaskStatus.FAILED]
                ),
            },
        }

    def health_check(self) -> Dict[str, Any]:
        """Perform health check."""
        return {
            "status": "healthy" if self.is_running else "stopped",
            "uptime": self.metrics["uptime"],
            "task_queue_size": len(
                [t for t in self.tasks.values() if t.status == TaskStatus.PENDING]
            ),
            "error_rate": self.metrics["tasks_failed"]
            / max(1, self.metrics["tasks_completed"] + self.metrics["tasks_failed"]),
            "last_check": time.time(),
        }


# Example agent implementation
class ExampleAgent(BasicAgent):
    def __init__(self):
        super().__init__("ExampleAgent", "example_agent_001")

        # Add specific capabilities for this agent
        self.capabilities.extend(["data_processing", "file_operations", "api_calls"])

    async def process_task(self, task: Task) -> Dict[str, Any]:
        """Custom task processing for ExampleAgent."""
        self.logger.info(f"ExampleAgent processing: {task.name}")

        # Example: Different processing based on task type
        if "data" in task.name.lower():
            return await self.process_data_task(task)
        elif "file" in task.name.lower():
            return await self.process_file_task(task)
        else:
            return await super().process_task(task)

    async def process_data_task(self, task: Task) -> Dict[str, Any]:
        """Process data-related tasks."""
        await asyncio.sleep(0.5)  # Simulate data processing
        return {
            "task_id": task.id,
            "type": "data_processing",
            "result": "Data processed successfully",
            "processed_at": time.time(),
        }

    async def process_file_task(self, task: Task) -> Dict[str, Any]:
        """Process file-related tasks."""
        await asyncio.sleep(0.3)  # Simulate file operations
        return {
            "task_id": task.id,
            "type": "file_processing",
            "result": "File operations completed",
            "processed_at": time.time(),
        }


async def main():
    """Main function to demonstrate agent usage."""
    # Create and register agent
    agent = ExampleAgent()
    agent.register_with_system()

    # Add some example tasks
    tasks = [
        Task("task_1", "Data Analysis Task", "Analyze the provided dataset"),
        Task("task_2", "File Processing Task", "Process uploaded files"),
        Task("task_3", "General Task", "Perform general operations"),
    ]

    for task in tasks:
        await agent.add_task(task)

    # Run agent for a short time
    print(f"Starting {agent.name}...")
    print("Initial status:", json.dumps(agent.get_status(), indent=2))

    # Create a task to run the agent for 5 seconds
    agent_task = asyncio.create_task(agent.run_continuously())

    # Let it run for a few seconds
    await asyncio.sleep(5)

    # Stop the agent
    agent.stop()
    await agent_task

    print("Final status:", json.dumps(agent.get_status(), indent=2))
    print("Health check:", json.dumps(agent.health_check(), indent=2))


if __name__ == "__main__":
    asyncio.run(main())
