"""
Agent Registry System - Manages agent discovery, registration, and health monitoring
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
import uuid
from dataclasses import dataclass, field
from redis_communication import RedisCommunicator, RedisConfig, MessageType

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AgentStatus(Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    IDLE = "idle"
    ERROR = "error"
    MAINTENANCE = "maintenance"


@dataclass
class AgentInfo:
    id: str
    type: str
    status: AgentStatus
    capabilities: List[str]
    capacity: int  # 0-100 representing current load
    registered_at: datetime
    last_heartbeat: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    tasks_completed: int = 0
    tasks_failed: int = 0
    average_task_time: float = 0.0

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "status": self.status.value,
            "capabilities": self.capabilities,
            "capacity": self.capacity,
            "registered_at": self.registered_at.isoformat(),
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "metadata": self.metadata,
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "average_task_time": self.average_task_time
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        return cls(
            id=data["id"],
            type=data["type"],
            status=AgentStatus(data["status"]),
            capabilities=data.get("capabilities", []),
            capacity=data.get("capacity", 100),
            registered_at=datetime.fromisoformat(data["registered_at"]),
            last_heartbeat=datetime.fromisoformat(data["last_heartbeat"]),
            metadata=data.get("metadata", {}),
            tasks_completed=data.get("tasks_completed", 0),
            tasks_failed=data.get("tasks_failed", 0),
            average_task_time=data.get("average_task_time", 0.0)
        )


class AgentRegistry:
    """Central registry for all agents in the system"""

    def __init__(self, redis_config: RedisConfig = None):
        self.redis_config = redis_config or RedisConfig()
        self.communicator = RedisCommunicator(
            agent_id="registry",
            agent_type="system",
            config=self.redis_config
        )
        self.agents: Dict[str, AgentInfo] = {}
        self.agent_types: Dict[str, List[str]] = {}
        self.health_check_interval = 15  # seconds
        self.heartbeat_timeout = 30  # seconds
        self.running = False

    async def start(self):
        """Start the agent registry"""
        logger.info("Starting Agent Registry")

        # Connect to Redis
        connected = await self.communicator.connect()
        if not connected:
            logger.error("Failed to connect to Redis")
            return False

        # Register message handlers
        self._register_handlers()

        # Start background tasks
        self.running = True
        asyncio.create_task(self.communicator.message_listener())
        asyncio.create_task(self.health_check_loop())
        asyncio.create_task(self.load_existing_agents())

        logger.info("Agent Registry started successfully")
        return True

    async def stop(self):
        """Stop the agent registry"""
        logger.info("Stopping Agent Registry")
        self.running = False
        await self.communicator.disconnect()

    def _register_handlers(self):
        """Register message handlers"""
        self.communicator.register_handler(
            MessageType.AGENT_REGISTER,
            self.handle_agent_registration
        )
        self.communicator.register_handler(
            MessageType.AGENT_HEARTBEAT,
            self.handle_agent_heartbeat
        )
        self.communicator.register_handler(
            MessageType.AGENT_STATUS,
            self.handle_agent_status
        )
        self.communicator.register_handler(
            MessageType.TASK_COMPLETE,
            self.handle_task_complete
        )
        self.communicator.register_handler(
            MessageType.TASK_FAILED,
            self.handle_task_failed
        )

    async def load_existing_agents(self):
        """Load existing agent information from Redis"""
        try:
            # Get all active agents
            active_agents = await self.communicator.get_active_agents()

            for agent_id in active_agents:
                agent_data = await self.communicator.get_agent_info(agent_id)
                if agent_data:
                    agent_info = self._create_agent_info(agent_data)
                    self.agents[agent_id] = agent_info
                    self._update_agent_type_index(agent_info)

            logger.info(f"Loaded {len(self.agents)} existing agents")

        except Exception as e:
            logger.error(f"Error loading existing agents: {e}")

    def _create_agent_info(self, data: Dict[str, Any]) -> AgentInfo:
        """Create AgentInfo from Redis data"""
        return AgentInfo(
            id=data["id"],
            type=data["type"],
            status=AgentStatus(data.get("status", "online")),
            capabilities=data.get("capabilities", []),
            capacity=100,
            registered_at=datetime.fromisoformat(data.get("registered_at", datetime.now().isoformat())),
            last_heartbeat=datetime.fromisoformat(data.get("last_heartbeat", datetime.now().isoformat()))
        )

    async def handle_agent_registration(self, message):
        """Handle agent registration"""
        payload = message.payload
        agent_id = payload["agent_id"]
        agent_type = payload["agent_type"]

        logger.info(f"Registering agent: {agent_id} (type: {agent_type})")

        # Get full agent info
        agent_data = await self.communicator.get_agent_info(agent_id)

        if agent_data:
            agent_info = self._create_agent_info(agent_data)
            self.agents[agent_id] = agent_info
            self._update_agent_type_index(agent_info)

            # Broadcast registry update
            await self.broadcast_registry_update()

    async def handle_agent_heartbeat(self, message):
        """Handle agent heartbeat"""
        agent_id = message.payload["agent_id"]

        if agent_id in self.agents:
            self.agents[agent_id].last_heartbeat = datetime.now()
            self.agents[agent_id].status = AgentStatus.ONLINE

            # Update capacity if provided
            if "capacity" in message.payload:
                self.agents[agent_id].capacity = message.payload["capacity"]

    async def handle_agent_status(self, message):
        """Handle agent status update"""
        agent_id = message.sender

        if agent_id in self.agents:
            if "status" in message.payload:
                status_str = message.payload["status"]
                if status_str in AgentStatus.__members__:
                    self.agents[agent_id].status = AgentStatus[status_str.upper()]

            if "capacity" in message.payload:
                self.agents[agent_id].capacity = message.payload["capacity"]

    async def handle_task_complete(self, message):
        """Handle task completion"""
        agent_id = message.payload["agent_id"]

        if agent_id in self.agents:
            self.agents[agent_id].tasks_completed += 1

            # Update average task time if provided
            if "task_time" in message.payload:
                agent = self.agents[agent_id]
                total_tasks = agent.tasks_completed
                current_avg = agent.average_task_time
                new_time = message.payload["task_time"]
                agent.average_task_time = (
                    (current_avg * (total_tasks - 1) + new_time) / total_tasks
                )

    async def handle_task_failed(self, message):
        """Handle task failure"""
        agent_id = message.payload["agent_id"]

        if agent_id in self.agents:
            self.agents[agent_id].tasks_failed += 1

    def _update_agent_type_index(self, agent_info: AgentInfo):
        """Update agent type index"""
        if agent_info.type not in self.agent_types:
            self.agent_types[agent_info.type] = []

        if agent_info.id not in self.agent_types[agent_info.type]:
            self.agent_types[agent_info.type].append(agent_info.id)

    async def health_check_loop(self):
        """Periodic health check for all agents"""
        while self.running:
            try:
                await self.check_agent_health()
                await asyncio.sleep(self.health_check_interval)
            except Exception as e:
                logger.error(f"Health check error: {e}")
                await asyncio.sleep(self.health_check_interval)

    async def check_agent_health(self):
        """Check health of all registered agents"""
        now = datetime.now()
        timeout_threshold = timedelta(seconds=self.heartbeat_timeout)

        for agent_id, agent_info in list(self.agents.items()):
            time_since_heartbeat = now - agent_info.last_heartbeat

            if time_since_heartbeat > timeout_threshold:
                if agent_info.status != AgentStatus.OFFLINE:
                    logger.warning(f"Agent {agent_id} is offline (no heartbeat)")
                    agent_info.status = AgentStatus.OFFLINE

                    # Remove from active agents in Redis
                    await self.communicator.redis_client.srem("active_agents", agent_id)
                    await self.communicator.redis_client.srem(
                        f"active_agents:{agent_info.type}", agent_id
                    )

                    # Broadcast status change
                    await self.communicator.broadcast_message(
                        MessageType.AGENT_STATUS,
                        {
                            "agent_id": agent_id,
                            "status": "offline",
                            "reason": "heartbeat_timeout"
                        }
                    )

    async def broadcast_registry_update(self):
        """Broadcast current registry state"""
        registry_state = {
            "total_agents": len(self.agents),
            "online_agents": sum(1 for a in self.agents.values() if a.status == AgentStatus.ONLINE),
            "agent_types": {
                agent_type: len(agents)
                for agent_type, agents in self.agent_types.items()
            },
            "timestamp": datetime.now().isoformat()
        }

        await self.communicator.broadcast_message(
            MessageType.PROJECT_UPDATE,
            {"registry_state": registry_state}
        )

    def get_available_agents(self, agent_type: Optional[str] = None,
                            min_capacity: int = 0) -> List[AgentInfo]:
        """Get available agents matching criteria"""
        agents = []

        for agent_info in self.agents.values():
            # Check if online and has capacity
            if agent_info.status != AgentStatus.ONLINE:
                continue

            if agent_info.capacity < min_capacity:
                continue

            # Filter by type if specified
            if agent_type and agent_info.type != agent_type:
                continue

            agents.append(agent_info)

        # Sort by capacity (highest first) and average task time (lowest first)
        agents.sort(key=lambda a: (-a.capacity, a.average_task_time))

        return agents

    def get_best_agent(self, agent_type: str, required_capabilities: List[str] = None) -> Optional[AgentInfo]:
        """Get the best available agent for a task"""
        available = self.get_available_agents(agent_type, min_capacity=10)

        if not available:
            return None

        if required_capabilities:
            # Filter by capabilities
            capable_agents = [
                agent for agent in available
                if all(cap in agent.capabilities for cap in required_capabilities)
            ]
            if capable_agents:
                return capable_agents[0]

        # Return agent with highest capacity
        return available[0]

    def get_registry_stats(self) -> Dict[str, Any]:
        """Get registry statistics"""
        online_agents = [a for a in self.agents.values() if a.status == AgentStatus.ONLINE]
        total_capacity = sum(a.capacity for a in online_agents) / max(len(online_agents), 1)

        stats = {
            "total_agents": len(self.agents),
            "online_agents": len(online_agents),
            "offline_agents": len([a for a in self.agents.values() if a.status == AgentStatus.OFFLINE]),
            "average_capacity": total_capacity,
            "agent_types": {},
            "total_tasks_completed": sum(a.tasks_completed for a in self.agents.values()),
            "total_tasks_failed": sum(a.tasks_failed for a in self.agents.values())
        }

        # Stats by agent type
        for agent_type, agent_ids in self.agent_types.items():
            type_agents = [self.agents[aid] for aid in agent_ids if aid in self.agents]
            online_type = [a for a in type_agents if a.status == AgentStatus.ONLINE]

            stats["agent_types"][agent_type] = {
                "total": len(type_agents),
                "online": len(online_type),
                "average_capacity": sum(a.capacity for a in online_type) / max(len(online_type), 1),
                "tasks_completed": sum(a.tasks_completed for a in type_agents),
                "average_task_time": sum(a.average_task_time for a in type_agents) / max(len(type_agents), 1)
            }

        return stats

    async def assign_task(self, task: Dict[str, Any], agent_type: str) -> Optional[str]:
        """Assign a task to the best available agent"""
        agent = self.get_best_agent(
            agent_type,
            required_capabilities=task.get("required_capabilities")
        )

        if not agent:
            logger.warning(f"No available agent for type {agent_type}")
            return None

        # Submit task to agent's queue
        await self.communicator.submit_task(
            agent_type,
            task,
            priority=task.get("priority", False)
        )

        # Update agent status
        agent.status = AgentStatus.BUSY
        agent.capacity = max(0, agent.capacity - 20)  # Reduce capacity

        logger.info(f"Assigned task {task.get('id')} to agent {agent.id}")

        return agent.id


async def test_agent_registry():
    """Test the agent registry"""

    registry = AgentRegistry()

    # Start registry
    started = await registry.start()

    if started:
        print("✅ Agent Registry started")

        # Wait a bit for any existing agents
        await asyncio.sleep(2)

        # Get registry stats
        stats = registry.get_registry_stats()
        print(f"📊 Registry Stats: {json.dumps(stats, indent=2)}")

        # Get available agents
        available = registry.get_available_agents()
        print(f"🤖 Available Agents: {len(available)}")

        for agent in available:
            print(f"  - {agent.id} ({agent.type}): {agent.status.value} - Capacity: {agent.capacity}%")

        # Test task assignment
        test_task = {
            "id": str(uuid.uuid4()),
            "type": "generate_image",
            "prompt": "A test image"
        }

        assigned_agent = await registry.assign_task(test_task, "visual")
        if assigned_agent:
            print(f"✅ Task assigned to agent: {assigned_agent}")
        else:
            print("❌ No agent available for task")

        await registry.stop()
        print("✅ Agent Registry stopped")

    else:
        print("❌ Failed to start Agent Registry")
        print("Please ensure Redis is running")


if __name__ == "__main__":
    asyncio.run(test_agent_registry())