"""
Redis Communication Layer for Multi-Agent System
Handles all inter-agent communication through Redis pub/sub and queues
"""

import asyncio
import json
import logging
import redis
import redis.asyncio as aioredis
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime
import uuid
from enum import Enum
from dataclasses import dataclass, asdict
import pickle

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MessageType(Enum):
    TASK_ASSIGNMENT = "task_assignment"
    TASK_UPDATE = "task_update"
    TASK_COMPLETE = "task_complete"
    TASK_FAILED = "task_failed"
    AGENT_REGISTER = "agent_register"
    AGENT_HEARTBEAT = "agent_heartbeat"
    AGENT_STATUS = "agent_status"
    PROJECT_UPDATE = "project_update"
    RESOURCE_REQUEST = "resource_request"
    RESOURCE_RESPONSE = "resource_response"


@dataclass
class Message:
    id: str
    type: MessageType
    sender: str
    recipient: str  # Can be "broadcast" for all agents
    payload: Dict[str, Any]
    timestamp: datetime
    correlation_id: Optional[str] = None

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type.value,
            "sender": self.sender,
            "recipient": self.recipient,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
            "correlation_id": self.correlation_id
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        return cls(
            id=data["id"],
            type=MessageType(data["type"]),
            sender=data["sender"],
            recipient=data["recipient"],
            payload=data["payload"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            correlation_id=data.get("correlation_id")
        )


class RedisConfig:
    """Redis configuration"""
    def __init__(self, host: str = "localhost", port: int = 6379,
                 db: int = 0, password: Optional[str] = None):
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.decode_responses = True

    def get_url(self):
        if self.password:
            return f"redis://:{self.password}@{self.host}:{self.port}/{self.db}"
        return f"redis://{self.host}:{self.port}/{self.db}"


class RedisCommunicator:
    """Main Redis communication handler for agents"""

    def __init__(self, agent_id: str, agent_type: str, config: RedisConfig = None):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.config = config or RedisConfig()
        self.redis_client = None
        self.pubsub = None
        self.running = False
        self.message_handlers = {}
        self.subscriptions = set()

        # Channel names
        self.broadcast_channel = "agent:broadcast"
        self.private_channel = f"agent:{agent_id}"
        self.type_channel = f"agent_type:{agent_type}"

        # Queue names
        self.task_queue = f"tasks:{agent_type}"
        self.result_queue = "results"
        self.priority_queue = f"priority_tasks:{agent_type}"

    async def connect(self):
        """Connect to Redis"""
        try:
            self.redis_client = await aioredis.from_url(
                self.config.get_url(),
                decode_responses=True
            )

            # Test connection
            await self.redis_client.ping()
            logger.info(f"Agent {self.agent_id} connected to Redis")

            # Set up pub/sub
            self.pubsub = self.redis_client.pubsub()

            # Subscribe to channels
            await self.subscribe_to_channels()

            # Register agent
            await self.register_agent()

            return True

        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            return False

    async def disconnect(self):
        """Disconnect from Redis"""
        try:
            self.running = False

            # Unregister agent
            await self.unregister_agent()

            if self.pubsub:
                await self.pubsub.unsubscribe()
                await self.pubsub.close()

            if self.redis_client:
                await self.redis_client.close()

            logger.info(f"Agent {self.agent_id} disconnected from Redis")

        except Exception as e:
            logger.error(f"Error during disconnect: {e}")

    async def subscribe_to_channels(self):
        """Subscribe to relevant channels"""
        channels = [
            self.broadcast_channel,
            self.private_channel,
            self.type_channel
        ]

        for channel in channels:
            await self.pubsub.subscribe(channel)
            self.subscriptions.add(channel)

        logger.info(f"Agent {self.agent_id} subscribed to channels: {channels}")

    async def register_agent(self):
        """Register agent in Redis"""
        agent_data = {
            "id": self.agent_id,
            "type": self.agent_type,
            "status": "online",
            "registered_at": datetime.now().isoformat(),
            "last_heartbeat": datetime.now().isoformat(),
            "capabilities": self._get_agent_capabilities()
        }

        # Store agent data
        await self.redis_client.hset(
            f"agent:{self.agent_id}:info",
            mapping=agent_data
        )

        # Add to active agents set
        await self.redis_client.sadd(f"active_agents", self.agent_id)
        await self.redis_client.sadd(f"active_agents:{self.agent_type}", self.agent_id)

        # Broadcast registration
        await self.broadcast_message(
            MessageType.AGENT_REGISTER,
            {"agent_id": self.agent_id, "agent_type": self.agent_type}
        )

        # Set expiry for heartbeat (30 seconds)
        await self.redis_client.setex(
            f"agent:{self.agent_id}:heartbeat",
            30,
            "alive"
        )

    async def unregister_agent(self):
        """Unregister agent from Redis"""
        # Remove from active agents
        await self.redis_client.srem("active_agents", self.agent_id)
        await self.redis_client.srem(f"active_agents:{self.agent_type}", self.agent_id)

        # Update status
        await self.redis_client.hset(
            f"agent:{self.agent_id}:info",
            "status",
            "offline"
        )

    def _get_agent_capabilities(self) -> Dict[str, Any]:
        """Get agent capabilities based on type"""
        capabilities = {
            "visual": ["image_generation", "style_transfer", "upscaling"],
            "audio": ["music_generation", "voice_synthesis", "sound_effects"],
            "motion": ["camera_animation", "transitions", "object_animation"],
            "script": ["story_generation", "dialogue", "scene_description"],
            "post_production": ["compositing", "color_grading", "rendering"]
        }
        return json.dumps(capabilities.get(self.agent_type, []))

    async def send_message(self, recipient: str, message_type: MessageType,
                          payload: Dict[str, Any], correlation_id: str = None):
        """Send a message to a specific agent or broadcast"""
        message = Message(
            id=str(uuid.uuid4()),
            type=message_type,
            sender=self.agent_id,
            recipient=recipient,
            payload=payload,
            timestamp=datetime.now(),
            correlation_id=correlation_id
        )

        # Determine channel
        if recipient == "broadcast":
            channel = self.broadcast_channel
        elif recipient.startswith("type:"):
            # Send to all agents of a specific type
            agent_type = recipient.split(":")[1]
            channel = f"agent_type:{agent_type}"
        else:
            channel = f"agent:{recipient}"

        # Publish message
        await self.redis_client.publish(
            channel,
            json.dumps(message.to_dict())
        )

        # Store message in history
        await self.redis_client.lpush(
            f"message_history:{self.agent_id}",
            json.dumps(message.to_dict())
        )

        # Trim history to last 1000 messages
        await self.redis_client.ltrim(f"message_history:{self.agent_id}", 0, 999)

        logger.debug(f"Sent message {message.id} to {recipient}")

    async def broadcast_message(self, message_type: MessageType, payload: Dict[str, Any]):
        """Broadcast message to all agents"""
        await self.send_message("broadcast", message_type, payload)

    async def get_task(self, timeout: int = 0) -> Optional[Dict[str, Any]]:
        """Get a task from the queue"""
        # Check priority queue first
        task_data = await self.redis_client.blpop(
            [self.priority_queue, self.task_queue],
            timeout=timeout
        )

        if task_data:
            queue_name, task_json = task_data
            task = json.loads(task_json)
            logger.info(f"Got task from {queue_name}: {task.get('id')}")
            return task

        return None

    async def submit_task(self, agent_type: str, task: Dict[str, Any],
                         priority: bool = False):
        """Submit a task to an agent type's queue"""
        task["submitted_at"] = datetime.now().isoformat()
        task["submitted_by"] = self.agent_id

        queue = f"priority_tasks:{agent_type}" if priority else f"tasks:{agent_type}"

        await self.redis_client.rpush(
            queue,
            json.dumps(task)
        )

        logger.info(f"Submitted task {task.get('id')} to {agent_type} queue")

    async def submit_result(self, task_id: str, result: Dict[str, Any]):
        """Submit task result"""
        result_data = {
            "task_id": task_id,
            "agent_id": self.agent_id,
            "result": result,
            "completed_at": datetime.now().isoformat()
        }

        await self.redis_client.rpush(
            self.result_queue,
            json.dumps(result_data)
        )

        # Also store in task-specific key
        await self.redis_client.set(
            f"task_result:{task_id}",
            json.dumps(result_data),
            ex=3600  # Expire after 1 hour
        )

        # Send completion message
        await self.broadcast_message(
            MessageType.TASK_COMPLETE,
            {"task_id": task_id, "agent_id": self.agent_id}
        )

    async def update_task_status(self, task_id: str, status: str,
                                details: Dict[str, Any] = None):
        """Update task status"""
        status_data = {
            "task_id": task_id,
            "agent_id": self.agent_id,
            "status": status,
            "details": details or {},
            "updated_at": datetime.now().isoformat()
        }

        await self.redis_client.hset(
            f"task:{task_id}:status",
            mapping=status_data
        )

        # Broadcast update
        await self.broadcast_message(
            MessageType.TASK_UPDATE,
            status_data
        )

    async def heartbeat_loop(self, interval: int = 10):
        """Send periodic heartbeats"""
        while self.running:
            try:
                # Update heartbeat
                await self.redis_client.setex(
                    f"agent:{self.agent_id}:heartbeat",
                    30,  # 30 second expiry
                    "alive"
                )

                # Update last heartbeat time
                await self.redis_client.hset(
                    f"agent:{self.agent_id}:info",
                    "last_heartbeat",
                    datetime.now().isoformat()
                )

                # Send heartbeat message
                await self.send_message(
                    "broadcast",
                    MessageType.AGENT_HEARTBEAT,
                    {"agent_id": self.agent_id, "status": "alive"}
                )

                await asyncio.sleep(interval)

            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                await asyncio.sleep(interval)

    async def message_listener(self):
        """Listen for messages"""
        self.running = True

        async for message in self.pubsub.listen():
            if message["type"] == "message":
                try:
                    msg_data = json.loads(message["data"])
                    msg = Message.from_dict(msg_data)

                    # Skip own messages
                    if msg.sender == self.agent_id:
                        continue

                    # Handle message
                    await self.handle_message(msg)

                except Exception as e:
                    logger.error(f"Error processing message: {e}")

    async def handle_message(self, message: Message):
        """Handle incoming message"""
        logger.debug(f"Received message {message.id} from {message.sender}")

        # Check if handler exists for message type
        if message.type in self.message_handlers:
            handler = self.message_handlers[message.type]
            await handler(message)
        else:
            # Default handling
            logger.info(f"Unhandled message type: {message.type.value}")

    def register_handler(self, message_type: MessageType, handler: Callable):
        """Register a message handler"""
        self.message_handlers[message_type] = handler
        logger.info(f"Registered handler for {message_type.value}")

    async def get_active_agents(self, agent_type: str = None) -> List[str]:
        """Get list of active agents"""
        if agent_type:
            agents = await self.redis_client.smembers(f"active_agents:{agent_type}")
        else:
            agents = await self.redis_client.smembers("active_agents")

        return list(agents)

    async def get_agent_info(self, agent_id: str) -> Dict[str, Any]:
        """Get information about an agent"""
        info = await self.redis_client.hgetall(f"agent:{agent_id}:info")
        return info

    async def store_data(self, key: str, data: Any, expire: int = None):
        """Store data in Redis"""
        if isinstance(data, dict):
            data = json.dumps(data)

        if expire:
            await self.redis_client.setex(f"data:{self.agent_id}:{key}", expire, data)
        else:
            await self.redis_client.set(f"data:{self.agent_id}:{key}", data)

    async def get_data(self, key: str) -> Any:
        """Get data from Redis"""
        data = await self.redis_client.get(f"data:{self.agent_id}:{key}")
        if data:
            try:
                return json.loads(data)
            except:
                return data
        return None

    async def acquire_lock(self, resource: str, timeout: int = 10) -> bool:
        """Acquire a distributed lock"""
        lock_key = f"lock:{resource}"
        acquired = await self.redis_client.set(
            lock_key,
            self.agent_id,
            nx=True,
            ex=timeout
        )
        return bool(acquired)

    async def release_lock(self, resource: str):
        """Release a distributed lock"""
        lock_key = f"lock:{resource}"
        current_holder = await self.redis_client.get(lock_key)
        if current_holder == self.agent_id:
            await self.redis_client.delete(lock_key)


class AgentCommunicationMixin:
    """Mixin to add Redis communication to agent classes"""

    def setup_redis_communication(self, agent_id: str, agent_type: str,
                                 config: RedisConfig = None):
        """Set up Redis communication for the agent"""
        self.communicator = RedisCommunicator(agent_id, agent_type, config)

    async def start_communication(self):
        """Start Redis communication"""
        connected = await self.communicator.connect()
        if connected:
            # Start heartbeat
            asyncio.create_task(self.communicator.heartbeat_loop())

            # Start message listener
            asyncio.create_task(self.communicator.message_listener())

            # Register handlers
            self._register_message_handlers()

        return connected

    async def stop_communication(self):
        """Stop Redis communication"""
        await self.communicator.disconnect()

    def _register_message_handlers(self):
        """Register message handlers (override in subclass)"""
        pass


async def test_redis_communication():
    """Test Redis communication"""

    # Create test communicator
    comm = RedisCommunicator("test_agent_1", "visual")

    # Try to connect
    connected = await comm.connect()

    if connected:
        print("✅ Connected to Redis")

        # Test sending message
        await comm.broadcast_message(
            MessageType.AGENT_STATUS,
            {"status": "ready", "capacity": 100}
        )
        print("✅ Sent broadcast message")

        # Test task submission
        test_task = {
            "id": str(uuid.uuid4()),
            "type": "generate_image",
            "prompt": "A beautiful sunset"
        }
        await comm.submit_task("visual", test_task)
        print("✅ Submitted task")

        # Test getting task
        task = await comm.get_task(timeout=1)
        if task:
            print(f"✅ Retrieved task: {task['id']}")

        # Test data storage
        await comm.store_data("test_key", {"test": "data"})
        data = await comm.get_data("test_key")
        print(f"✅ Stored and retrieved data: {data}")

        # Get active agents
        agents = await comm.get_active_agents()
        print(f"✅ Active agents: {agents}")

        await comm.disconnect()
        print("✅ Disconnected from Redis")

        return True
    else:
        print("❌ Could not connect to Redis")
        print("Please ensure Redis is running:")
        print("  - Docker: docker run -d -p 6379:6379 redis:latest")
        print("  - Or install Redis locally")
        return False


if __name__ == "__main__":
    asyncio.run(test_redis_communication())