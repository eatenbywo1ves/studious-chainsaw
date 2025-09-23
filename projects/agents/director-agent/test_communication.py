"""
Test script for inter-agent communication system
Demonstrates Redis-based communication between multiple agents
"""

import asyncio
import json
import logging
from datetime import datetime
import sys
from typing import Dict, Any

# Import our modules
from redis_communication import RedisCommunicator, RedisConfig, MessageType, AgentCommunicationMixin
from agent_registry import AgentRegistry
from visual_agent import VisualAgent
from audio_agent import AudioAgent
from motion_agent import MotionAgent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class EnhancedVisualAgent(VisualAgent, AgentCommunicationMixin):
    """Visual agent with Redis communication"""

    def __init__(self, agent_id: str = None):
        super().__init__(agent_id)
        self.setup_redis_communication(self.agent_id, "visual")

    def _register_message_handlers(self):
        """Register custom message handlers"""
        self.communicator.register_handler(
            MessageType.TASK_ASSIGNMENT,
            self.handle_task_assignment
        )

    async def handle_task_assignment(self, message):
        """Handle task assignment from director"""
        logger.info(f"Visual Agent received task: {message.payload.get('task_id')}")

        # Process the scene
        result = await self.process_scene(message.payload)

        # Submit result
        await self.communicator.submit_result(
            message.payload.get('task_id'),
            result
        )


class EnhancedAudioAgent(AudioAgent, AgentCommunicationMixin):
    """Audio agent with Redis communication"""

    def __init__(self, agent_id: str = None):
        super().__init__(agent_id)
        self.setup_redis_communication(self.agent_id, "audio")

    def _register_message_handlers(self):
        """Register custom message handlers"""
        self.communicator.register_handler(
            MessageType.TASK_ASSIGNMENT,
            self.handle_task_assignment
        )

    async def handle_task_assignment(self, message):
        """Handle task assignment from director"""
        logger.info(f"Audio Agent received task: {message.payload.get('task_id')}")

        # Process the scene
        result = await self.process_scene(message.payload)

        # Submit result
        await self.communicator.submit_result(
            message.payload.get('task_id'),
            result
        )


class EnhancedMotionAgent(MotionAgent, AgentCommunicationMixin):
    """Motion agent with Redis communication"""

    def __init__(self, agent_id: str = None):
        super().__init__(agent_id)
        self.setup_redis_communication(self.agent_id, "motion")

    def _register_message_handlers(self):
        """Register custom message handlers"""
        self.communicator.register_handler(
            MessageType.TASK_ASSIGNMENT,
            self.handle_task_assignment
        )

    async def handle_task_assignment(self, message):
        """Handle task assignment from director"""
        logger.info(f"Motion Agent received task: {message.payload.get('task_id')}")

        # Process the scene
        result = await self.process_scene(message.payload)

        # Submit result
        await self.communicator.submit_result(
            message.payload.get('task_id'),
            result
        )


class TestDirector:
    """Test director to coordinate agents"""

    def __init__(self):
        self.communicator = RedisCommunicator(
            agent_id="test_director",
            agent_type="director"
        )
        self.registry = None

    async def start(self):
        """Start the test director"""
        connected = await self.communicator.connect()
        if not connected:
            return False

        # Start registry
        self.registry = AgentRegistry()
        await self.registry.start()

        return True

    async def create_test_project(self):
        """Create a test video project"""
        project = {
            "id": "test_project_001",
            "title": "Test Video Project",
            "scenes": [
                {
                    "scene_id": "scene_001",
                    "duration": 5,
                    "visual_prompt": "A beautiful sunrise over mountains",
                    "style": "realistic",
                    "needs_music": True,
                    "mood": "calm",
                    "motion_type": "pan",
                    "transition_in": "fade"
                },
                {
                    "scene_id": "scene_002",
                    "duration": 5,
                    "visual_prompt": "A bustling city street",
                    "style": "cyberpunk",
                    "needs_music": True,
                    "mood": "energetic",
                    "motion_type": "track",
                    "sound_effects": ["traffic", "crowd"]
                }
            ]
        }

        return project

    async def distribute_tasks(self, project: Dict[str, Any]):
        """Distribute tasks to agents"""
        tasks_distributed = []

        for scene in project["scenes"]:
            # Visual task
            visual_task = {
                "task_id": f"{scene['scene_id']}_visual",
                "scene_id": scene["scene_id"],
                "visual_prompt": scene["visual_prompt"],
                "style": scene.get("style", "realistic"),
                "duration": scene["duration"]
            }

            agent_id = await self.registry.assign_task(visual_task, "visual")
            if agent_id:
                tasks_distributed.append(("visual", visual_task["task_id"], agent_id))
                await self.communicator.send_message(
                    agent_id,
                    MessageType.TASK_ASSIGNMENT,
                    visual_task
                )

            # Audio task
            audio_task = {
                "task_id": f"{scene['scene_id']}_audio",
                "scene_id": scene["scene_id"],
                "duration": scene["duration"],
                "needs_music": scene.get("needs_music", True),
                "mood": scene.get("mood", "calm"),
                "sound_effects": scene.get("sound_effects", [])
            }

            agent_id = await self.registry.assign_task(audio_task, "audio")
            if agent_id:
                tasks_distributed.append(("audio", audio_task["task_id"], agent_id))
                await self.communicator.send_message(
                    agent_id,
                    MessageType.TASK_ASSIGNMENT,
                    audio_task
                )

            # Motion task
            motion_task = {
                "task_id": f"{scene['scene_id']}_motion",
                "scene_id": scene["scene_id"],
                "duration": scene["duration"],
                "motion_type": scene.get("motion_type", "static"),
                "transition_in": scene.get("transition_in")
            }

            agent_id = await self.registry.assign_task(motion_task, "motion")
            if agent_id:
                tasks_distributed.append(("motion", motion_task["task_id"], agent_id))
                await self.communicator.send_message(
                    agent_id,
                    MessageType.TASK_ASSIGNMENT,
                    motion_task
                )

        return tasks_distributed

    async def stop(self):
        """Stop the director"""
        if self.registry:
            await self.registry.stop()
        await self.communicator.disconnect()


async def test_full_system():
    """Test the full multi-agent system"""

    print("\n" + "="*60)
    print("🎬 MULTI-AGENT VIDEO SYSTEM TEST")
    print("="*60 + "\n")

    # Check Redis connection first
    test_comm = RedisCommunicator("test", "test")
    if not await test_comm.connect():
        print("❌ Redis is not running!")
        print("\n📋 To start Redis:")
        print("  Option 1 - Docker (recommended):")
        print("    docker-compose up -d")
        print("\n  Option 2 - Docker without compose:")
        print("    docker run -d -p 6379:6379 redis:latest")
        print("\n  Option 3 - Local installation:")
        print("    redis-server")
        await test_comm.disconnect()
        return
    await test_comm.disconnect()

    print("✅ Redis is running\n")

    # Start director
    print("🎬 Starting Test Director...")
    director = TestDirector()
    if not await director.start():
        print("❌ Failed to start director")
        return

    print("✅ Director started\n")

    # Start agents
    agents = []

    print("🤖 Starting Agents...")

    # Visual Agent
    visual_agent = EnhancedVisualAgent()
    await visual_agent.initialize()
    if await visual_agent.start_communication():
        agents.append(visual_agent)
        print("  ✅ Visual Agent started")
    else:
        print("  ❌ Visual Agent failed to start")

    # Audio Agent
    audio_agent = EnhancedAudioAgent()
    await audio_agent.initialize()
    if await audio_agent.start_communication():
        agents.append(audio_agent)
        print("  ✅ Audio Agent started")
    else:
        print("  ❌ Audio Agent failed to start")

    # Motion Agent
    motion_agent = EnhancedMotionAgent()
    await motion_agent.initialize()
    if await motion_agent.start_communication():
        agents.append(motion_agent)
        print("  ✅ Motion Agent started")
    else:
        print("  ❌ Motion Agent failed to start")

    print()

    # Wait for agents to register
    await asyncio.sleep(2)

    # Check registry
    print("📊 Registry Status:")
    stats = director.registry.get_registry_stats()
    print(f"  Total Agents: {stats['total_agents']}")
    print(f"  Online Agents: {stats['online_agents']}")
    for agent_type, type_stats in stats['agent_types'].items():
        print(f"  {agent_type.capitalize()}: {type_stats['online']}/{type_stats['total']} online")
    print()

    # Create and distribute test project
    print("📽️ Creating test project...")
    project = await director.create_test_project()
    print(f"  Project: {project['title']}")
    print(f"  Scenes: {len(project['scenes'])}")
    print()

    print("📨 Distributing tasks to agents...")
    tasks = await director.distribute_tasks(project)
    print(f"  Tasks distributed: {len(tasks)}")
    for task_type, task_id, agent_id in tasks:
        print(f"    {task_type}: {task_id} -> {agent_id[:8]}...")
    print()

    # Wait for processing
    print("⏳ Processing tasks (5 seconds)...")
    await asyncio.sleep(5)

    # Final statistics
    print("\n📈 Final Statistics:")
    final_stats = director.registry.get_registry_stats()
    print(f"  Tasks Completed: {final_stats['total_tasks_completed']}")
    print(f"  Tasks Failed: {final_stats['total_tasks_failed']}")
    print()

    # Cleanup
    print("🧹 Cleaning up...")
    for agent in agents:
        await agent.stop_communication()
    await director.stop()

    print("\n✅ Test completed successfully!")


async def simple_connectivity_test():
    """Simple test to verify Redis connectivity"""

    print("\n🔌 Testing Redis Connectivity...")

    comm = RedisCommunicator("test_agent", "test")
    connected = await comm.connect()

    if connected:
        print("✅ Connected to Redis successfully!")

        # Test basic operations
        await comm.store_data("test_key", {"message": "Hello Redis!"})
        data = await comm.get_data("test_key")
        print(f"✅ Data storage test: {data}")

        await comm.disconnect()
    else:
        print("❌ Failed to connect to Redis")
        print("\nPlease ensure Redis is running:")
        print("  docker-compose up -d")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--simple":
        asyncio.run(simple_connectivity_test())
    else:
        asyncio.run(test_full_system())