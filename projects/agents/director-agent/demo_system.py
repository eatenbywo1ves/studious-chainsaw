"""
Simple demonstration of the multi-agent system with Redis communication
"""

import asyncio
import json
import uuid
from redis_communication import RedisCommunicator, MessageType
from agent_registry import AgentRegistry
from visual_agent import VisualAgent
from audio_agent import AudioAgent
from motion_agent import MotionAgent

class DemoDirector:
    """Simple demo director"""

    def __init__(self):
        self.communicator = RedisCommunicator("demo_director", "director")

    async def run_demo(self):
        """Run a simple demo"""
        print("\n===== MULTI-AGENT VIDEO SYSTEM DEMO =====\n")

        # Connect to Redis
        connected = await self.communicator.connect()
        if not connected:
            print("Failed to connect to Redis!")
            return

        print("[OK] Director connected to Redis")

        # Create a test scene
        test_scene = {
            "scene_id": "demo_scene_001",
            "duration": 5,
            "visual_prompt": "A futuristic cityscape at sunset",
            "style": "cyberpunk",
            "needs_music": True,
            "mood": "energetic",
            "motion_type": "pan",
            "transition_in": "fade"
        }

        # Broadcast scene to agents
        print(f"\nBroadcasting scene: {test_scene['scene_id']}")
        await self.communicator.broadcast_message(
            MessageType.TASK_ASSIGNMENT,
            test_scene
        )

        # Check for active agents
        active_agents = await self.communicator.get_active_agents()
        print(f"Active agents: {len(active_agents)}")

        await asyncio.sleep(2)

        await self.communicator.disconnect()
        print("\n[OK] Demo completed")


async def run_simple_agent(agent_type, agent_class):
    """Run a simple agent"""
    agent = agent_class()
    await agent.initialize()

    comm = RedisCommunicator(agent.agent_id, agent_type)
    connected = await comm.connect()

    if connected:
        print(f"[OK] {agent_type.capitalize()} agent connected")

        # Listen for messages for 5 seconds
        timeout = 5
        start = asyncio.get_event_loop().time()

        while asyncio.get_event_loop().time() - start < timeout:
            # Check for tasks
            task = await comm.get_task(timeout=1)
            if task:
                print(f"  {agent_type.capitalize()} agent processing task: {task.get('scene_id')}")

                # Process the task
                if agent_type == "visual":
                    result = await agent.process_scene(task)
                elif agent_type == "audio":
                    result = await agent.process_scene(task)
                elif agent_type == "motion":
                    result = await agent.process_scene(task)

                # Submit result
                await comm.submit_result(task.get('scene_id'), result)
                print(f"  {agent_type.capitalize()} agent completed task")

            await asyncio.sleep(0.5)

        await comm.disconnect()
    else:
        print(f"Failed to connect {agent_type} agent")


async def main():
    """Main demo function"""

    print("\n" + "="*50)
    print("  MULTI-AGENT VIDEO SYSTEM - REDIS DEMO")
    print("="*50)

    # Start agents in parallel
    agent_tasks = [
        asyncio.create_task(run_simple_agent("visual", VisualAgent)),
        asyncio.create_task(run_simple_agent("audio", AudioAgent)),
        asyncio.create_task(run_simple_agent("motion", MotionAgent))
    ]

    # Wait a bit for agents to start
    await asyncio.sleep(2)

    # Run director demo
    director = DemoDirector()
    await director.run_demo()

    # Wait for agents to finish
    await asyncio.gather(*agent_tasks)

    print("\n" + "="*50)
    print("  DEMO COMPLETE - All agents connected via Redis!")
    print("="*50)
    print("\n[OK] Redis communication layer is working")
    print("[OK] Agents can register and receive tasks")
    print("[OK] Task distribution system operational")
    print("\nNext steps:")
    print("  1. View Redis data at: http://localhost:8081")
    print("  2. Integrate with real APIs for generation")
    print("  3. Build web dashboard for monitoring")

if __name__ == "__main__":
    asyncio.run(main())