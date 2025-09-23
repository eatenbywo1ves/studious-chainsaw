#!/usr/bin/env python3
"""
Start Director-Agent System with Redis Integration
"""

import asyncio
import json
import redis
import sys
import signal
from typing import Dict, Any
from datetime import datetime

# Import agent modules
from agent_registry import AgentRegistry
from redis_communication import RedisCommunicator
from audio_agent import AudioAgent
from visual_agent import VisualAgent
from motion_agent import MotionAgent

class DirectorAgentSystem:
    """Main system orchestrator for director-agent architecture"""

    def __init__(self):
        """Initialize the director-agent system"""
        self.redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
        self.registry = AgentRegistry()
        self.agents = {}
        self.running = False
        self.tasks_processed = 0

    async def initialize_agents(self):
        """Initialize all agent services"""
        print("\nInitializing Agent Services...")

        # Create agent instances
        agents_config = [
            {'id': 'audio_agent', 'type': 'audio', 'class': AudioAgent},
            {'id': 'visual_agent', 'type': 'visual', 'class': VisualAgent},
            {'id': 'motion_agent', 'type': 'motion', 'class': MotionAgent}
        ]

        for config in agents_config:
            try:
                # Create agent instance
                agent = config['class'](config['id'])
                self.agents[config['id']] = agent

                # Register in Redis
                agent_info = {
                    'type': config['type'],
                    'status': 'ready',
                    'started': datetime.now().isoformat(),
                    'tasks_completed': 0
                }
                self.redis_client.hset('agent_registry', config['id'], json.dumps(agent_info))

                print(f"  [OK] {config['id']} initialized")

            except Exception as e:
                print(f"  [FAIL] {config['id']}: {e}")

    async def director_loop(self):
        """Main director coordination loop"""
        print("\nDirector Agent Active - Monitoring Tasks...")

        pubsub = self.redis_client.pubsub()
        pubsub.subscribe('task_requests', 'agent_status')

        while self.running:
            # Check for new tasks
            task_str = self.redis_client.rpop('task_queue')
            if task_str:
                task = json.loads(task_str)
                await self.process_task(task)

            # Check for messages
            message = pubsub.get_message(timeout=0.1)
            if message and message['type'] == 'message':
                await self.handle_message(message)

            await asyncio.sleep(0.1)

    async def process_task(self, task: Dict[str, Any]):
        """Process a task by routing to appropriate agent"""
        print(f"\nProcessing Task {task.get('id', 'unknown')}:")
        print(f"  Type: {task.get('type')}")

        # Determine which agent should handle the task
        agent_mapping = {
            'generate_audio': 'audio_agent',
            'generate_visual': 'visual_agent',
            'apply_motion': 'motion_agent'
        }

        agent_id = agent_mapping.get(task.get('type'))
        if agent_id and agent_id in self.agents:
            # Send task to agent
            self.redis_client.publish(f'{agent_id}_commands', json.dumps(task))

            # Update stats
            self.tasks_processed += 1

            # Update agent task count
            agent_info_str = self.redis_client.hget('agent_registry', agent_id)
            if agent_info_str:
                agent_info = json.loads(agent_info_str)
                agent_info['tasks_completed'] += 1
                agent_info['last_task'] = datetime.now().isoformat()
                self.redis_client.hset('agent_registry', agent_id, json.dumps(agent_info))

            print(f"  [OK] Routed to {agent_id}")
        else:
            print(f"  [WARN] No agent available for task type: {task.get('type')}")

    async def handle_message(self, message: Dict[str, Any]):
        """Handle pub/sub messages"""
        channel = message['channel']
        data = json.loads(message['data'])

        if channel == 'agent_status':
            agent_id = data.get('agent')
            status = data.get('status')
            print(f"  Agent Status: {agent_id} - {status}")

    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status"""
        # Get all agents from registry
        registry = self.redis_client.hgetall('agent_registry')

        agents_status = {}
        for agent_id, info_str in registry.items():
            info = json.loads(info_str)
            agents_status[agent_id] = {
                'type': info.get('type'),
                'status': info.get('status'),
                'tasks': info.get('tasks_completed', 0)
            }

        return {
            'running': self.running,
            'agents': agents_status,
            'tasks_processed': self.tasks_processed,
            'queue_length': self.redis_client.llen('task_queue')
        }

    async def shutdown(self):
        """Gracefully shutdown the system"""
        print("\nShutting down Director-Agent System...")
        self.running = False

        # Update agent statuses
        for agent_id in self.agents:
            agent_info_str = self.redis_client.hget('agent_registry', agent_id)
            if agent_info_str:
                agent_info = json.loads(agent_info_str)
                agent_info['status'] = 'stopped'
                agent_info['stopped'] = datetime.now().isoformat()
                self.redis_client.hset('agent_registry', agent_id, json.dumps(agent_info))

        print("  [OK] System shutdown complete")

    async def run(self):
        """Main system run method"""
        print("="*60)
        print("    DIRECTOR-AGENT SYSTEM WITH REDIS")
        print("="*60)

        # Initialize
        await self.initialize_agents()

        # Start running
        self.running = True

        # Add sample tasks
        print("\nAdding sample tasks to queue...")
        sample_tasks = [
            {'id': 1, 'type': 'generate_audio', 'params': {'duration': 5, 'style': 'ambient'}},
            {'id': 2, 'type': 'generate_visual', 'params': {'resolution': '1920x1080', 'frames': 30}},
            {'id': 3, 'type': 'apply_motion', 'params': {'effect': 'zoom', 'duration': 3}}
        ]

        for task in sample_tasks:
            self.redis_client.lpush('task_queue', json.dumps(task))
            print(f"  Added task {task['id']}: {task['type']}")

        # Run director loop
        try:
            await self.director_loop()
        except KeyboardInterrupt:
            await self.shutdown()

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print("\nReceived shutdown signal")
    sys.exit(0)

async def main():
    """Main entry point"""
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Create and run system
    system = DirectorAgentSystem()

    # Start system
    await system.run()

    # Show final status
    status = system.get_system_status()
    print("\n" + "="*60)
    print("    SYSTEM STATUS")
    print("="*60)
    print(f"Tasks Processed: {status['tasks_processed']}")
    print(f"Queue Length: {status['queue_length']}")
    print("\nAgent Status:")
    for agent_id, info in status['agents'].items():
        print(f"  {agent_id}: {info['status']} ({info['tasks']} tasks)")

if __name__ == "__main__":
    print("Starting Director-Agent System...")
    print("Press Ctrl+C to stop")

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nSystem stopped by user")
    except Exception as e:
        print(f"System error: {e}")
        import traceback
        traceback.print_exc()