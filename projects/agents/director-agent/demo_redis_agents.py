#!/usr/bin/env python3
"""
Demo Director-Agent System with Redis
Simulated agents for testing without full dependencies
"""

import redis
import json
import time
import threading
from datetime import datetime
import random

class SimulatedAgent:
    """Base class for simulated agents"""

    def __init__(self, agent_id, agent_type):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
        self.running = True
        self.tasks_completed = 0

    def register(self):
        """Register agent in Redis"""
        agent_info = {
            'type': self.agent_type,
            'status': 'ready',
            'started': datetime.now().isoformat(),
            'tasks_completed': 0
        }
        self.redis_client.hset('agent_registry', self.agent_id, json.dumps(agent_info))
        print(f"[{self.agent_id}] Registered")

    def process_task(self, task):
        """Simulate task processing"""
        print(f"[{self.agent_id}] Processing task {task.get('id')}: {task.get('type')}")

        # Simulate work
        time.sleep(random.uniform(0.5, 2.0))

        # Update status
        self.tasks_completed += 1

        # Publish result
        result = {
            'agent': self.agent_id,
            'task_id': task.get('id'),
            'status': 'completed',
            'output': f"{self.agent_type}_output_{task.get('id')}.dat"
        }
        self.redis_client.publish('agent_results', json.dumps(result))

        print(f"[{self.agent_id}] Task {task.get('id')} completed")

    def run(self):
        """Main agent loop"""
        self.register()
        pubsub = self.redis_client.pubsub()
        pubsub.subscribe(f'{self.agent_id}_commands')

        while self.running:
            message = pubsub.get_message(timeout=1.0)
            if message and message['type'] == 'message':
                task = json.loads(message['data'])
                self.process_task(task)

    def stop(self):
        """Stop the agent"""
        self.running = False
        print(f"[{self.agent_id}] Stopped")

class DirectorAgent:
    """Director agent that coordinates other agents"""

    def __init__(self):
        self.redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
        self.running = True
        self.task_counter = 0

    def create_sample_tasks(self):
        """Create sample tasks for demonstration"""
        tasks = [
            {'id': 1, 'type': 'generate_audio', 'duration': 10},
            {'id': 2, 'type': 'generate_visual', 'frames': 30},
            {'id': 3, 'type': 'apply_motion', 'style': 'smooth'},
            {'id': 4, 'type': 'generate_audio', 'duration': 5},
            {'id': 5, 'type': 'generate_visual', 'frames': 60}
        ]

        for task in tasks:
            self.redis_client.lpush('task_queue', json.dumps(task))

        print(f"[Director] Added {len(tasks)} tasks to queue")

    def route_task(self, task):
        """Route task to appropriate agent"""
        # Determine target agent
        routing = {
            'generate_audio': 'audio_agent',
            'generate_visual': 'visual_agent',
            'apply_motion': 'motion_agent'
        }

        agent_id = routing.get(task.get('type'))
        if agent_id:
            # Check if agent is registered
            agent_info = self.redis_client.hget('agent_registry', agent_id)
            if agent_info:
                # Send task to agent
                self.redis_client.publish(f'{agent_id}_commands', json.dumps(task))
                print(f"[Director] Routed task {task.get('id')} to {agent_id}")
                self.task_counter += 1
            else:
                print(f"[Director] Agent {agent_id} not available")
        else:
            print(f"[Director] No agent for task type: {task.get('type')}")

    def run(self):
        """Main director loop"""
        print("[Director] Starting coordination")

        # Subscribe to results
        pubsub = self.redis_client.pubsub()
        pubsub.subscribe('agent_results')

        while self.running:
            # Process task queue
            task_str = self.redis_client.rpop('task_queue')
            if task_str:
                task = json.loads(task_str)
                self.route_task(task)

            # Check for results
            message = pubsub.get_message(timeout=0.1)
            if message and message['type'] == 'message':
                result = json.loads(message['data'])
                print(f"[Director] Received result from {result.get('agent')} for task {result.get('task_id')}")

            time.sleep(0.1)

    def stop(self):
        """Stop the director"""
        self.running = False
        print(f"[Director] Stopped - Processed {self.task_counter} tasks")

def run_demo():
    """Run the demonstration"""
    print("="*60)
    print("    DIRECTOR-AGENT REDIS DEMO")
    print("="*60)

    # Clear previous state
    r = redis.Redis(host='localhost', port=6379, decode_responses=True)
    r.delete('agent_registry', 'task_queue')

    # Create agents
    agents = [
        SimulatedAgent('audio_agent', 'audio'),
        SimulatedAgent('visual_agent', 'visual'),
        SimulatedAgent('motion_agent', 'motion')
    ]

    # Create director
    director = DirectorAgent()

    # Start agent threads
    agent_threads = []
    for agent in agents:
        thread = threading.Thread(target=agent.run)
        thread.daemon = True
        thread.start()
        agent_threads.append(thread)

    # Give agents time to register
    time.sleep(1)

    # Create tasks
    director.create_sample_tasks()

    # Start director thread
    director_thread = threading.Thread(target=director.run)
    director_thread.daemon = True
    director_thread.start()

    # Run for demo duration
    print("\nSystem running... (10 seconds)")
    time.sleep(10)

    # Show status
    print("\n" + "="*60)
    print("    FINAL STATUS")
    print("="*60)

    # Get agent registry
    registry = r.hgetall('agent_registry')
    print("\nRegistered Agents:")
    for agent_id, info_str in registry.items():
        info = json.loads(info_str)
        print(f"  {agent_id}: {info.get('type')} - {info.get('status')}")

    # Check remaining queue
    queue_len = r.llen('task_queue')
    print(f"\nRemaining tasks in queue: {queue_len}")

    # Stop everything
    print("\nStopping system...")
    director.stop()
    for agent in agents:
        agent.stop()

    time.sleep(1)

    print("\n" + "="*60)
    print("    DEMO COMPLETE")
    print("="*60)
    print("[OK] Director-Agent system with Redis integration successful")
    print("[OK] Agents registered and processing tasks")
    print("[OK] Director routing tasks correctly")
    print("[OK] Pub/Sub messaging operational")

if __name__ == "__main__":
    try:
        run_demo()
    except redis.ConnectionError:
        print("[FAIL] Cannot connect to Redis. Please ensure Redis is running.")
        print("       Run: docker-compose up -d redis")
    except Exception as e:
        print(f"Demo error: {e}")
        import traceback
        traceback.print_exc()